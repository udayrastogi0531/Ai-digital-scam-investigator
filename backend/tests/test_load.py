"""Controlled concurrency / load behaviour.

These are deterministic *behavioural* tests, not benchmarks.  Nothing here
asserts a requests-per-second figure — timings vary by machine and are not a
product claim.  What they pin is how the system behaves under simultaneous
load:

* many concurrent text investigations all complete;
* image submissions beyond ``MAX_CONCURRENT_IMAGE_OPS`` are refused with a
  graceful ``503`` + ``Retry-After`` rather than queued without bound;
* capacity returns to zero afterwards (no slot leak) even when work fails;
* nothing deadlocks — every gather is bounded by ``wait_for``;
* the per-IP rate limiter still rejects the overflow while this is happening.

Requests are held open with ``asyncio.Event`` rather than sleeps, so the
scenarios are reproducible.  See ``scripts/load_test.py`` for the optional
timed measurement run.
"""
from __future__ import annotations

import asyncio
import io

import httpx
import pytest
from fastapi import HTTPException
from PIL import Image

from app.core import rate_limit as rate_limit_mod
from app.core.config import get_settings
from app.core.concurrency import get_gate, reset_gate
from app.main import app
from app.schemas.api import InvestigationSummary
from tests.conftest import BENIGN_NOTE

IMAGE_LIMIT = 2
GATHER_TIMEOUT = 20


def _png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (120, 60), color=(250, 250, 250)).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def two_image_slots(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_IMAGE_OPS", str(IMAGE_LIMIT))
    get_settings.cache_clear()
    reset_gate()
    yield
    get_settings.cache_clear()
    reset_gate()


def _auth(client) -> dict[str, str]:
    return {"Authorization": client.headers["Authorization"]}


def _text_post(ac, text: str = BENIGN_NOTE):
    return ac.post("/api/analyze/text", json={"text": text})


def _image_post(ac):
    return ac.post(
        "/api/analyze/image",
        files={"image": ("shot.png", _png_bytes(), "image/png")},
        data={"text": BENIGN_NOTE},
    )


# --- concurrency basics -----------------------------------------------------


def test_many_concurrent_text_investigations_all_succeed(client):
    auth = _auth(client)

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", headers=auth) as ac:
            return await asyncio.wait_for(
                asyncio.gather(*[_text_post(ac) for _ in range(5)]), timeout=GATHER_TIMEOUT
            )

    responses = asyncio.run(_run())
    assert [r.status_code for r in responses] == [200] * 5
    assert all(r.json()["status"] == "completed" for r in responses)


def test_image_burst_beyond_the_limit_is_refused_not_queued(client, two_image_slots, monkeypatch):
    """Two in flight fill the limit; further submissions get a 503 immediately."""
    auth = _auth(client)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def _blocking(db, payload, image_bytes=None, *, user_id=None):
        entered.set()
        await release.wait()
        return InvestigationSummary(investigation_id="stub", title="stub", status="completed")

    monkeypatch.setattr("app.api.routes.analyze._run_submission", _blocking)

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", headers=auth) as ac:
            first = asyncio.create_task(_image_post(ac))
            second = asyncio.create_task(_image_post(ac))
            # Wait until both in-flight requests actually hold a slot; polling
            # the counter is deterministic, unlike a fixed sleep.
            for _ in range(500):
                if get_gate().in_use >= IMAGE_LIMIT:
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("in-flight requests did not acquire slots")
            assert entered.is_set()

            overflow = [_image_post(ac) for _ in range(3)]
            refused = await asyncio.wait_for(asyncio.gather(*overflow), timeout=GATHER_TIMEOUT)

            release.set()
            finished = await asyncio.wait_for(asyncio.gather(first, second), timeout=GATHER_TIMEOUT)
            return finished, refused

    finished, refused = asyncio.run(_run())
    assert all(r.status_code == 200 for r in finished)
    assert all(r.status_code == 503 for r in refused)
    assert all(r.headers.get("retry-after") == "1" for r in refused)
    assert get_gate().in_use == 0


def test_no_slot_leak_after_repeated_success(client, two_image_slots):
    """A steady stream of image work leaves the counter at zero (no leak)."""
    auth = _auth(client)

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", headers=auth) as ac:
            for _ in range(6):
                resp = await asyncio.wait_for(_image_post(ac), timeout=GATHER_TIMEOUT)
                assert resp.status_code == 200
        return True

    assert asyncio.run(_run())
    assert get_gate().in_use == 0


def test_slots_are_released_after_failures(client, two_image_slots, monkeypatch):
    """Failures inside the guarded block release their slots (no deadlock)."""
    auth = _auth(client)

    async def _boom(db, payload, image_bytes=None, *, user_id=None):
        raise HTTPException(status_code=400, detail="processing failed")

    monkeypatch.setattr("app.api.routes.analyze._run_submission", _boom)

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", headers=auth) as ac:
            return await asyncio.wait_for(
                asyncio.gather(*[_image_post(ac) for _ in range(4)]), timeout=GATHER_TIMEOUT
            )

    responses = asyncio.run(_run())
    codes = [r.status_code for r in responses]
    # Failures are clean (400); a burst may also legitimately refuse an overflow
    # with 503 before a slot frees.  Nothing may be a 500.
    assert all(c in (400, 503) for c in codes), codes
    assert 400 in codes
    assert get_gate().in_use == 0  # no slot leaked by the failures
    # A follow-up request still reaches the handler (400) rather than being
    # refused with 503, which proves capacity came back.
    follow = client.post(
        "/api/analyze/image",
        files={"image": ("shot.png", _png_bytes(), "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert follow.status_code == 400


def test_rate_limiter_rejects_the_overflow_under_concurrency(client, monkeypatch):
    """The per-IP limiter still caps a concurrent burst (independent of the gate)."""
    auth = _auth(client)
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "3")
    monkeypatch.setattr(rate_limit_mod, "_buckets", {})
    get_settings.cache_clear()
    try:

        async def _run():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver", headers=auth
            ) as ac:
                return await asyncio.wait_for(
                    asyncio.gather(*[_text_post(ac) for _ in range(5)]), timeout=GATHER_TIMEOUT
                )

        responses = asyncio.run(_run())
        codes = sorted(r.status_code for r in responses)
        assert codes.count(200) == 3
        assert codes.count(429) == 2
    finally:
        get_settings.cache_clear()

"""Bounded concurrency for image / OCR processing.

The per-IP rate limiter bounds how *often* a client may submit; it says nothing
about how many individually-valid — and therefore memory-hungry — images are
being decoded and OCR'd at the same moment.  ``app/core/concurrency.py`` adds
that in-process bound, and these tests pin the behaviour a client can observe:

* a normal image still succeeds and does not leave a slot held;
* while the configured number of investigations is running, one more is
  refused with a retryable ``503`` (not queued indefinitely);
* capacity is restored once the in-flight work finishes;
* a slot is returned even when processing raises or the upload is rejected.

The concurrency test drives the ASGI app directly with ``httpx.AsyncClient`` so
it can hold one request open deterministically (an ``asyncio.Event``), rather
than relying on sleeps or timing.
"""
from __future__ import annotations

import asyncio
import io

import httpx
import pytest
from fastapi import HTTPException
from PIL import Image

from app.core.config import get_settings
from app.core.concurrency import get_gate, reset_gate
from app.main import app
from app.schemas.api import InvestigationSummary
from tests.conftest import BENIGN_NOTE


def _png_bytes(size: tuple[int, int] = (120, 60)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color=(250, 250, 250)).save(buf, format="PNG")
    return buf.getvalue()


def _image_post(client, text: str = BENIGN_NOTE):
    return client.post(
        "/api/analyze/image",
        files={"image": ("shot.png", _png_bytes(), "image/png")},
        data={"text": text},
    )


@pytest.fixture
def one_slot(monkeypatch):
    """Pin the concurrent-image limit to 1 and rebuild the gate from it."""
    monkeypatch.setenv("MAX_CONCURRENT_IMAGE_OPS", "1")
    get_settings.cache_clear()
    reset_gate()
    yield
    get_settings.cache_clear()
    reset_gate()


def test_gate_is_built_from_the_configured_limit(one_slot):
    assert get_gate().limit == 1


def test_normal_image_succeeds_and_releases_its_slot(client, one_slot):
    """The happy path still works and leaves the counter back at zero."""
    resp = _image_post(client)
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"
    assert get_gate().in_use == 0


def test_extra_image_request_is_refused_while_capacity_is_full(one_slot, monkeypatch):
    """One in-flight investigation fills a single slot; the next gets a 503."""
    entered = asyncio.Event()
    release = asyncio.Event()

    async def _blocking_submission(db, payload, image_bytes=None):
        entered.set()
        await release.wait()
        return InvestigationSummary(investigation_id="stub", title="stub", status="completed")

    monkeypatch.setattr("app.api.routes.analyze._run_submission", _blocking_submission)

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            first = asyncio.create_task(
                ac.post(
                    "/api/analyze/image",
                    files={"image": ("shot.png", _png_bytes(), "image/png")},
                    data={"text": BENIGN_NOTE},
                )
            )
            # Wait until the first request actually holds the slot.
            await asyncio.wait_for(entered.wait(), timeout=5)

            refused = await ac.post(
                "/api/analyze/image",
                files={"image": ("shot.png", _png_bytes(), "image/png")},
                data={"text": BENIGN_NOTE},
            )
            assert refused.status_code == 503
            assert "capacity" in refused.json()["detail"].lower()
            assert refused.headers.get("retry-after") == "1"

            # Let the first request finish; capacity must come back.
            release.set()
            done = await asyncio.wait_for(first, timeout=5)
            assert done.status_code == 200

            recovered = await ac.post(
                "/api/analyze/image",
                files={"image": ("shot.png", _png_bytes(), "image/png")},
                data={"text": BENIGN_NOTE},
            )
            assert recovered.status_code == 200

    asyncio.run(_run())
    assert get_gate().in_use == 0


def test_slot_is_released_when_processing_raises(client, one_slot, monkeypatch):
    """An exception inside the guarded block must not leak the slot.

    With a single slot, a leak would show up on the *second* request as a
    ``503``; the assertion that it is again the ``400`` proves the release.
    """

    async def _boom(db, payload, image_bytes=None):
        raise HTTPException(status_code=400, detail="processing failed")

    monkeypatch.setattr("app.api.routes.analyze._run_submission", _boom)

    first = _image_post(client)
    assert first.status_code == 400
    assert get_gate().in_use == 0

    second = _image_post(client)
    assert second.status_code == 400  # not 503 -> the slot was returned


def test_slot_is_released_after_a_rejected_upload(client, one_slot):
    """A validation failure returns the slot so the next upload can proceed."""
    rejected = client.post(
        "/api/analyze/image",
        files={"image": ("payload.png", b"not an image", "image/png")},
        data={"text": BENIGN_NOTE},
    )
    assert rejected.status_code == 400

    accepted = _image_post(client)
    assert accepted.status_code == 200

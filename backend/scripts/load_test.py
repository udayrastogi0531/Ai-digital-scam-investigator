"""Controlled, in-process load measurement.

This drives the FastAPI app directly over ASGI (no network, no external load
tool) and prints what it actually observed: wall-clock duration, successes,
graceful 503 refusals and failures for a few concurrency scenarios.

It is intentionally modest and honest:

* it measures the *application* under a synthetic burst, not a production
  fleet;
* the provider calls are the deterministic mock implementations, so these are
  not numbers for a deployment with live LLM / threat-intelligence latency;
* the numbers depend entirely on the machine shown in the header — they are a
  baseline, not a guarantee.

Usage (from ``backend/``)::

    python -m scripts.load_test
"""
from __future__ import annotations

import asyncio
import io
import os
import platform
import sys
import tempfile
import time

# Configure the environment before the app is imported (settings/engine are
# built at import time).  Use a throwaway SQLite database and mock providers.
_TMP = tempfile.mkdtemp(prefix="scaminv_load_")
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_TMP}/load.db")
os.environ.setdefault("OCR_PROVIDER", "mock")
os.environ.setdefault("LLM_PROVIDER", "mock")
os.environ.setdefault("AUTH_SECRET_KEY", "load-test-signing-key-not-a-secret")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "10000")
os.environ.setdefault("MAX_CONCURRENT_IMAGE_OPS", "2")

import httpx  # noqa: E402
from PIL import Image  # noqa: E402

from app.core.concurrency import reset_gate  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SMALL_TEXT = "Hi, confirming our meeting tomorrow at 10am. Thanks!"
IMAGE_LIMIT = int(os.environ["MAX_CONCURRENT_IMAGE_OPS"])


def _png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (120, 60), color=(250, 250, 250)).save(buf, format="PNG")
    return buf.getvalue()


async def _run_scenario(kind: str, concurrency: int, headers: dict[str, str]):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", headers=headers, timeout=120
    ) as ac:
        started = time.perf_counter()
        if kind == "text":
            tasks = [ac.post("/api/analyze/text", json={"text": SMALL_TEXT}) for _ in range(concurrency)]
        else:
            tasks = [
                ac.post(
                    "/api/analyze/image",
                    files={"image": ("shot.png", _png_bytes(), "image/png")},
                    data={"text": SMALL_TEXT},
                )
                for _ in range(concurrency)
            ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - started

    ok = refused = failed = 0
    for item in responses:
        if isinstance(item, BaseException):
            failed += 1
        elif item.status_code == 200:
            ok += 1
        elif item.status_code == 503:
            refused += 1
        else:
            failed += 1
    return elapsed, ok, refused, failed


def main() -> int:
    print("== machine ==")
    print(f"platform={platform.platform()} python={sys.version.split()[0]} cpus={os.cpu_count()}")
    print(f"image_concurrency_limit={IMAGE_LIMIT} providers=mock sqlite=temp\n")

    with TestClient(app) as client:
        reg = client.post(
            "/api/auth/register",
            json={"email": "load@example.com", "password": "load-test-passphrase"},
        )
        reg.raise_for_status()
        headers = {"Authorization": f"Bearer {reg.json()['access_token']}"}

        print(f"{'scenario':<26}{'conc':>6}{'seconds':>10}{'ok':>6}{'503':>6}{'fail':>6}")
        print("-" * 60)
        for kind, concurrency in [("text", 1), ("text", 10), ("text", 25), ("image", 1), ("image", 6)]:
            reset_gate()
            elapsed, ok, refused, failed = asyncio.run(_run_scenario(kind, concurrency, headers))
            label = f"{kind} investigations"
            print(f"{label:<26}{concurrency:>6}{elapsed:>10.3f}{ok:>6}{refused:>6}{failed:>6}")

    print("\nNOTE: in-process ASGI measurement on the machine above with mock providers.")
    print("It is a behaviour baseline, not a production throughput guarantee.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

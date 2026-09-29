"""Rate-limiter behaviour.

The limiter had no coverage at all: `conftest.py` raises the limit to 1000 so
it cannot interfere with other tests, which meant nothing asserted that the
limit exists, that it returns `429`, or that the window ever reopens.

These tests exercise the dependency directly with constructed requests, so the
configured test limit stays untouched.

The forwarded-header case is also worth reading as documentation: the client
key comes from `x-forwarded-for` when present, which a client can set itself.
That is a known residual risk recorded in SECURITY.md, not an oversight.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core import rate_limit as rate_limit_mod
from app.core.config import get_settings


def _request(forwarded: str | None = None, host: str = "198.51.100.7") -> Request:
    headers = []
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/investigations",
            "headers": headers,
            "client": (host, 12345),
            "query_string": b"",
        }
    )


@pytest.fixture
def _clean_buckets(monkeypatch):
    """Isolate the module-level bucket store and restore settings afterwards."""
    monkeypatch.setattr(rate_limit_mod, "_buckets", {})
    yield
    get_settings.cache_clear()


def test_client_key_prefers_the_forwarded_address():
    assert rate_limit_mod._client_key(_request(forwarded="203.0.113.5, 10.0.0.1")) == "203.0.113.5"
    assert rate_limit_mod._client_key(_request()) == "198.51.100.7"


def test_rate_limit_allows_up_to_the_limit_then_rejects(monkeypatch, _clean_buckets):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "3")
    get_settings.cache_clear()
    dependency = rate_limit_mod.rate_limit()

    async def _exceed():
        for _ in range(3):
            await dependency(_request())
        await dependency(_request())  # fourth call in the same window

    with pytest.raises(HTTPException) as exc:
        asyncio.run(_exceed())

    assert exc.value.status_code == 429
    assert "rate limit" in exc.value.detail.lower()
    assert "3/minute" in exc.value.detail


def test_rate_limit_window_reopens_after_a_minute(monkeypatch, _clean_buckets):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    get_settings.cache_clear()

    clock = {"now": 1_000.0}
    monkeypatch.setattr(rate_limit_mod.time, "monotonic", lambda: clock["now"])

    dependency = rate_limit_mod.rate_limit()

    async def _run():
        await dependency(_request())
        await dependency(_request())
        clock["now"] += 61.0  # window has passed
        await dependency(_request())  # must be allowed again

    asyncio.run(_run())  # no exception == the window reopened


def test_rate_limit_is_per_client(monkeypatch, _clean_buckets):
    """One noisy client must not exhaust another client's budget."""
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "1")
    get_settings.cache_clear()
    dependency = rate_limit_mod.rate_limit()

    async def _run():
        await dependency(_request(host="198.51.100.7"))
        await dependency(_request(host="203.0.113.9"))  # different client, allowed

    asyncio.run(_run())

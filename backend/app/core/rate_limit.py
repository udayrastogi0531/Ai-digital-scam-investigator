"""In-memory sliding-window rate limiter for expensive endpoints.

Single-process design is sufficient for local/self-hosted deployments;
a Redis-backed limiter would be the production upgrade path.
"""
from __future__ import annotations

import time

from fastapi import HTTPException, Request

from app.core.config import get_settings

_WINDOW_SECONDS = 60.0
_buckets: dict[str, list[float]] = {}


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(limit_per_minute: int | None = None):
    """FastAPI dependency factory: enforce a per-IP limit on POST routes."""

    async def dependency(request: Request) -> None:
        settings = get_settings()
        limit = limit_per_minute or settings.rate_limit_per_minute
        key = _client_key(request)
        now = time.monotonic()
        bucket = _buckets.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < _WINDOW_SECONDS]
        if len(bucket) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded — try again in a moment (max {limit}/minute).",
            )
        bucket.append(now)

    return dependency
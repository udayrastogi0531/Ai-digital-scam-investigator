"""Bounded, in-process concurrency for expensive image/OCR processing.

The upload path already caps a *single* image at 64 M pixels, but several
individually-valid images could be submitted at the same time: 64 M RGB pixels
is roughly 192 MB of raw pixel memory before Python/Pillow/OCR overhead, so a
handful of concurrent decodes can add up.  The per-IP rate limiter bounds how
*often* a client may submit, not how many uploads are being processed at once.

This module supplies the missing bound: a small counter that admits at most
``MAX_CONCURRENT_IMAGE_OPS`` image investigations at a time and rejects the
rest immediately with a retryable ``503`` rather than queueing indefinitely.

Scope and honesty:

* The gate lives in the process.  Under multiple uvicorn/gunicorn workers each
  worker has its own gate, so the effective ceiling is
  ``workers × MAX_CONCURRENT_IMAGE_OPS``.  It is **not** a global limit and it
  is **not** a DDoS control; the per-IP rate limiter still does that job.
* Acquisition is a plain synchronous check-and-increment.  FastAPI runs the
  coroutines of a single worker on one event loop and a coroutine only yields
  at an ``await``, so this check is atomic with respect to other requests —
  there is no window between testing capacity and taking it.  A lock or
  semaphore would buy nothing here and would risk the deadlocks an ``await``
  while holding the gate can introduce.
* The slot is always released from a ``finally`` block, so a validation error,
  an exception inside the pipeline, or a client disconnect cannot leak it.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import HTTPException

from app.core.config import get_settings


class CapacityExceededError(HTTPException):
    """Raised when the concurrent image-processing limit is already taken."""

    def __init__(self, limit: int):
        super().__init__(
            status_code=503,
            detail=(
                f"Image processing is at capacity ({limit} concurrent "
                "investigation(s)); please try again in a moment."
            ),
            headers={"Retry-After": "1"},
        )


class _CapacityGate:
    """A single-threaded bounded counter (see the module docstring)."""

    def __init__(self, limit: int):
        self._limit = max(1, limit)
        self._in_use = 0

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def in_use(self) -> int:
        return self._in_use

    def try_acquire(self) -> bool:
        if self._in_use >= self._limit:
            return False
        self._in_use += 1
        return True

    def release(self) -> None:
        # Guard against a double release turning the counter negative and
        # silently lifting the limit.
        if self._in_use > 0:
            self._in_use -= 1


_gate: _CapacityGate | None = None


def get_gate() -> _CapacityGate:
    """Return the process-wide gate, built lazily from the current settings."""
    global _gate
    if _gate is None:
        _gate = _CapacityGate(get_settings().max_concurrent_image_ops)
    return _gate


def reset_gate() -> None:
    """Rebuild the gate — used by tests after changing the configured limit."""
    global _gate
    _gate = None


@asynccontextmanager
async def image_processing_slot() -> AsyncIterator[None]:
    """Admit one image investigation, releasing the slot on every exit path.

    Raises :class:`CapacityExceededError` (``503``) when every slot is taken;
    it never waits, so a saturating burst cannot pile up unbounded work.
    """
    gate = get_gate()
    if not gate.try_acquire():
        raise CapacityExceededError(gate.limit)
    try:
        yield
    finally:
        gate.release()

"""Threat-intelligence provider abstraction.

Providers are queried by URL only — the backend never fetches or renders
the arbitrary URL itself, which avoids SSRF.  Only providers whose API
keys are configured are instantiated; keys never leave the backend.

Failure semantics (the whole system relies on these):
* A lookup that did not produce a verdict returns ``verdict=unknown`` with
  a non-``ok`` ``status`` (``error`` | ``unavailable`` | ``rate_limited``).
* ``unknown`` / non-``ok`` is *no information*: it is never interpreted as
  clean, never lowers risk, and never counts as an informative verdict in
  the risk engine's normalization.
* Provider responses are normalized here into :class:`ThreatIntelResult`;
  provider-specific payloads stay inside ``detail`` only.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from app.schemas.analysis import ThreatIntelResult


class ThreatIntelProvider(ABC):
    name: str = "base"
    is_mock: bool = False

    @abstractmethod
    async def check(self, url: str) -> ThreatIntelResult:
        """Return reputation/intelligence for a single URL."""


def severity_from_score(score: float) -> str:
    if score >= 0.7:
        return "critical"
    if score >= 0.45:
        return "high"
    if score >= 0.2:
        return "medium"
    return "low"


def now_iso() -> str:
    """ISO-8601 UTC timestamp for a live provider lookup."""
    return datetime.now(timezone.utc).isoformat()


def status_from_http(code: int) -> str:
    """Map an HTTP status to a lookup status.

    ``rate_limited`` for 429, ``unavailable`` for 5xx (the provider is
    having an outage), ``error`` for anything else unexpected.
    """
    if code == 429:
        return "rate_limited"
    if 500 <= code < 600:
        return "unavailable"
    return "error"


def failure_result(provider: str, *, status: str, error: str) -> ThreatIntelResult:
    """A non-verdict result for a failed lookup (never a clean verdict)."""
    return ThreatIntelResult(
        provider=provider,
        verdict="unknown",
        status=status,
        risk_score=0.0,
        reputation=f"lookup failed ({status})",
        hits=0,
        error=error,
        checked_at=now_iso(),
    )
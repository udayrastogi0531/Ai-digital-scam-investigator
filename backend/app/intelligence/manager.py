"""Threat-intelligence manager.

Instantiates every provider whose API key is configured and falls back to
the mock provider otherwise.  All providers are consulted and results are
merged (worst verdict wins, consistent with safety-first aggregation).

Provider failures never crash an investigation: the manager catches every
exception a provider raises and converts it into a normalized
non-verdict result (``verdict=unknown`` with an error/unavailable/
rate_limited status).  Failed lookups are *no information* — they cannot
lower the merged risk and stay visible per-provider in ``detail``.
"""
from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.intelligence.base import ThreatIntelProvider, failure_result
from app.intelligence.google_safe_browsing import GoogleSafeBrowsingProvider
from app.intelligence.mock import MockThreatIntelProvider
from app.intelligence.virustotal import VirusTotalProvider
from app.schemas.analysis import ThreatIntelResult

# Verdict severity order for the safety-first merge.
_VERDICT_ORDER = {"safe": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
# Status severity: which failure state to surface when no verdict exists.
_STATUS_ORDER = {"ok": 0, "error": 1, "unavailable": 2, "rate_limited": 3}


class ThreatIntelManager:
    def __init__(self, providers: list[ThreatIntelProvider] | None = None):
        self.providers = providers if providers is not None else _default_providers()

    @property
    def uses_mock(self) -> bool:
        return all(p.is_mock for p in self.providers)

    @property
    def active_names(self) -> list[str]:
        return [p.name for p in self.providers]

    async def analyze(self, url: str) -> ThreatIntelResult:
        """Query all providers concurrently; merge into a single result."""
        if not self.providers:
            return ThreatIntelResult(provider="none", verdict="unknown", status="ok", risk_score=0.0)
        import asyncio

        async def _safe_check(provider: ThreatIntelProvider) -> ThreatIntelResult:
            try:
                return await provider.check(url)
            except Exception as exc:  # noqa: BLE001 - a provider bug/outage must not crash the run
                return failure_result(
                    provider.name,
                    status="unavailable",
                    error=f"provider raised: {exc}",
                )

        results = await asyncio.gather(*(_safe_check(p) for p in self.providers))
        return _merge(results)


def _merge(results: list[ThreatIntelResult]) -> ThreatIntelResult:
    """Worst verdict wins; risk score is the max across providers.

    Status semantics: ``ok`` as soon as any provider produced an actual
    verdict (safe/suspicious/malicious); otherwise the most severe failure
    state is reported so an outage is visible instead of masquerading as
    "no result".
    """
    if not results:
        return ThreatIntelResult(provider="none", verdict="unknown", status="ok", risk_score=0.0)
    worst = max(results, key=lambda r: (_VERDICT_ORDER.get(r.verdict, 1), r.risk_score))
    real = [r for r in results if not r.is_mock]
    is_mock = not real
    informative = [r for r in results if r.status == "ok" and r.verdict in ("safe", "suspicious", "malicious")]
    if informative:
        status = "ok"
    else:
        status = max((r.status for r in results if r.status != "ok"), key=lambda s: _STATUS_ORDER.get(s, 1), default="ok")
    categories: list[str] = []
    for r in results:
        for cat in r.categories:
            if cat not in categories:
                categories.append(cat)
    checked_at = max((r.checked_at for r in results if r.checked_at), default=None)
    detail = {
        "providers": [
            {
                "provider": r.provider,
                "verdict": r.verdict,
                "status": r.status,
                "risk_score": r.risk_score,
                "reputation": r.reputation,
                "categories": list(r.categories),
                "is_mock": r.is_mock,
                "error": r.error,
                "checked_at": r.checked_at,
            }
            for r in results
        ]
    }
    return ThreatIntelResult(
        provider="+".join(r.provider for r in results),
        is_mock=is_mock,
        verdict=worst.verdict,
        status=status,
        risk_score=round(worst.risk_score, 2),
        reputation=worst.reputation,
        categories=categories,
        hits=sum(r.hits for r in results),
        detail=detail,
        error=worst.error,
        checked_at=checked_at,
    )


def _default_providers() -> list[ThreatIntelProvider]:
    settings = get_settings()
    providers: list[ThreatIntelProvider] = []
    if settings.google_safe_browsing_api_key:
        providers.append(GoogleSafeBrowsingProvider())
    if settings.virustotal_api_key:
        providers.append(VirusTotalProvider())
    if not providers:
        providers.append(MockThreatIntelProvider())
    return providers


@lru_cache(maxsize=1)
def get_manager() -> ThreatIntelManager:
    return ThreatIntelManager()
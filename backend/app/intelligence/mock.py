"""Mock threat-intelligence provider.

Used when no external API keys are configured.  It behaves like a tiny
*fictional* reputation database: hosts on the demo blocklist get a
deterministic suspicious verdict, and everything else is ``unknown``.

Importantly it does NOT recompute URL structural heuristics: that is the
URL-analysis agent's job.  Reusing the same heuristic here would count the
same underlying signal twice in the risk engine, which is why unknown hosts
return a verdict of ``unknown`` with no risk contribution.  Results are
always marked ``is_mock=True`` and the UI labels them as demo data — they
are never presented as real external intelligence.
"""
from __future__ import annotations

from app.intelligence.base import ThreatIntelProvider
from app.schemas.analysis import ThreatIntelResult

# Fictional demo domains used by the bundled demo cases (see services/demo_cases.py).
_DEMO_BLOCKLIST = {
    "secure-login.example.com",
    "login.security-check.example",
    "verify-account.example",
    "track-parcel.example",
    "claim-prize.example",
    "invest-now.example",
    "job-offer.example",
    "kyc-update.example",
    "delivery-center.example",
    "refund-support.example",
    "wallet-verify.example",
    "microsooft-login.example",
    "support-download.example",
    "paypa1-login.example.com",
}


class MockThreatIntelProvider(ThreatIntelProvider):
    name = "mock"
    is_mock = True

    async def check(self, url: str) -> ThreatIntelResult:
        hostname = _hostname(url)
        if hostname in _DEMO_BLOCKLIST or any(
            hostname.endswith("." + d) for d in _DEMO_BLOCKLIST
        ):
            return ThreatIntelResult(
                provider=self.name,
                is_mock=True,
                verdict="suspicious",
                status="ok",
                risk_score=0.85,
                reputation="listed in demo blocklist",
                categories=["demo_blocklist"],
                hits=1,
                detail={
                    "note": "DEMO ONLY: domain appears in the fictional demo blocklist, not a real intelligence feed.",
                    "signals": ["demo_blocklist"],
                },
            )
        return ThreatIntelResult(
            provider=self.name,
            is_mock=True,
            verdict="unknown",
            status="ok",
            risk_score=0.0,
            reputation="no demo reputation record",
            hits=0,
            detail={
                "note": (
                    "DEMO ONLY: the domain has no entry in the fictional demo reputation "
                    "database and no external feed is configured; verdict is unknown rather "
                    "than inferred from URL structure."
                ),
            },
        )


def _hostname(url: str) -> str:
    from urllib.parse import urlparse

    lowered = url.strip().lower()
    if not lowered.startswith(("http://", "https://")):
        lowered = "http://" + lowered
    hostname = (urlparse(lowered).hostname or "").lower().rstrip(".")
    return hostname

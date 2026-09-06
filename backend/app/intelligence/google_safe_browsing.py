"""Google Safe Browsing provider.

API: ``POST https://safebrowsing.googleapis.com/v4/threatMatches:find``
Enabled only when ``GOOGLE_SAFE_BROWSING_API_KEY`` is set.
"""
from __future__ import annotations

import logging

import httpx

from app.core.config import get_settings
from app.intelligence.base import (
    ThreatIntelProvider,
    failure_result,
    now_iso,
    severity_from_score,
    status_from_http,
)
from app.schemas.analysis import ThreatIntelResult

logger = logging.getLogger("scaminvestigator.intel")

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    name = "google_safe_browsing"

    def __init__(self, api_key: str | None = None):
        settings = get_settings()
        self.api_key = api_key or settings.google_safe_browsing_api_key
        self.timeout = settings.threat_intel_timeout_seconds

    async def check(self, url: str) -> ThreatIntelResult:
        endpoint = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={self.api_key}"
        )
        payload = {
            "client": {"clientId": "scam-investigator", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": _THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(endpoint, json=payload)
            if resp.status_code != 200:
                status = status_from_http(resp.status_code)
                return failure_result(
                    self.name,
                    status=status,
                    error=f"GSB returned HTTP {resp.status_code}",
                )
            matches = resp.json().get("matches", [])
            if matches:
                types = sorted({m.get("threatType", "?") for m in matches})
                return ThreatIntelResult(
                    provider=self.name,
                    verdict="malicious",
                    risk_score=0.95,
                    reputation="listed by Google Safe Browsing",
                    categories=list(types),
                    hits=len(matches),
                    detail={"threat_types": types},
                    checked_at=now_iso(),
                )
            return ThreatIntelResult(
                provider=self.name,
                verdict="safe",
                risk_score=0.05,
                reputation="not listed by Google Safe Browsing",
                hits=0,
                checked_at=now_iso(),
            )
        except httpx.HTTPError as exc:
            logger.warning("GSB lookup failed: %s", exc)
            return failure_result(
                self.name,
                status="unavailable",
                error=f"GSB lookup failed (unreachable or timeout): {exc}",
            )


def severity_from_threat(result: ThreatIntelResult) -> str:
    return severity_from_score(result.risk_score)
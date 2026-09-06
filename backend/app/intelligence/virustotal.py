"""VirusTotal v3 URL reputation provider.

API: ``GET /api/v3/urls/{url_id}`` where ``url_id`` is the base64url
encoding of the URL.  Enabled only when ``VIRUSTOTAL_API_KEY`` is set.
"""
from __future__ import annotations

import base64
import logging

import httpx

from app.core.config import get_settings
from app.intelligence.base import (
    ThreatIntelProvider,
    failure_result,
    now_iso,
    status_from_http,
)
from app.schemas.analysis import ThreatIntelResult

logger = logging.getLogger("scaminvestigator.intel")


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    def __init__(self, api_key: str | None = None):
        settings = get_settings()
        self.api_key = api_key or settings.virustotal_api_key
        self.base_url = settings.virustotal_base_url.rstrip("/")
        self.timeout = settings.threat_intel_timeout_seconds

    @staticmethod
    def _url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async def check(self, url: str) -> ThreatIntelResult:
        headers = {"x-apikey": self.api_key}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.base_url}/urls/{self._url_id(url)}", headers=headers
                )
            if resp.status_code == 404:
                return ThreatIntelResult(
                    provider=self.name,
                    verdict="unknown",
                    risk_score=0.1,
                    reputation="not seen by VirusTotal",
                    hits=0,
                    checked_at=now_iso(),
                )
            if resp.status_code != 200:
                status = status_from_http(resp.status_code)
                return failure_result(
                    self.name,
                    status=status,
                    error=f"VirusTotal returned HTTP {resp.status_code}",
                )
            stats = resp.json()["data"]["attributes"].get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(stats.get(k, 0)) for k in ("harmless", "malicious", "suspicious", "undetected"))
            hits = malicious + suspicious
            if malicious >= 1 or suspicious >= 2:
                score = 0.5 + 0.08 * min(hits, 6)
                verdict = "malicious" if malicious >= 2 else "suspicious"
            elif hits == 1:
                score, verdict = 0.45, "suspicious"
            else:
                score, verdict = 0.1, "safe"
            return ThreatIntelResult(
                provider=self.name,
                verdict=verdict,
                risk_score=round(min(0.98, score), 2),
                reputation=(
                    f"{malicious} malicious / {suspicious} suspicious "
                    f"out of {total} engines"
                ),
                hits=hits,
                detail={"stats": stats},
                checked_at=now_iso(),
            )
        except httpx.HTTPError as exc:
            logger.warning("VirusTotal lookup failed: %s", exc)
            return failure_result(
                self.name,
                status="unavailable",
                error=f"VirusTotal lookup failed (unreachable or timeout): {exc}",
            )
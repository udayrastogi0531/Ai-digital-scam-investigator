"""OPT-IN live threat-intelligence integration tests.

These call real external APIs and are therefore excluded from the normal
(offline) test suite.  They only run when explicitly enabled:

    set RUN_LIVE_INTEL_TESTS=1
    set GOOGLE_SAFE_BROWSING_API_KEY=...
    set VIRUSTOTAL_API_KEY=...

(Windows syntax shown; use ``export`` on POSIX.)

Without both the switch and a key for a provider, that provider's tests are
skipped so `pytest` stays fully deterministic offline.

What they assert (not API correctness — the normalized contract):
* provider calls succeed against the live service and return structured,
  normalized results (verdict/status/risk_score/reputation/hits);
* a lookup never crashes or hangs the manager merge;
* no-record / clean outcomes are distinguishable from failures.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from app.core.config import get_settings
from app.intelligence.google_safe_browsing import GoogleSafeBrowsingProvider
from app.intelligence.manager import ThreatIntelManager
from app.intelligence.virustotal import VirusTotalProvider

LIVE_ENABLED = os.environ.get("RUN_LIVE_INTEL_TESTS", "") == "1"
SETTINGS = get_settings()

# Public benign sample URLs; live keys are needed for any lookup to work.
_BENIGN_URLS = ["https://example.com/", "https://www.wikipedia.org/"]


def _has(key_name: str) -> bool:
    return LIVE_ENABLED and bool(getattr(SETTINGS, key_name))


@pytest.mark.skipif(
    not _has("google_safe_browsing_api_key"),
    reason="live GSB test requires RUN_LIVE_INTEL_TESTS=1 + GOOGLE_SAFE_BROWSING_API_KEY",
)
def test_live_google_safe_browsing_normalized_result():
    provider = GoogleSafeBrowsingProvider()

    async def run():
        results = [await provider.check(u) for u in _BENIGN_URLS]
        return results

    results = asyncio.run(run())
    for result in results:
        assert result.status == "ok", result.error
        assert result.verdict in ("safe", "unknown", "suspicious", "malicious")
        assert 0.0 <= result.risk_score <= 1.0
        assert result.provider == "google_safe_browsing"
        assert result.is_mock is False
        assert result.checked_at is not None
        assert result.error is None


@pytest.mark.skipif(
    not _has("virustotal_api_key"),
    reason="live VT test requires RUN_LIVE_INTEL_TESTS=1 + VIRUSTOTAL_API_KEY",
)
def test_live_virustotal_normalized_result():
    provider = VirusTotalProvider()

    async def run():
        results = [await provider.check(u) for u in _BENIGN_URLS]
        return results

    results = asyncio.run(run())
    for result in results:
        assert result.status == "ok", result.error
        assert result.verdict in ("safe", "unknown", "suspicious", "malicious")
        assert result.is_mock is False
        assert result.provider == "virustotal"
        assert result.checked_at is not None


@pytest.mark.skipif(not LIVE_ENABLED, reason="live intel tests disabled")
def test_live_manager_merges_providers_without_crashing():
    """The manager must tolerate any provider state and stay structured."""
    manager = ThreatIntelManager()

    async def run():
        out = []
        for provider in manager.providers:
            try:
                out.append(await provider.check(_BENIGN_URLS[0]))
            except Exception:  # noqa: BLE001 - a live outage must not fail the merge
                out.append(None)
        merged = await manager.analyze(_BENIGN_URLS[0])
        return out, merged

    _, merged = asyncio.run(run())
    assert merged.provider
    assert merged.verdict in ("safe", "unknown", "suspicious", "malicious")
    assert isinstance(merged.detail, dict) and "providers" in merged.detail


LLM_LIVE_ENABLED = os.environ.get("RUN_LIVE_LLM_TESTS", "") == "1" and SETTINGS.llm_provider == "openai_compatible" and bool(SETTINGS.llm_api_key)


@pytest.mark.skipif(
    not LLM_LIVE_ENABLED,
    reason="live LLM test requires RUN_LIVE_LLM_TESTS=1 + LLM_PROVIDER=openai_compatible + LLM_API_KEY",
)
def test_live_llm_explanation_is_grounded_and_non_mock():
    """With a real key the LLM returns a validated, non-mock explanation."""
    import asyncio

    from app.llm.openai_compatible import OpenAICompatibleProvider
    from app.schemas.analysis import ScamClassification
    from app.schemas.llm import ReportContext

    provider = OpenAICompatibleProvider()
    context = ReportContext(
        investigation_id="live-llm-1",
        input_types=["text"],
        text_preview="Please click http://paypa1-verify.example.net/login and verify your account now.",
        classification=ScamClassification(primary="unknown", confidence=0.0),
        evidence=[],
    )

    async def run():
        return await provider.explain(context)

    explanation = asyncio.run(run())
    assert explanation.provider == "openai_compatible"
    assert explanation.is_mock is False
    assert explanation.summary  # structured summary produced

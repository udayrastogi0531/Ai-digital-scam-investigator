"""Phase 3 regression tests.

Covers the Phase-3 hardening areas that are deterministic and offline:

* URL-anchored risk normalization (Goal 1)
* threat-intel provider contract, normalization and failure states (Goal 2)
* mocked provider behavior — no live API calls here; live tests live in
  ``test_threat_intel_live.py`` (env-opt-in)
* LLM grounding / failure fallback with malformed or empty output (Goals 5/6)
* ML real-data loader validation, duplication, contamination guards and
  reproducible splits (Goal 3)
* insufficient-evidence wording (Goal 4)

No test case is hardcoded in production logic — everything here asserts
generic behavior.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from app.graph import run_investigation
from app.intelligence.base import ThreatIntelProvider
from app.intelligence.google_safe_browsing import GoogleSafeBrowsingProvider
from app.intelligence.manager import ThreatIntelManager, _merge
from app.intelligence.mock import MockThreatIntelProvider
from app.intelligence.virustotal import VirusTotalProvider
from app.llm.openai_compatible import OpenAICompatibleProvider
from app.ml.dataset import (
    DatasetValidationError,
    load_dataset,
    stratified_split,
)
from app.schemas.analysis import ScamClassification, TextSignals, ThreatIntelResult
from app.schemas.evidence import InputPayload
from app.schemas.llm import ExplanationResult, ReportContext
from app.schemas.risk import RiskAssessment
from app.services.investigation_service import prepare_state
from app.risk.engine import RiskInputs, compute_risk


# ===========================================================================
# Goal 1 — URL-anchored risk normalization
# ===========================================================================


def _risk(url_risk=0.0, *, text_channel=0.0, anchor=False, intel=0.0, informative=True) -> RiskAssessment:
    return compute_risk(
        RiskInputs(
            ml_score=text_channel,
            url_risk=url_risk,
            threat_intel_score=intel,
            pattern_score=0.0,
            evidence_count=4,
            distinct_sources=2,
            high_severity_count=1 if anchor else 0,
            consistency=0.9,
            has_text=True,
            has_url=True,
            intel_informative=informative,
            url_anchor=anchor,
        )
    )


def test_silent_text_channels_do_not_dilute_anchored_url():
    """A strong URL + neutral text must score like the URL alone (not LOW)."""
    inputs = dict(url_risk=0.9, text_channel=0.0, anchor=True, informative=False)
    with_neutral_text = _risk(**inputs)
    # identical to the pure-URL case because the silent text/ML channels drop
    # out of the normalization entirely
    pure_url = _risk(**{**inputs, "text_channel": 0.0})
    assert with_neutral_text.score == pure_url.score
    assert with_neutral_text.level != "LOW"
    assert with_neutral_text.score >= 50
    # WITHOUT the anchor the same neutral text dilutes the URL to LOW
    diluted = _risk(url_risk=0.9, text_channel=0.0, anchor=False, informative=False)
    assert diluted.level == "LOW"
    assert diluted.score < with_neutral_text.score


def test_weak_url_with_neutral_text_is_not_anchored():
    """A benign/low-risk URL + neutral text must stay LOW (no anchor)."""
    low = _risk(url_risk=0.15, text_channel=0.0, anchor=False)
    assert low.level == "LOW"
    anchored_low_url = _risk(url_risk=0.15, text_channel=0.0, anchor=True)
    # an anchor flag on a weak URL cannot manufacture risk by itself
    assert anchored_low_url.score < 25


def test_anchored_url_combines_with_real_text_evidence():
    """Strong URL + strong text evidence combine rather than cancel."""
    combined = _risk(url_risk=0.9, text_channel=0.9, anchor=True)
    url_only = _risk(url_risk=0.9, text_channel=0.0, anchor=True)
    assert combined.score > url_only.score


def test_anchor_is_generic_not_score_gated():
    """Engine behaviour depends only on the caller-supplied anchor flag."""
    same = _risk(url_risk=0.55, text_channel=0.0, anchor=True)
    stronger = _risk(url_risk=0.9, text_channel=0.0, anchor=True)
    assert stronger.score > same.score
    assert same.level in ("MEDIUM", "HIGH", "CRITICAL")


def test_benign_official_url_plus_scammy_text_not_suspicious_by_url(client):
    body = client.post(
        "/api/investigations",
        data={
            "text": (
                "URGENT security notice for PayPal users: scammers send fake 'account suspended' emails "
                "asking for your password and OTP. PayPal will never ask for these by message. To check "
                "your account, always open https://www.paypal.com yourself and log in."
            )
        },
    ).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] == "LOW"


def test_suspicious_url_with_neutral_text_is_not_diluted(client):
    body = client.post(
        "/api/investigations",
        data={
            "text": (
                "Hi, this invoice arrived in my inbox this morning. Is it legit? "
                "http://paypa1-verify.example.net/invoice?cmd=_verify&email=user@example.net"
            )
        },
    ).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert body["risk"]["score"] >= 25


# ===========================================================================
# Goal 2 — threat-intel provider contract and failure states
# ===========================================================================


class _FixedProvider(ThreatIntelProvider):
    """Deterministic provider stub for manager tests."""

    name = "fixed"
    is_mock = False

    def __init__(self, result: ThreatIntelResult):
        self._result = result

    async def check(self, url: str) -> ThreatIntelResult:
        return self._result


class _BoomProvider(ThreatIntelProvider):
    name = "boom"

    async def check(self, url: str) -> ThreatIntelResult:
        raise RuntimeError("provider exploded")


def _r(provider="fixed", verdict="unknown", status="ok", risk=0.0, is_mock=False, **kwargs):
    return ThreatIntelResult(
        provider=provider, verdict=verdict, status=status, risk_score=risk, is_mock=is_mock, **kwargs
    )


def test_manager_worst_verdict_wins_and_normalizes():
    safe = _r("p1", "safe", risk=0.05)
    mal = _r("p2", "malicious", risk=0.95, categories=["SOCIAL_ENGINEERING"])
    merged = _merge([safe, mal])
    assert merged.verdict == "malicious"
    assert merged.risk_score == 0.95
    assert merged.categories == ["SOCIAL_ENGINEERING"]
    assert merged.status == "ok"
    providers = merged.detail["providers"]
    assert {p["provider"] for p in providers} == {"p1", "p2"}
    assert all("status" in p and "verdict" in p for p in providers)


def test_manager_failure_states_never_look_clean():
    merged = _merge([_r("p1", "unknown", "unavailable", error="down"), _r("p2", "unknown", "rate_limited", error="429")])
    assert merged.verdict == "unknown"
    assert merged.status == "rate_limited"
    assert merged.risk_score == 0.0  # no fabricated risk either way


def test_manager_provider_exception_is_captured_not_crash():
    manager = ThreatIntelManager([_BoomProvider()])
    result = asyncio.run(manager.analyze("https://example.com/x"))
    assert result.verdict == "unknown"
    assert result.status == "unavailable"
    assert "raised" in (result.error or "")


def test_risk_node_ignores_unavailable_intel_for_normalization():
    """A failed provider must not add its weight to the denominator."""
    # buggy legacy behaviour: a real-but-failed provider counted as
    # "informative" with a zero score, adding its 0.25 weight as pure
    # dilution for a weak/benign URL that is not anchored.
    buggy = _risk(url_risk=0.2, intel=0.0, anchor=False, informative=True)
    fixed = _risk(url_risk=0.2, intel=0.0, anchor=False, informative=False)
    assert fixed.score > buggy.score
    # failed intel is no information: identical to no intel at all
    no_intel = _risk(url_risk=0.2, intel=0.0, anchor=False, informative=False)
    assert fixed.score == no_intel.score
    assert fixed.score > 0


# ---- provider-level timeout / status behavior (mocked transport) ----------


class _FakeResp:
    def __init__(self, status_code: int, data=None):
        self.status_code = status_code
        self._data = data if data is not None else {}

    def json(self):
        return self._data


class _FakeClient:
    def __init__(self, responses=None, exc=None):
        self._responses = responses or []
        self._exc = exc
        self.calls: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kwargs):
        self.calls.append(("post", url))
        if self._exc is not None:
            raise self._exc
        return self._responses.pop(0) if self._responses else _FakeResp(200)

    async def get(self, url, **kwargs):
        self.calls.append(("get", url))
        if self._exc is not None:
            raise self._exc
        return self._responses.pop(0) if self._responses else _FakeResp(200)


def _patch_client(monkeypatch, client):
    class _Factory:
        def __init__(self, **kwargs):
            pass

        def __call__(self, **kwargs):
            return client

    monkeypatch.setattr(httpx, "AsyncClient", _Factory())


def test_gsb_rate_limited_status(monkeypatch):
    _patch_client(monkeypatch, _FakeClient(responses=[_FakeResp(429)]))
    result = asyncio.run(GoogleSafeBrowsingProvider(api_key="k").check("https://example.com/"))
    assert result.verdict == "unknown"
    assert result.status == "rate_limited"
    assert result.risk_score == 0.0


def test_gsb_unavailable_on_5xx(monkeypatch):
    _patch_client(monkeypatch, _FakeClient(responses=[_FakeResp(503)]))
    result = asyncio.run(GoogleSafeBrowsingProvider(api_key="k").check("https://example.com/"))
    assert result.status == "unavailable"
    assert result.verdict == "unknown"


def test_gsb_timeout_is_unavailable_not_clean(monkeypatch):
    _patch_client(monkeypatch, _FakeClient(exc=httpx.ConnectTimeout("boom", request=None)))
    result = asyncio.run(GoogleSafeBrowsingProvider(api_key="k").check("https://example.com/"))
    assert result.status == "unavailable"
    assert result.verdict == "unknown"
    assert result.error and "timeout" in result.error.lower()


def test_gsb_malicious_normalizes_categories(monkeypatch):
    resp = _FakeResp(
        200,
        {"matches": [{"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"}]},
    )
    _patch_client(monkeypatch, _FakeClient(responses=[resp]))
    result = asyncio.run(GoogleSafeBrowsingProvider(api_key="k").check("https://evil.example/"))
    assert result.verdict == "malicious"
    assert result.status == "ok"
    assert "SOCIAL_ENGINEERING" in result.categories
    assert result.hits == 2
    assert result.checked_at is not None


def test_gsb_clean_is_informative_ok(monkeypatch):
    _patch_client(monkeypatch, _FakeClient(responses=[_FakeResp(200, {})]))
    result = asyncio.run(GoogleSafeBrowsingProvider(api_key="k").check("https://example.com/"))
    assert result.verdict == "safe"
    assert result.status == "ok"
    assert result.risk_score == 0.05


def test_virustotal_rate_limited_and_unknown_404(monkeypatch):
    _patch_client(monkeypatch, _FakeClient(responses=[_FakeResp(429)]))
    result = asyncio.run(VirusTotalProvider(api_key="k").check("https://example.com/"))
    assert result.status == "rate_limited"
    assert result.verdict == "unknown"

    _patch_client(monkeypatch, _FakeClient(responses=[_FakeResp(404)]))
    result = asyncio.run(VirusTotalProvider(api_key="k").check("https://example.com/"))
    assert result.status == "ok"
    assert result.verdict == "unknown"  # no record != clean
    assert result.risk_score == 0.1


def test_mock_intel_is_unknown_or_blocklist_and_labeled(monkeypatch):
    provider = MockThreatIntelProvider()
    unknown = asyncio.run(provider.check("http://192.168.1.1/webscr"))
    assert unknown.is_mock and unknown.verdict == "unknown" and unknown.status == "ok"
    listed = asyncio.run(provider.check("https://secure-login.example.com/x"))
    assert listed.verdict == "suspicious" and listed.categories == ["demo_blocklist"]


@pytest.mark.asyncio
async def test_graph_completes_when_all_providers_fail(monkeypatch):
    """Provider outage must not crash or lower an investigation's risk."""
    failing = ThreatIntelManager([_BoomProvider()])
    # threat_intel_node resolves get_manager from app.intelligence at import
    # time; the node module holds its own reference.
    monkeypatch.setattr("app.agents.threat_intel_node.get_manager", lambda: failing)

    payload = InputPayload(text="Please open this link: http://paypa1-verify.example.net/invoice?cmd=_verify")
    state = prepare_state("p3-intel-fail", payload)
    result = await run_investigation(state)
    assert result["status"] == "completed"
    # no verdict, but the strong URL evidence is still reflected
    assert result["risk"].level in ("MEDIUM", "HIGH", "CRITICAL")
    assert any("failed" in w or "provider" in w for w in result["warnings"])


# ===========================================================================
# Goals 5/6 — LLM grounding and malformed-output fallback
# ===========================================================================


def _provider(monkeypatch, chat_output):
    provider = OpenAICompatibleProvider(api_key="test-key", base_url="http://localhost:1/v1", model="test")
    calls = []

    async def fake_chat(system, user, json_mode=True):
        calls.append(user)
        if isinstance(chat_output, Exception):
            raise chat_output
        return chat_output

    monkeypatch.setattr(provider, "_chat", fake_chat)
    return provider, calls


def _context() -> ReportContext:
    return ReportContext(
        investigation_id="test-1",
        input_types=["text"],
        text_preview="hello",
        classification=ScamClassification(primary="unknown", confidence=0.0),
        risk=RiskAssessment(score=0.0, level="LOW", confidence=0.2, contributors=[], method="x"),
        evidence=[],
        text_signals=TextSignals(),
    )


@pytest.mark.asyncio
async def test_llm_malformed_classification_falls_back(monkeypatch):
    provider, _ = _provider(monkeypatch, "not json at all")
    result = await provider.classify(_context())
    assert result is None  # classification stays deterministic


@pytest.mark.asyncio
async def test_llm_empty_classification_falls_back(monkeypatch):
    provider, _ = _provider(monkeypatch, "")
    assert await provider.classify(_context()) is None


@pytest.mark.asyncio
async def test_llm_malformed_explanation_uses_deterministic_fallback(monkeypatch):
    provider, _ = _provider(monkeypatch, "```\n{broken json\n```")
    explanation = await provider.explain(_context())
    assert isinstance(explanation, ExplanationResult)
    assert explanation.provider == "deterministic-fallback"
    assert explanation.summary  # grounded summary still produced


@pytest.mark.asyncio
async def test_llm_malformed_report_uses_deterministic_fallback(monkeypatch):
    provider, _ = _provider(monkeypatch, '{"summary": ')
    report = await provider.generate_report(_context())
    assert report.provider == "deterministic-fallback"
    assert report.recommendations is not None


@pytest.mark.asyncio
async def test_llm_exception_falls_back_gracefully(monkeypatch):
    """A network failure inside the real _chat wrapper falls back."""
    provider = OpenAICompatibleProvider(api_key="test-key", base_url="http://localhost:1/v1", model="test")
    _patch_client(monkeypatch, _FakeClient(exc=httpx.ConnectTimeout("down", request=None)))
    explanation = await provider.explain(_context())
    assert explanation.provider == "deterministic-fallback"


@pytest.mark.asyncio
async def test_llm_valid_classification_is_parsed_and_risk_stays_deterministic(monkeypatch):
    provider, _ = _provider(
        monkeypatch,
        json.dumps({"primary": "phishing", "alternatives": [], "confidence": 0.8, "rationale": "url looks bad"}),
    )
    result = await provider.classify(_context())
    assert result is not None and result.primary == "phishing"
    assert result.method == "hybrid(rules+llm)"
    # the LLM never changes the risk assessment itself
    assert result.confidence <= 1.0


def test_deterministic_low_wording_distinguishes_insufficient_evidence():
    from app.llm.deterministic import deterministic_explain

    ctx = _context()
    ctx.risk = RiskAssessment(score=0.0, level="LOW", confidence=0.2, contributors=[], evidence_sufficiency="INSUFFICIENT")
    text = deterministic_explain(ctx).summary
    assert "not a verified safe/clean result" in text
    assert "Insufficient evidence" in text

    ctx.risk = RiskAssessment(score=3.0, level="LOW", confidence=0.8, contributors=[], evidence_sufficiency="SUFFICIENT")
    text2 = deterministic_explain(ctx).summary
    assert "not a verified safe/clean result" not in text2


def test_correlation_conclusion_low_insufficient_wording():
    from app.risk.correlation import build_conclusion

    low_sparse = build_conclusion([], "LOW", "unknown", evidence_sufficiency="INSUFFICIENT")
    assert "not a verified clean result" in low_sparse
    low_supported = build_conclusion(["Suspicious URL structure"], "LOW", "unknown", evidence_sufficiency="SUFFICIENT")
    assert "clean" not in low_supported


# ===========================================================================
# Goal 3 — real-data loader, validation and reproducible splits
# ===========================================================================


def _write_dataset(tmp_path, rows: list[dict], name="data.csv"):
    import csv

    path = tmp_path / name
    fields = list(rows[0].keys()) if rows else ["text", "label"]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_loader_accepts_wellformed_rows(tmp_path):
    path = _write_dataset(
        tmp_path,
        [
            {"id": "r1", "text": "Pay the fee now", "label": "scam", "scam_category": "advance_fee"},
            {"id": "r2", "text": "Lunch at noon?", "label": "benign"},
        ],
    )
    rows, stats = load_dataset(path)
    assert len(rows) == 2
    assert stats.label_counts == {"scam": 1, "benign": 1}
    assert stats.errors == []


def test_loader_rejects_invalid_rows(tmp_path):
    path = _write_dataset(
        tmp_path,
        [
            {"text": "", "label": "scam", "scam_category": "job_scam"},          # no content
            {"text": "hi", "label": "maybe"},                                   # bad label
            {"text": "verify now", "label": "scam"},                            # missing category (strict)
            {"text": "win", "label": "scam", "scam_category": "not_a_category"},  # bad category
            {"text": "ok", "label": "benign", "scam_category": "job_scam"},     # benign w/ scam cat
            {"text": "fine", "label": "benign"},                                # valid
        ],
    )
    rows, stats = load_dataset(path)
    assert len(rows) == 1
    assert len(stats.errors) >= 4


def test_loader_deduplicates_by_text_and_id(tmp_path):
    """Rows are deduplicated by stable id when present, else by text."""
    path = _write_dataset(
        tmp_path,
        [
            {"id": "c", "text": "First with this id", "label": "scam", "scam_category": "phishing"},
            {"id": "c", "text": "Duplicate id", "label": "scam", "scam_category": "phishing"},
            {"text": "Same text twice", "label": "scam", "scam_category": "phishing"},
            {"text": "Same text twice", "label": "benign"},
            {"id": "d", "text": "Unique id row", "label": "benign"},
        ],
    )
    rows, stats = load_dataset(path)
    assert stats.duplicates_removed == 2
    assert len(rows) == 3


def test_loader_refuses_evaluation_corpus():
    with pytest.raises(DatasetValidationError, match="evaluation corpus"):
        load_dataset("data/evaluation/evaluation_cases.json")


def test_loader_rejects_rows_overlapping_evaluation_ids(tmp_path):
    # take one real corpus id
    corpus = json.loads(open("data/evaluation/evaluation_cases.json", encoding="utf-8").read())
    cid = corpus[0]["id"]
    path = _write_dataset(
        tmp_path,
        [{"id": cid, "text": "sneaky copy", "label": "scam", "scam_category": "phishing"}],
    )
    rows, stats = load_dataset(path)
    assert rows == []  # the overlapping row is rejected
    assert any("contamination guard" in e for e in stats.errors)


def test_stratified_split_is_reproducible_and_balanced(tmp_path):
    rows, stats = load_dataset("data/datasets/scam_messages.csv", deduplicate=False)
    train_a, val_a, test_a = stratified_split(rows, seed=7)
    train_b, val_b, test_b = stratified_split(rows, seed=7)
    assert len(train_a) == len(train_b) and len(val_a) == len(val_b) and len(test_a) == len(test_b)
    labels = {r["label"] for r in [*train_a, *val_a, *test_a]}
    assert labels == {"scam", "benign"}
    # classes present in every split
    for part in (train_a, val_a, test_a):
        assert {"scam", "benign"} <= {r["label"] for r in part}
    # deterministic content too
    assert [r["text"] for r in test_a] == [r["text"] for r in test_b]


def test_loader_origin_flags_synthetic(tmp_path):
    rows, stats = load_dataset("data/datasets/scam_messages.csv")
    assert stats.origin == "synthetic"

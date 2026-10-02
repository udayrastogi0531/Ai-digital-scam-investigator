"""Regression tests for the post-audit correctness fixes."""
from __future__ import annotations

import asyncio

import pytest

from app.analysis.text_signals import analyze_text_signals
from app.extraction.text_extractor import extract_all
from app.extraction.url_analysis import analyze_url
from app.graph import run_investigation
from app.intelligence.mock import MockThreatIntelProvider
from app.patterns.engine import classify, is_ambiguous, match_rules
from app.risk.engine import RiskInputs, compute_risk, sufficiency_label, sufficiency_score
from app.schemas.evidence import InputPayload
from app.services.investigation_service import prepare_state

JOB_SCAM_TEXT = (
    "Congratulations, you have been selected for a remote role! Guaranteed salary $3,000/week, "
    "no experience needed. Pay the $99 registration fee now to confirm your seat — only a few spots left."
)

STRONG_BANKING_TEXT = (
    "SECURITY ALERT: unusual activity on your account. Your debit card will be blocked within 24 hours. "
    "Verify your account now at https://secure-login.example.com/card/verify and enter the one-time "
    "code sent to your phone, or your account will be suspended."
)

LOOKALIKE_URL = "http://paypa1-secure-login.example.com/account/verify"


# ---------------------------------------------------------------------------
# Phase 1 — scam-type filter must work on SQLite
# ---------------------------------------------------------------------------

def test_scam_type_filter_works_on_sqlite(client):
    job = client.post("/api/investigations", data={"text": JOB_SCAM_TEXT, "title": "filter job"}).json()
    assert job["status"] == "completed"

    resp = client.get("/api/investigations", params={"scam_type": "job_scam"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert any(item["id"] == job["investigation_id"] for item in body["items"])

    # a non-matching category still returns a non-erroring, correctly
    # filtered result (the shared session DB may hold other investigations,
    # so assert the filter excludes the job rather than the total being 0)
    resp = client.get("/api/investigations", params={"scam_type": "lottery_scam"})
    assert resp.status_code == 200
    assert all(item["id"] != job["investigation_id"] for item in resp.json()["items"])


def test_scam_type_filter_postgres_compiles():
    """The scam-type filter must also compile on PostgreSQL, not just SQLite.

    ``_scam_type_expr`` used to branch on the dialect and call ``.astext`` on
    the PostgreSQL side.  ``.astext`` exists only on the ``postgresql.JSONB``
    comparator, so on the plain ``JSON`` column used here it raised
    ``AttributeError: Neither 'BinaryExpression' object nor 'Comparator'
    object has an attribute 'astext'`` — and because the offline suite runs on
    SQLite, nothing caught it until CI reached a real server.  Compiling the
    expression for the PostgreSQL dialect exercises that branch with no
    server, and pinning the ``->>`` operator keeps the behaviour honest.
    """
    from sqlalchemy.dialects import postgresql, sqlite

    from app.services.investigation_service import _scam_type_expr

    expr = _scam_type_expr("job_scam")
    pg_sql = str(expr.compile(dialect=postgresql.dialect()))
    sqlite_sql = str(expr.compile(dialect=sqlite.dialect()))
    assert "->>" in pg_sql, pg_sql
    assert "json_extract" in sqlite_sql.lower(), sqlite_sql


# ---------------------------------------------------------------------------
# Phase 2 — ML prediction exposed in API
# ---------------------------------------------------------------------------

def test_ml_prediction_exposed_in_api(client):
    body = client.post("/api/investigations", data={"text": STRONG_BANKING_TEXT}).json()
    ml = body.get("ml")
    assert ml is not None, "ML prediction should be part of the API response"
    assert ml["model"] == "LogisticRegression"
    assert ml["is_mock"] is False
    assert 0.0 <= ml["probability_scam"] <= 1.0
    assert ml["label"] in ("benign", "scam")


# ---------------------------------------------------------------------------
# Phase 3 — sparse evidence cannot carry misleadingly high confidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sufficiency_and_confidence_unit_levels():
    sparse = compute_risk(RiskInputs())
    assert sparse.evidence_sufficiency == "INSUFFICIENT"
    assert sparse.confidence < 0.5

    benignish = compute_risk(
        RiskInputs(evidence_count=1, distinct_sources=1, consistency=0.4)
    )
    assert benignish.level == "LOW"
    assert benignish.evidence_sufficiency in ("INSUFFICIENT", "PARTIAL")
    assert benignish.confidence < 0.5

    strong = compute_risk(
        RiskInputs(
            ml_score=0.95,
            url_risk=0.9,
            threat_intel_score=0.9,
            pattern_score=0.9,
            otp_request=1.0,
            credential_request=1.0,
            consistency=0.9,
            evidence_count=10,
            high_severity_count=4,
            distinct_sources=6,
            live_ml=True,
            live_intel=True,
        )
    )
    assert strong.evidence_sufficiency == "SUFFICIENT"
    assert strong.confidence >= 0.8
    assert strong.level in ("HIGH", "CRITICAL")


def test_sufficiency_label_boundaries():
    assert sufficiency_label(0.2) == "INSUFFICIENT"
    assert sufficiency_label(0.5) == "PARTIAL"
    assert sufficiency_label(0.8) == "SUFFICIENT"
    assert 0.0 <= sufficiency_score(RiskInputs()) <= 1.0


def test_benign_text_is_low_confidence_not_high(client):
    body = client.post("/api/investigations", data={"text": "Can we push the standup to 11? Thanks!"}).json()
    assert body["risk"]["level"] == "LOW"
    assert body["risk"]["confidence"] < 0.6
    assert body["risk"]["evidence_sufficiency"] in ("INSUFFICIENT", "PARTIAL")


def test_sparse_unclear_url_low_confidence(client):
    body = client.post(
        "/api/analyze/url", data={"url": "https://example.com/contact"}
    ).json()
    assert body["risk"]["level"] == "LOW"
    assert body["risk"]["evidence_sufficiency"] in ("INSUFFICIENT", "PARTIAL")
    assert body["risk"]["confidence"] <= 0.55


# ---------------------------------------------------------------------------
# Phase 4 — URL-only lookalike detection
# ---------------------------------------------------------------------------

def test_url_only_lookalike_signals_without_text():
    u = analyze_url(LOOKALIKE_URL)
    assert "brand_lookalike" in u.signals
    assert u.risk_score >= 0.5
    assert u.detail["brand_lookalike"]["claimed_brand"] == "paypal"


def test_official_domain_not_flagged_as_lookalike():
    u = analyze_url("https://www.paypal.com/account/login")
    assert "brand_lookalike" not in u.signals
    assert u.risk_score < 0.3


def test_unrelated_domain_not_flagged():
    u = analyze_url("https://example.com/about")
    assert "brand_lookalike" not in u.signals


def test_url_only_lookalike_is_not_falsely_low(client):
    body = client.post("/api/analyze/url", data={"url": LOOKALIKE_URL}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] != "LOW"
    assert any(
        e["source"] == "url_analysis" and e.get("signal") == "url_risk"
        for e in body["evidence"]
    )


def test_blocklisted_url_only_reaches_high(client):
    body = client.post(
        "/api/analyze/url", data={"url": "https://secure-login.example.com/verify"}
    ).json()
    assert body["risk"]["level"] in ("HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# Phase 5 — mock threat intelligence is independent of URL structural risk
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mock_intel_returns_unknown_not_structural():
    provider = MockThreatIntelProvider()
    # High structural risk URL (IP host): intel must still be unknown.
    result = await provider.check("http://192.168.1.1/webscr/login")
    assert result.is_mock is True
    assert result.verdict == "unknown"
    assert result.risk_score == 0.0

    # Fictional demo-blocklist host → deterministic suspicious entry.
    listed = await provider.check("https://secure-login.example.com/x")
    assert listed.verdict == "suspicious"
    assert listed.risk_score == 0.85


# ---------------------------------------------------------------------------
# Phase 6 — LLM classification refinement wiring
# ---------------------------------------------------------------------------

def test_is_ambiguous_helper():
    ambiguous, _ = classify("Hi, how are you? Nothing suspicious here.", extract_all("Hi."), analyze_text_signals("Hi."))
    assert is_ambiguous(ambiguous)
    clear, _ = classify(JOB_SCAM_TEXT, extract_all(JOB_SCAM_TEXT), analyze_text_signals(JOB_SCAM_TEXT))
    assert not is_ambiguous(clear)


@pytest.mark.asyncio
async def test_ambiguous_case_invokes_llm_classify_without_changing_rules():
    text = "We are moving offices next month, new address on 4th street."
    payload = InputPayload(text=text, title="ambiguous")
    state = prepare_state("classify-amb", payload)
    result = await run_investigation(state)
    assert result["status"] == "completed"
    stages = {t["stage"] for t in result["timeline"]}
    assert "llm_classify" in stages  # branch ran in mock mode
    # In demo mode classification stays on the rules result (unchanged).
    assert result["classification"] is not None
    assert result["classification"].primary in ("unknown", "other")


@pytest.mark.asyncio
async def test_clear_classification_skips_llm():
    payload = InputPayload(text=JOB_SCAM_TEXT, title="clear job scam")
    state = prepare_state("classify-clear", payload)
    result = await run_investigation(state)
    assert result["status"] == "completed"
    stages = {t["stage"] for t in result["timeline"]}
    assert "llm_classify" not in stages
    assert result["classification"].primary == "job_scam"


# ---------------------------------------------------------------------------
# Phase 7/8 — banking phishing calibration
# ---------------------------------------------------------------------------

def test_strong_banking_phishing_classified_as_banking():
    classification, matches = classify(
        STRONG_BANKING_TEXT, extract_all(STRONG_BANKING_TEXT), analyze_text_signals(STRONG_BANKING_TEXT)
    )
    assert classification.primary in ("banking_scam", "phishing")
    categories = {m.rule.category for m in matches}
    assert "banking_scam" in categories


def test_strong_banking_phishing_risk_band(client):
    body = client.post("/api/investigations", data={"text": STRONG_BANKING_TEXT}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] in ("HIGH", "CRITICAL")
    assert body["risk"]["score"] >= 50


# ---------------------------------------------------------------------------
# Detection-quality fixes: generalised matching + scam-context gating
# ---------------------------------------------------------------------------

def _rule_ids(text: str) -> set[str]:
    return {m.rule.id for m in match_rules(text, extract_all(text), analyze_text_signals(text))}


def test_numeric_and_hyphenated_guaranteed_returns_are_matched():
    """Pattern variants literal keywords cannot express must still match."""
    text = "Guaranteed 40% returns in 7 days. Double your investment risk-free."
    matches = match_rules(text, extract_all(text), analyze_text_signals(text))
    ids = {m.rule.id for m in matches}
    assert "invest_guaranteed_returns" in ids  # "guaranteed 40% returns", "double your investment"
    assert "invest_risk_free_claim" in ids  # "investment risk-free"
    strong = next(m for m in matches if m.rule.id == "invest_guaranteed_returns")
    assert strong.hit_count >= 2
    assert strong.matched_patterns  # the matched surface forms are explainable


def test_risk_free_claim_variants_are_matched():
    for text in (
        "Zero-risk investing: our fund returns 8% monthly, risk-free and worry free.",
        "A no risk portfolio with guaranteed 6% yearly returns.",
    ):
        assert "invest_risk_free_claim" in _rule_ids(text), text


def test_generalised_signals_feed_the_ml_feature():
    """The pattern change is visible to the model's scam_keyword_hits feature."""
    from app.ml.features import extract_features

    features = extract_features("Guaranteed 40% returns. Double your investment risk-free.")
    assert features["scam_keyword_hits"] >= 2
    assert features["reward_score"] > 0.0
    assert features["pressure_score"] > 0.0


def test_status_only_delivery_claims_need_a_request():
    bare = "Your parcel could not be delivered because the address could not be confirmed."
    assert not (_rule_ids(bare) & {"delivery_undeliverable", "delivery_tracking_link"})

    asked = "Your parcel could not be delivered. Pay the $2.99 redelivery fee within 24 hours."
    assert "delivery_undeliverable" in _rule_ids(asked)


def test_rule_required_entities_are_enforced():
    """`required_entities` gating works (it decides the shared-document rule)."""
    without_link = "Hi, I've shared the document with you. Please review the shared document."
    assert "phishing_shared_document" not in _rule_ids(without_link)

    with_link = (
        "A document has been shared with you. Review it at "
        "https://docs-share.example.com/view?token=9f2a."
    )
    assert "phishing_shared_document" in _rule_ids(with_link)


def test_shared_document_language_does_not_steal_the_banking_category():
    """A banking verification demand keeps its own (more specific) category."""
    text = (
        "Dear customer, routine verification is required to keep your card active. "
        "Please complete verification using the secure portal at "
        "https://meridianbank-secure.example/verify within 72 hours."
    )
    classification, _ = classify(text, extract_all(text), analyze_text_signals(text))
    assert classification.primary == "banking_scam"


# ---------------------------------------------------------------------------
# LLM refinement must stay evidence-driven
# ---------------------------------------------------------------------------

class _FakeLLM:
    """A live-looking provider that always proposes one fixed category."""

    name = "fake-openai-compatible"
    is_mock = False

    def __init__(self, primary: str) -> None:
        self.primary = primary

    async def classify(self, context):
        from app.schemas.analysis import ScamClassification

        return ScamClassification(
            primary=self.primary, alternatives=[], confidence=0.5, method="hybrid(rules+llm)"
        )


@pytest.mark.asyncio
async def test_llm_cannot_invent_a_category_without_deterministic_evidence(monkeypatch):
    """A live LLM must not label a message the rules found no scam signal in."""
    from app.agents import classify_node

    monkeypatch.setattr(classify_node, "get_llm_provider", lambda: _FakeLLM("delivery_scam"))
    text = "Receipt for your parcel delivery. Your parcel was delivered successfully."
    result = await run_investigation(prepare_state("llm-guard", InputPayload(text=text)))

    assert result["status"] == "completed"
    assert result["classification"].primary == "unknown"
    rejected = [e for e in result["evidence"] if e.signal == "classification_suggestion_rejected"]
    assert rejected, "the unadopted suggestion must be recorded, not silently dropped"
    assert rejected[0].detail["suggested_primary"] == "delivery_scam"
    assert result["risk"].level == "LOW"


@pytest.mark.asyncio
async def test_llm_refinement_is_adopted_when_rules_found_evidence(monkeypatch):
    """Refinement still works where the deterministic engine did find a scam."""
    from app.agents import classify_node

    monkeypatch.setattr(classify_node, "get_llm_provider", lambda: _FakeLLM("investment_scam"))
    text = (
        "Earn up to 5% daily with our crypto mining pool! Guaranteed payouts and staking "
        "rewards for early depositors. Deposit BTC to your mining account today."
    )
    result = await run_investigation(prepare_state("llm-adopt", InputPayload(text=text)))

    assert result["classification"].primary == "investment_scam"
    assert result["classification"].method == "hybrid(rules+llm)"


def test_risk_bands_are_monotonic():
    weak = compute_risk(RiskInputs(otp_request=0.0))
    medium = compute_risk(
        RiskInputs(otp_request=1.0, credential_request=1.0, evidence_count=4, distinct_sources=3, consistency=0.9)
    )
    strong = compute_risk(
        RiskInputs(
            ml_score=0.98, url_risk=0.95, threat_intel_score=0.95, pattern_score=1.0,
            otp_request=1.0, credential_request=1.0, payment_request=1.0,
            evidence_count=10, high_severity_count=4, distinct_sources=6,
            consistency=1.0, live_ml=True, live_intel=True,
        )
    )
    assert weak.score <= medium.score <= strong.score
    assert weak.level == "LOW"
    assert strong.level in ("HIGH", "CRITICAL")

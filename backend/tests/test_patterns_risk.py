"""Unit tests: scam patterns, entities, risk engine, evidence correlation."""
from __future__ import annotations

from app.analysis.text_signals import analyze_text_signals
from app.extraction.entity_extractor import extract_known_entities
from app.extraction.text_extractor import extract_all
from app.patterns.engine import classify
from app.risk.correlation import correlate_evidence
from app.risk.engine import RiskInputs, compute_risk
from app.schemas.evidence import EvidenceSignal


def _signals(text: str):
    return analyze_text_signals(text)


def test_job_scam_pattern():
    text = (
        "You are selected! Guaranteed salary $3,000/week for 5 hours. "
        "Pay $99 registration fee to secure your position. Hurry, limited slots!"
    )
    classification, matches = classify(text, extract_all(text), _signals(text))
    assert classification.primary == "job_scam"
    assert classification.confidence > 0.5
    categories = {m.rule.category for m in matches}
    assert "job_scam" in categories


def test_banking_phishing_pattern():
    text = (
        "URGENT: Your account will be suspended. Confirm your details or it will be closed. "
        "Enter your password and OTP at http://bank-secure-verify.example/login"
    )
    classification, matches = classify(text, extract_all(text), _signals(text))
    assert classification.primary in ("banking_scam", "phishing", "account_takeover")
    assert any(m.rule.category in ("banking_scam", "phishing") for m in matches)


def test_benign_message_not_classified_scam():
    text = "Hi, can we move the standup to 10:30 tomorrow? The report is attached. Thanks!"
    classification, matches = classify(text, extract_all(text), _signals(text))
    assert classification.primary in ("unknown", "other")
    assert matches == []


def test_known_entity_extraction():
    text = "Your Microsoft account will be closed. Verify at http://microsoft-verify.example/login"
    entities = extract_known_entities(text)
    all_values = [e.value.lower() for e in entities.all()]
    assert any("microsoft" in v for v in all_values)


def test_risk_boundaries():
    low = compute_risk(RiskInputs())
    assert low.level == "LOW"
    assert 0 <= low.score <= 100

    high = compute_risk(
        RiskInputs(
            ml_score=0.95,
            url_risk=0.9,
            threat_intel_score=0.9,
            pattern_score=0.9,
            payment_request=1.0,
            credential_request=1.0,
            otp_request=1.0,
            evidence_count=8,
            high_severity_count=5,
        )
    )
    assert high.score >= 50
    assert high.level in ("HIGH", "CRITICAL")
    assert high.contributors  # contributing factors explained


def test_risk_weights_configurable_format():
    score = compute_risk(RiskInputs(payment_request=1.0, evidence_count=2)).score
    assert isinstance(score, float)


def test_correlation_groups_themes_and_reports_conflicts():
    signals = [
        EvidenceSignal(source="url_analysis", signal="suspicious_domain", severity="high", confidence=0.9,
                       description="lookalike domain"),
        EvidenceSignal(source="text_analysis", signal="credential_request", severity="high", confidence=0.9,
                       description="asks for password"),
        EvidenceSignal(source="text_analysis", signal="payment_request", severity="high", confidence=0.8,
                       description="asks for payment"),
    ]
    result = correlate_evidence(signals, None, risk_level=None, classification_primary=None)
    assert len(result.corroborating) >= 1
    assert result.consistency_score > 0.5
    assert "url_risk" in result.themes and "language_signals" in result.themes
    assert result.conclusion

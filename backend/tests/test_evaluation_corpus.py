"""Corpus-driven regression tests (Phase 2 detection calibration).

Every case in ``data/evaluation/evaluation_cases.json`` is run through the
REAL API pipeline:

* benign cases must stay LOW (strict — false positives on hard negatives
  fail the suite);
* scam cases must reach their expected minimum risk band and the expected
  (or documented-acceptable) category;
* sparse evidence must not produce a confident verdict.

``known_hard_case`` entries are excluded from band assertions on purpose:
they are documented as cases the deterministic engine honestly cannot
disambiguate (e.g. an unsolicited shared-document link with no other
signals).  The corpus notes explain why.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "evaluation" / "evaluation_cases.json"
LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

CASES = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
BENIGN_IDS = [c["id"] for c in CASES if not c["expected"]["is_scam"]]
SCAM_IDS = [c["id"] for c in CASES if c["expected"]["is_scam"] and not c.get("known_hard_case")]


def _case(case_id: str) -> dict:
    return next(c for c in CASES if c["id"] == case_id)


def _submit(client, case: dict) -> dict:
    data = {}
    if case.get("text"):
        data["text"] = case["text"]
    if case.get("urls"):
        data["urls"] = case["urls"]
    resp = client.post("/api/investigations", data=data)
    assert resp.status_code < 400, f"{case['id']}: HTTP {resp.status_code} {resp.text[:300]}"
    return resp.json()


@pytest.mark.parametrize("case_id", BENIGN_IDS)
def test_benign_case_stays_low(client, case_id):
    """Every benign corpus case (including all hard negatives) must be LOW."""
    body = _submit(client, _case(case_id))
    assert body["status"] == "completed"
    level = body["risk"]["level"]
    assert level == "LOW", (
        f"{case_id}: benign message scored {level} {body['risk']['score']} "
        f"({body['risk']['confidence']:.0%}) — false positive"
    )


@pytest.mark.parametrize("case_id", SCAM_IDS)
def test_scam_case_reaches_expected_band_and_category(client, case_id):
    """Scam cases must reach their expected band and category."""
    case = _case(case_id)
    exp = case["expected"]
    body = _submit(client, case)
    assert body["status"] == "completed"
    level = body["risk"]["level"]
    assert LEVELS[level] >= LEVELS[exp["minimum_risk_level"]], (
        f"{case_id}: expected >= {exp['minimum_risk_level']}, got {level} "
        f"(score {body['risk']['score']})"
    )
    if exp["primary_category"] != "unknown":
        pred = (body.get("scam_type") or {}).get("primary")
        acceptable = (exp["primary_category"], *exp.get("acceptable_categories", []))
        assert pred in acceptable, (
            f"{case_id}: expected category {exp['primary_category']}, got {pred}"
        )


def test_sparse_url_is_not_confidently_low(client):
    """Sparse evidence must stay uncertain (low confidence / INSUFFICIENT)."""
    sparse = _submit(client, _case("burl02_sparse"))
    assert sparse["risk"]["confidence"] <= 0.55, (
        f"sparse URL reported {sparse['risk']['confidence']:.0%} confidence"
    )
    assert sparse["risk"]["evidence_sufficiency"] in ("INSUFFICIENT", "PARTIAL")


def test_strong_corroborated_case_has_higher_confidence(client):
    """Multi-channel evidence must carry materially higher confidence."""
    strong = _submit(client, _case("m01_banking_strong_mixed"))
    assert strong["risk"]["evidence_sufficiency"] in ("PARTIAL", "SUFFICIENT")
    assert strong["risk"]["confidence"] >= 0.8


def test_ml_prediction_exposed_in_api(client):
    """ML contribution is exposed and clearly labelled (not the verdict)."""
    body = _submit(client, _case("s11_investment_guaranteed"))
    ml = body.get("ml") or {}
    assert ml.get("probability_scam") is not None
    assert ml.get("model")
    assert ml.get("is_mock") is not None


# --- unit-level signal checks (fast, no HTTP) -------------------------------


def test_protective_warning_is_not_a_credential_request():
    from app.analysis.text_signals import analyze_text_signals

    ts = analyze_text_signals(
        "Meridian Bank: never share your OTP or card PIN with anyone. "
        "Our staff will never ask for your password or one-time code."
    )
    assert ts.protective_warning is True
    assert ts.otp_request is False
    assert ts.credential_request is False


def test_two_factor_code_is_not_an_otp_request():
    from app.analysis.text_signals import analyze_text_signals

    ts = analyze_text_signals(
        "Your Nova verification code is 482913. It expires in 10 minutes. "
        "Never share this code with anyone."
    )
    assert ts.otp_request is False


def test_otp_request_requires_requestive_verb():
    from app.analysis.text_signals import analyze_text_signals

    scam = analyze_text_signals(
        "Reply with the one-time code we just sent to confirm your identity."
    )
    assert scam.otp_request is True


def test_payment_mention_is_not_a_payment_request():
    from app.analysis.text_signals import analyze_text_signals

    ts = analyze_text_signals(
        "Receipt from CloudNest: your subscription payment of $14.99 was received. Thank you."
    )
    assert ts.payment_request is False


def test_punycode_homoglyph_lookalike_detected():
    from app.extraction.entity_extractor import detect_brand_lookalike_host

    hit = detect_brand_lookalike_host("xn--80ak6aa92e.com")
    assert hit is not None
    assert hit["claimed_brand"] == "apple"
    assert detect_brand_lookalike_host("www.paypal.com") is None


def test_alarm_rules_suppressed_for_protective_warning():
    from app.analysis.text_signals import analyze_text_signals
    from app.patterns.engine import match_rules

    text = (
        "Meridian Bank: never share your OTP or card PIN with anyone. "
        "Our staff will never ask for your password or one-time code."
    )
    ts = analyze_text_signals(text)
    matches = match_rules(text, None, ts)
    assert all(
        m.rule.id not in {"bank_otp_request", "bank_login_verification", "phishing_generic"}
        for m in matches
    )


def test_requestive_scam_is_not_suppressed_by_protective_wording():
    from app.analysis.text_signals import analyze_text_signals
    from app.patterns.engine import match_rules

    text = (
        "CoinPulse Support: to restore access to your wallet, enter your 12-word "
        "recovery phrase at https://coinpulse-wallet.example/restore. "
        "Do not share your phrase with anyone else."
    )
    ts = analyze_text_signals(text)
    assert ts.credential_request is True  # "enter your" is a real request
    matches = match_rules(text, None, ts)
    assert any(m.rule.id == "crypto_wallet_drain" for m in matches)
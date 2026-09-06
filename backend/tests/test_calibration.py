"""Risk-calibration regression tests (post-audit phases 7/8/11).

Each case is a realistic, fully fictional scam/benign message.  The
assertions pin the *risk band* the investigation engine must land in so
calibration changes stay intentional — they do not assert exact scores.
"""
from __future__ import annotations

BENIGN = "Can we push the standup to 11? Thanks!"

JOB_SCAM = (
    "Congratulations, you have been selected for a remote role! Guaranteed income of "
    "$3,000/week, no experience needed. Pay the $99 registration fee now to confirm your "
    "seat — only 3 spots left, this offer expires today."
)

BANKING_PHISHING = (
    "SECURITY ALERT: unusual activity on your account. Your debit card will be blocked "
    "within 24 hours. Verify your account now at https://secure-login.example.com/card/verify "
    "and enter the one-time code sent to your phone, or your account will be suspended."
)

INVESTMENT_SCAM = (
    "Guaranteed 400% returns in 48 hours from our crypto signals — zero risk. Deposit now, "
    "the offer closes at midnight and only 20 spots remain. Send $250 via crypto wallet to "
    "activate your account and double your money."
)

DELIVERY_SCAM = (
    "Your parcel is on hold. Pay the $1.99 redelivery fee at "
    "https://track-parcel.example/reschedule within 24 hours or it will be returned to sender."
)

LOOKALIKE_URL = "http://paypa1-secure-login.example.com/account/verify"
SPARSE_URL = "https://example.com/contact"


def test_benign_text_stays_low(client):
    body = client.post("/api/investigations", data={"text": BENIGN}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] == "LOW"
    assert body["risk"]["confidence"] < 0.6
    assert body["risk"]["evidence_sufficiency"] in ("INSUFFICIENT", "PARTIAL")
    assert (body["scam_type"] or {}).get("primary") == "unknown"


def test_job_scam_reaches_high(client):
    body = client.post("/api/investigations", data={"text": JOB_SCAM}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] in ("HIGH", "CRITICAL")
    assert body["scam_type"]["primary"] == "job_scam"


def test_banking_phishing_reaches_high(client):
    body = client.post("/api/investigations", data={"text": BANKING_PHISHING}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] in ("HIGH", "CRITICAL")
    assert body["risk"]["score"] >= 50
    assert body["scam_type"]["primary"] == "banking_scam"


def test_url_only_lookalike_flagged_not_low(client):
    body = client.post("/api/investigations", data={"urls": LOOKALIKE_URL}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] != "LOW"
    # URL-derived classification (no text needed) identifies the intent.
    assert body["scam_type"]["primary"] == "phishing"


def test_official_login_url_not_flagged(client):
    body = client.post("/api/investigations", data={"urls": "https://www.paypal.com/account/login"}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] == "LOW"


def test_investment_scam_reaches_high(client):
    body = client.post("/api/investigations", data={"text": INVESTMENT_SCAM}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] in ("HIGH", "CRITICAL")
    assert body["scam_type"]["primary"] == "investment_scam"


def test_delivery_scam_classified_delivery_and_banded(client):
    body = client.post("/api/investigations", data={"text": DELIVERY_SCAM}).json()
    assert body["status"] == "completed"
    assert body["scam_type"]["primary"] == "delivery_scam"
    assert body["risk"]["level"] in ("MEDIUM", "HIGH")


def test_sparse_url_low_confidence_not_misleading(client):
    body = client.post("/api/investigations", data={"urls": SPARSE_URL}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] == "LOW"
    assert body["risk"]["confidence"] <= 0.55
    assert body["risk"]["evidence_sufficiency"] in ("INSUFFICIENT", "PARTIAL")

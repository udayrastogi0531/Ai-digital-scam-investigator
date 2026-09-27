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

# --- generalised guaranteed-return language (documented calibration gap) ---
# The rule keyword list holds literal phrases, so the numeric variant
# ("guaranteed 40% returns" has a token between the two keywords) and the
# hyphenated "risk-free" were never matched and an obvious investment scam
# stayed at LOW.
GUARANTEED_RETURNS_NUMERIC = "Guaranteed 40% returns in 7 days. Double your investment risk-free."
GUARANTEED_RETURNS_PERCENT = (
    "Our fund guarantees 12% annual returns with no risk — deposit today to lock in "
    "your allocation."
)

# --- hard negatives for the same wording --------------------------------
# A genuine receipt that merely mentions a parcel, a genuine carrier notice
# with an official link, promotional "risk-free" wording and a real risk
# disclaimer.  None of them is a scam, so all of them must stay LOW.
BENIGN_RECEIPT_PARCEL = "Receipt for your parcel delivery. Your parcel was delivered successfully."
BENIGN_CARRIER_NOTICE = (
    "Your parcel from Acme is out for delivery today. Track your package at "
    "https://www.dhl.com/us-en/home/tracking.html"
)
BENIGN_RISK_FREE_PROMO = "Try Nova Pro risk-free for 30 days. No credit card required, cancel anytime."
BENIGN_INVESTMENT_DISCLAIMER = (
    "Important: the value of investments can fall as well as rise. No investment can "
    "guarantee returns, and past performance is not a guide to the future."
)

# --- shared-document link bait (documented false negative) ----------------
SHARED_DOCUMENT_LINK = (
    "Please review the shared file. Open the file here: "
    "https://files-share.example.com/view?token=9f2a. Access is valid for 48 hours."
)
BENIGN_FILE_SHARING = (
    "Hi team, I've put the Q3 report in our shared folder at "
    "https://drive.google.com/drive/folders/abc. Let me know if you cannot open the file."
)
BENIGN_ESIGNATURE = (
    "Reminder: your Q3 contract is awaiting your signature. Sign the document within "
    "24 hours at https://acme.docusign.com/sign/abc."
)


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


def test_guaranteed_numeric_returns_reach_medium_investment(client):
    """Numeric/hyphenated guaranteed-return wording must not stay LOW."""
    for text in (GUARANTEED_RETURNS_NUMERIC, GUARANTEED_RETURNS_PERCENT):
        body = client.post("/api/investigations", data={"text": text}).json()
        assert body["status"] == "completed"
        assert body["risk"]["level"] in ("MEDIUM", "HIGH", "CRITICAL"), (
            f"guaranteed-return pitch scored {body['risk']['level']} "
            f"({body['risk']['score']})"
        )
        assert body["scam_type"]["primary"] == "investment_scam"


def test_benign_receipt_mentioning_parcel_stays_low(client):
    """A genuine receipt must not be labelled a delivery scam."""
    body = client.post("/api/investigations", data={"text": BENIGN_RECEIPT_PARCEL}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] == "LOW"
    assert (body["scam_type"] or {}).get("primary") == "unknown"


def test_benign_carrier_notice_with_official_link_stays_low(client):
    """A genuine delivery notice carrying an official carrier link is not a scam."""
    body = client.post("/api/investigations", data={"text": BENIGN_CARRIER_NOTICE}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] == "LOW"


def test_benign_risk_free_and_guarantee_wording_stays_low(client):
    """Promotional "risk-free" wording and investment disclaimers are not scams."""
    for text in (BENIGN_RISK_FREE_PROMO, BENIGN_INVESTMENT_DISCLAIMER):
        body = client.post("/api/investigations", data={"text": text}).json()
        assert body["status"] == "completed"
        assert body["risk"]["level"] == "LOW", (
            f"benign investment wording scored {body['risk']['level']} "
            f"({body['risk']['score']}): {text[:60]}"
        )


def test_shared_document_link_bait_is_phishing_not_low(client):
    """An unsolicited shared-document link is phishing, not LOW."""
    body = client.post("/api/investigations", data={"text": SHARED_DOCUMENT_LINK}).json()
    assert body["status"] == "completed"
    assert body["risk"]["level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert body["scam_type"]["primary"] == "phishing"


def test_benign_file_sharing_messages_stay_low(client):
    """Everyday file talk and a legitimate e-signature request are not scams."""
    for text in (BENIGN_FILE_SHARING, BENIGN_ESIGNATURE):
        body = client.post("/api/investigations", data={"text": text}).json()
        assert body["status"] == "completed"
        assert body["risk"]["level"] == "LOW", (
            f"benign file-sharing text scored {body['risk']['level']} "
            f"({body['risk']['score']}): {text[:60]}"
        )

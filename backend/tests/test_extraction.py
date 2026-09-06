"""Unit tests: URL feature extraction, text/entity extraction, signals."""
from __future__ import annotations

from app.analysis.text_signals import analyze_text_signals
from app.extraction.text_extractor import extract_all, extract_urls
from app.extraction.url_analysis import analyze_url


def test_url_ip_address_flagged():
    u = analyze_url("http://192.168.1.1/login.php")
    assert u.has_ip_address is True
    assert u.hostname == "192.168.1.1"


def test_url_https_and_parsing():
    u = analyze_url("https://www.example.com/secure/path?q=1&token=abc")
    assert u.is_https is True
    assert u.domain == "example.com"
    assert u.tld == "com"
    assert u.query_params == ["q", "token"]


def test_url_suspicious_keywords_and_tld():
    u = analyze_url("http://paypal-secure-verify.xyz/account/login")
    assert u.risk_score >= 0.4
    assert any("verify" in kw or "secure" in kw for kw in u.suspicious_keywords)


def test_url_shortener_detected():
    u = analyze_url("https://bit.ly/abc123")
    assert u.is_shortened is True
    assert u.risk_score >= 0.2


def test_benign_url_low_risk():
    u = analyze_url("https://www.example.com/about")
    assert u.risk_score < 0.15


def test_extract_urls_email_phone_amount():
    text = (
        "Contact support@example.test or +1-555-0100. Pay $2,450 by Friday "
        "at http://claim.example/release. Meeting is on 12 May."
    )
    entities = extract_all(text)
    assert any(e.value == "http://claim.example/release" for e in entities.urls)
    assert any(e.value == "support@example.test" for e in entities.emails)
    assert any(e.entity_type == "phone" for e in entities.all())
    assert any(e.entity_type == "amount" for e in entities.all())
    assert any(e.entity_type == "date" for e in entities.all())


def test_extract_international_phone_formats():
    text = "Call +1-555-0100 or (555) 010-1234 or 555-0167 today."
    entities = extract_all(text)
    values = [e.value for e in entities.all() if e.entity_type == "phone"]
    assert "+1-555-0100" in values
    assert "(555) 010-1234" in values
    assert "555-0167" in values


def test_extract_urls_dedupes():
    text = "Check http://example.com and http://example.com again"
    assert len(extract_urls(text)) == 1


def test_normal_message_has_no_urgency():
    signals = analyze_text_signals("Hi, can we move the standup to 10:30 tomorrow? Thanks!")
    assert signals.urgency_score < 0.5
    assert not signals.credential_request
    assert not signals.payment_request


def test_phishing_signals_detected():
    text = (
        "URGENT: your account will be closed unless you verify now. "
        "Send your password and OTP to avoid suspension. Pay the fee today."
    )
    signals = analyze_text_signals(text)
    assert signals.urgency_score >= 0.25
    assert signals.urgent_phrases  # urgency language present
    assert signals.credential_request is True
    assert signals.otp_request is True
    assert signals.payment_request is True

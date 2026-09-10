"""Feature extraction for the scam classifier.

The SAME function is used by the training script and by the live backend,
guaranteeing the trained model sees the exact feature distribution it will
encounter at inference time.

All features are derived deterministically from structured inputs
(entities, text signals, URL analyses) so nothing here depends on an LLM.
"""
from __future__ import annotations

from app.analysis.text_signals import analyze_text_signals
from app.extraction.text_extractor import extract_all
from app.patterns.engine import match_rules

# URL *presence* features are deliberately absent.  This product
# investigates suspicious URLs by design, so “a URL is present” is
# uninformative for the language model — and URL structural risk is already
# scored deterministically by the ``url_risk`` channel (plus threat
# intelligence).  Training the ML on URL-presence would double-count URL
# evidence and taught the SMS-trained model to flag *any* URL-heavy message
# as spam, inflating confidence on sparse URL submissions.  URL findings
# still flow into the feature vector via ``scam_keyword_hits`` / text
# signals when the surrounding language is suspicious.
FEATURE_NAMES = [
    "message_length",
    "word_count",
    "special_char_frequency",
    "uppercase_ratio",
    "urgency_score",
    "fear_threat_score",
    "reward_score",
    "pressure_score",
    "authority_score",
    "payment_request",
    "credential_request",
    "otp_request",
    "sensitive_info_request",
    "has_phone",
    "has_email",
    "amount_count",
    "scam_keyword_hits",
    "punctuation_ratio",
]

SPECIAL_CHARS = set("_@%*&!")


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, v))


def extract_features(
    text: str,
    *,
    entities=None,
    text_signals=None,
    url_analyses=None,
) -> dict[str, float]:
    """Compute the feature vector as an ordered dict keyed by FEATURE_NAMES.

    ``url_analyses`` is accepted for API compatibility with the graph nodes
    but not consumed: URL risk is scored by the deterministic ``url_risk``
    channel, not the ML language model (see the FEATURE_NAMES note).
    """
    from app.utils.text import normalize_text

    text = normalize_text(text)

    if entities is None:
        entities = extract_all(text)
    if text_signals is None:
        text_signals = analyze_text_signals(text)

    lower = text.lower()
    total_chars = max(len(text), 1)

    special_chars = sum(1 for ch in text if ch in SPECIAL_CHARS)
    punctuation = sum(1 for ch in text if ch in ".,;:!?")
    uppercase = sum(1 for ch in text if ch.isupper())

    scam_matches = match_rules(text, entities, text_signals)

    return {
        "message_length": float(len(text)),
        "word_count": float(len(text.split())),
        "special_char_frequency": special_chars / total_chars,
        "uppercase_ratio": uppercase / total_chars,
        "urgency_score": text_signals.urgency_score,
        "fear_threat_score": text_signals.fear_threat_score,
        "reward_score": text_signals.reward_score,
        "pressure_score": text_signals.pressure_score,
        "authority_score": _clamp01(0.25 * len(text_signals.authority_phrases)),
        "payment_request": float(text_signals.payment_request),
        "credential_request": float(text_signals.credential_request),
        "otp_request": float(text_signals.otp_request),
        "sensitive_info_request": float(text_signals.sensitive_info_request),
        "has_phone": float(len(entities.phones) > 0),
        "has_email": float(len(entities.emails) > 0),
        "amount_count": float(len(entities.amounts)),
        "scam_keyword_hits": float(len(scam_matches)),
        "punctuation_ratio": punctuation / total_chars,
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    """Ordered numeric vector aligned with FEATURE_NAMES."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]
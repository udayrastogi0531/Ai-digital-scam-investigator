"""Risk node: aggregate all component scores into the deterministic risk."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.graph.state import InvestigationState
from app.risk import RiskInputs, compute_risk
from app.risk.engine import URL_ANCHOR_MIN


# Verdicts that actually inform the risk engine (as opposed to "no data":
# unknown/no-record/error/unavailable/rate-limited carry no information and
# must never dilute the URL evidence).
_INFORMATIVE_VERDICTS = {"safe", "suspicious", "malicious"}

# Verdicts strong enough to *anchor* a URL assessment.
_ANCHOR_VERDICTS = {"suspicious", "malicious"}


def _informative(result) -> bool:
    return result.status == "ok" and result.verdict in _INFORMATIVE_VERDICTS


def _anchoring(result) -> bool:
    return result.status == "ok" and result.verdict in _ANCHOR_VERDICTS


@timed_node("risk")
def risk_node(state: InvestigationState) -> InvestigationState:
    ml = state.get("ml_prediction")
    urls = state.get("urls") or []
    threat_intel = state.get("threat_intel") or []
    patterns = state.get("pattern_matches") or []
    text_signals = state.get("text_signals")
    entity_analysis = state.get("entity_analysis")
    correlation = state.get("correlation") or {}
    evidence = state.get("evidence") or []

    # Sum of matched-rule weights over 4.0: a single critical rule (2.5)
    # reaches ~0.6 and a pair of vetted high-severity rules saturate the
    # channel, so strong rule evidence is not diluted by unrelated text
    # channels.  Calibrated on the evaluation corpus (see scripts/
    # evaluate_detection.py) — no single rule alone decides a verdict.
    pattern_score = min(1.0, sum(p.get("weight", 1.0) for p in patterns) / 4.0)

    url_risk = max((u.risk_score for u in urls), default=0.0)
    threat_score = max((t.risk_score for t in threat_intel), default=0.0)
    impersonation = min(1.0, len(entity_analysis.impersonation_indicators) / 2.0) if entity_analysis else 0.0

    high_severity = sum(1 for e in evidence if e.severity in ("high", "critical"))
    distinct_sources = len({e.source for e in evidence})
    has_text = bool(
        (state.get("normalized_text") or "").strip() or (state.get("ocr_text") or "").strip()
    )
    has_url = bool(urls)
    # Intel only participates in the score when it actually produced an
    # informative verdict (a real clean/malicious/suspicious answer or a
    # demo blocklist hit).  "No data" — mock-unknown, no reputation record,
    # provider outage, timeout or rate limit — carries no information and
    # must neither contribute to the numerator nor dilute the URL weight.
    intel_informative = any(_informative(t) for t in threat_intel)
    live_ml = bool(ml and not ml.is_mock and ml.model not in (None, "none"))
    live_intel = any(not t.is_mock for t in threat_intel)
    # URL-anchored evidence: strong structural URL risk or an intel verdict
    # of suspicious/malicious.  Only then does the engine stop counting
    # silent text channels in the normalization denominator.
    url_anchor = has_url and (
        any(u.risk_score >= URL_ANCHOR_MIN for u in urls) or any(_anchoring(t) for t in threat_intel)
    )

    inputs = RiskInputs(
        ml_score=ml.probability_scam if ml else 0.0,
        url_risk=url_risk,
        threat_intel_score=threat_score,
        pattern_score=pattern_score,
        entity_impersonation=impersonation,
        urgency=max(text_signals.urgency_score, text_signals.fear_threat_score, text_signals.pressure_score) if text_signals else 0.0,
        payment_request=float(text_signals.payment_request) if text_signals else 0.0,
        credential_request=float(text_signals.credential_request) if text_signals else 0.0,
        otp_request=float(text_signals.otp_request) if text_signals else 0.0,
        sensitive_info=float(text_signals.sensitive_info_request) if text_signals else 0.0,
        suspicious_instructions=float(text_signals.suspicious_instructions) if text_signals else 0.0,
        consistency=float(correlation.get("consistency_score", 1.0)),
        evidence_count=len(evidence),
        high_severity_count=high_severity,
        distinct_sources=distinct_sources,
        live_ml=live_ml,
        live_intel=live_intel,
        has_text=has_text,
        has_url=has_url,
        intel_informative=intel_informative,
        url_anchor=url_anchor,
        details={
            "pattern_score": pattern_score,
            "url_risk": url_risk,
            "threat_intel_score": threat_score,
            "impersonation": impersonation,
        },
    )
    risk = compute_risk(inputs)

    # finalize the correlation conclusion now that the risk level is known
    correlation = dict(correlation)
    from app.risk.correlation import build_conclusion

    classification = state.get("classification")
    primary = getattr(classification, "primary", "unknown") if classification else "unknown"
    correlation["conclusion"] = build_conclusion(
        correlation.get("corroborating", []),
        risk.level,
        primary,
        evidence_sufficiency=risk.evidence_sufficiency,
    )
    return state_update(state, risk=risk, correlation=correlation)
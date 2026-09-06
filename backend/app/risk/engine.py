"""Deterministic risk aggregation.

The risk score is computed from structured component scores with
configurable weights — NOT from the LLM's opinion.  Every contributor is
recorded so the report can explain the score.

Calibration notes
-----------------
* ``confidence`` depends on how much *independent* evidence exists
  (volume, source diversity, severity, corroboration, live providers), so
  sparse evidence can never report a high confidence.
* ``evidence_sufficiency`` labels the assessment INSUFFICIENT / PARTIAL /
  SUFFICIENT so a LOW score from "not much evidence" is distinguishable
  from a LOW score backed by many clean signals.
* Scores are normalized over the weights of the evidence channels that
  were actually *applicable* to the submission, not the full weight table:
  URL/intel weights are only in the denominator when a URL was analyzed
  (and intel only when it produced an informative verdict), and text/ML
  weights only when text was present.  This keeps a strong text-only scam
  from being diluted by URL channels that could never fire, and lets a
  strong URL-only submission reach HIGH without an ad-hoc score bump.
* **URL-anchored normalization.**  When strong URL-level evidence exists
  (URL-anchored evidence), *silent* channels — channels whose score is
  below ``CHANNEL_SILENT_MAX`` because the content simply carried no
  signal there — no longer count their weight in the normalization
  denominator.  A brand-lookalike / credential-harvesting URL is therefore
  not diluted by neutral surrounding text: evidence quality wins over
  evidence quantity.  A benign official URL never anchors (its URL score
  is low and no provider flags it), so neutral or genuinely benign text
  next to an official URL is still scored on its own text evidence and
  stays LOW.  The anchor is decided by the caller from structured
  evidence (URL structural risk >= ``URL_ANCHOR_MIN`` or a provider
  verdict of suspicious/malicious) — it is generic, not domain- or
  test-specific.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from app.core.config import get_settings
from app.schemas.risk import RiskAssessment, RiskContributor

logger = logging.getLogger("scaminvestigator.risk")

DEFAULT_WEIGHTS: dict[str, float] = {
    # Pattern rules are hand-vetted and the most precise deterministic
    # channel.  The bundled ML model is trained on a synthetic corpus and
    # has shown it over-trusts surface keywords on benign messages, so it
    # deliberately carries the smallest weight of the deterministic
    # channels.  ``suspicious_instructions`` (remote access, gift-card
    # purchases, disabling security) is a high-precision request channel.
    "ml_score": 0.10,
    "url_risk": 0.18,
    "threat_intel": 0.25,
    "pattern_score": 0.35,
    "entity_impersonation": 0.08,
    "urgency": 0.07,
    "payment_request": 0.10,
    "credential_request": 0.12,
    "otp_request": 0.12,
    "sensitive_info": 0.07,
    "suspicious_instructions": 0.08,
    "consistency": 0.05,
}

LEVELS = [("CRITICAL", 75.0), ("HIGH", 50.0), ("MEDIUM", 25.0), ("LOW", 0.0)]

INSUFFICIENT_MAX = 0.35
SUFFICIENT_MIN = 0.60

# URL structural risk at/above which the URL evidence is treated as an
# anchor (aligned with the "strong URL" definition used elsewhere: the
# url_analysis severity mapping and the URL-derived classification both use
# 0.4 as the strong-URL boundary).
URL_ANCHOR_MIN = 0.4
# A channel whose score is below this threshold carried no meaningful
# evidence and must not dilute an anchored assessment.
CHANNEL_SILENT_MAX = 0.2


@dataclass
class RiskInputs:
    ml_score: float = 0.0
    url_risk: float = 0.0
    threat_intel_score: float = 0.0
    pattern_score: float = 0.0
    entity_impersonation: float = 0.0  # 0..1
    urgency: float = 0.0
    payment_request: float = 0.0
    credential_request: float = 0.0
    otp_request: float = 0.0
    sensitive_info: float = 0.0
    suspicious_instructions: float = 0.0
    consistency: float = 1.0  # 0..1
    evidence_count: int = 0
    high_severity_count: int = 0
    distinct_sources: int = 0  # independent evidence producers (url/text/ml/intel/…)
    live_ml: bool = False  # a trained model produced the ML score
    live_intel: bool = False  # a real (non-mock) intel provider was consulted
    # --- channel applicability (default True keeps plain unit calls stable) ---
    has_text: bool = True  # textual evidence was present (message and/or OCR)
    has_url: bool = True  # a URL was analyzed
    intel_informative: bool = True  # intel returned an informative verdict (safe/suspicious/malicious, status ok)
    # URL-anchored evidence: at least one URL has strong structural risk or
    # an intel provider returned suspicious/malicious.  When True, silent
    # channels (score < CHANNEL_SILENT_MAX) stop diluting the denominator.
    url_anchor: bool = False
    details: dict = field(default_factory=dict)


def _load_weights() -> dict[str, float]:
    settings = get_settings()
    path = settings.risk_weights_path
    if path and path.exists():
        try:
            data = json.loads(path.read_text())
            merged = dict(DEFAULT_WEIGHTS)
            merged.update(data)
            return merged
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to load risk weights %s: %s", path, exc)
    return dict(DEFAULT_WEIGHTS)


def sufficiency_score(inputs: RiskInputs) -> float:
    """0..1 measure of how much independent evidence supports the verdict."""
    volume = min(1.0, inputs.evidence_count / 6.0)
    diversity = min(1.0, inputs.distinct_sources / 5.0)
    severity = min(1.0, inputs.high_severity_count / 2.0)
    corroboration = max(0.0, min(1.0, inputs.consistency))
    providers = 0.5 * (1.0 if inputs.live_ml else 0.0) + 0.5 * (1.0 if inputs.live_intel else 0.0)

    score = 0.30 * volume + 0.25 * diversity + 0.20 * severity
    score += 0.15 * corroboration + 0.10 * providers
    return max(0.0, min(1.0, score))


def sufficiency_label(score: float) -> str:
    if score < INSUFFICIENT_MAX:
        return "INSUFFICIENT"
    if score < SUFFICIENT_MIN:
        return "PARTIAL"
    return "SUFFICIENT"


def _is_anchored_url_evidence(inputs: RiskInputs) -> bool:
    """Whether the caller has identified strong URL-level evidence.

    The anchor is generic by construction: it is derived from the URL
    structural risk threshold (``URL_ANCHOR_MIN``) or an intel verdict of
    suspicious/malicious — never from specific domains or test cases.
    """
    return inputs.url_anchor and inputs.has_url


def compute_risk(inputs: RiskInputs) -> RiskAssessment:
    """Aggregate component scores into a 0..100 risk assessment.

    Only the weights of *applicable* evidence channels take part in the
    normalization (see module docstring), so the score is not diluted by
    channels the input type could never exercise.  When the assessment is
    URL-anchored, channels that are applicable but *silent* (score below
    ``CHANNEL_SILENT_MAX``) additionally drop out of the denominator so
    neutral text cannot dilute strong URL evidence.
    """
    weights = _load_weights()
    components: dict[str, float] = {
        "ml_score": inputs.ml_score,
        "url_risk": inputs.url_risk,
        "threat_intel": inputs.threat_intel_score,
        "pattern_score": inputs.pattern_score,
        "entity_impersonation": inputs.entity_impersonation,
        "urgency": inputs.urgency,
        "payment_request": inputs.payment_request,
        "credential_request": inputs.credential_request,
        "otp_request": inputs.otp_request,
        "sensitive_info": inputs.sensitive_info,
        "suspicious_instructions": inputs.suspicious_instructions,
        "consistency": inputs.consistency,
    }

    def applicable(key: str) -> bool:
        if key == "consistency":
            return True
        if key in ("url_risk",):
            return inputs.has_url
        if key == "threat_intel":
            return inputs.has_url and inputs.intel_informative
        if key == "entity_impersonation":
            return inputs.has_text
        # ml + text-driven channels need textual evidence
        return inputs.has_text

    anchored = _is_anchored_url_evidence(inputs)

    def participates(key: str) -> bool:
        """A channel's weight counts in the normalization denominator."""
        if not applicable(key):
            return False
        if not anchored:
            return True
        if key == "consistency":
            return True
        # Anchored mode prefers evidence quality over quantity: a channel
        # that returned no meaningful evidence (score below the silent
        # threshold) neither contributes to the numerator nor dilutes the
        # denominator.
        return max(0.0, min(1.0, components[key])) >= CHANNEL_SILENT_MAX

    total_weight = sum(weights.get(k, 0.0) for k in components if participates(k))
    score = 0.0
    for key, value in components.items():
        if not participates(key):
            continue
        w = weights.get(key, 0.0)
        if key == "consistency":
            # higher consistency corroborates risk; low consistency dampens it
            contribution = w * (value - 0.5) * 2.0 * (score / 100.0 if score else 0.0)
        else:
            contribution = w * max(0.0, min(1.0, value))
        score += contribution
    # normalize by participating weight so weights act as relative importance
    score = (score / total_weight) * 100.0 if total_weight else 0.0

    level = "LOW"
    for name, threshold in LEVELS:
        if score >= threshold:
            level = name
            break

    sufficiency = sufficiency_score(inputs)
    confidence = round(max(0.0, min(0.97, 0.2 + 0.8 * sufficiency)), 2)

    contributors = _contributors(components, inputs)

    return RiskAssessment(
        score=round(score, 1),
        level=level,
        confidence=confidence,
        contributors=contributors,
        weights=weights,
        method="deterministic_weighted",
        evidence_sufficiency=sufficiency_label(sufficiency),
    )


def _contributors(components: dict[str, float], inputs: RiskInputs) -> list[RiskContributor]:
    labels = {
        "ml_score": "Machine-learning probability",
        "url_risk": "URL structural risk",
        "threat_intel": "Threat intelligence",
        "pattern_score": "Scam-pattern match",
        "entity_impersonation": "Brand impersonation indicators",
        "urgency": "Urgency/fear language",
        "payment_request": "Payment request",
        "credential_request": "Credential request",
        "otp_request": "OTP request",
        "sensitive_info": "Sensitive-information request",
        "suspicious_instructions": "Suspicious instructions (remote access / gift cards)",
    }
    out: list[RiskContributor] = []
    for key, label in labels.items():
        value = components.get(key, 0.0)
        if value >= 0.2:
            raw_detail = inputs.details.get(key)
            detail = raw_detail if isinstance(raw_detail, str) else None
            out.append(
                RiskContributor(
                    name=label,
                    impact=round(value * 2.0 - 1.0, 3),  # -1..1 scale
                    detail=detail,
                    evidence_sources=_sources_for(key),
                )
            )
    if not out and inputs.evidence_count == 0:
        out.append(RiskContributor(name="Evidence volume", impact=0.0, detail="Insufficient evidence"))
    return out


def _sources_for(key: str) -> list[str]:
    mapping = {
        "ml_score": ["ml_classifier"],
        "url_risk": ["url_analysis"],
        "threat_intel": ["threat_intelligence"],
        "pattern_score": ["scam_pattern"],
        "entity_impersonation": ["entity_analysis"],
        "urgency": ["text_analysis"],
        "payment_request": ["text_analysis"],
        "credential_request": ["text_analysis"],
        "otp_request": ["text_analysis"],
        "sensitive_info": ["text_analysis"],
        "suspicious_instructions": ["text_analysis"],
    }
    return mapping.get(key, ["text_analysis"])

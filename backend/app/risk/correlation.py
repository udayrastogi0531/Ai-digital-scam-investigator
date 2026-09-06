"""Evidence correlation.

Combines signals from different sources into themes, checks consistency
(do the sources agree?), and produces the narrative bridge between raw
signals and the final conclusion.  This runs *before* the LLM so the
explanation agent can reference pre-correlated facts instead of guessing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas.analysis import ThreatIntelResult
from app.schemas.evidence import EvidenceSignal

_THEME_BY_SOURCE: dict[str, str] = {
    "url_analysis": "url_risk",
    "threat_intelligence": "external_reputation",
    "scam_pattern": "scam_pattern",
    "text_analysis": "language_signals",
    "entity_analysis": "brand_impersonation",
    "ml_classifier": "ml_prediction",
}


@dataclass
class CorrelationResult:
    themes: dict[str, list[EvidenceSignal]] = field(default_factory=dict)
    corroborating: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    consistency_score: float = 1.0
    conclusion: str = "Insufficient evidence to draw a conclusion."
    evidence: list[EvidenceSignal] = field(default_factory=list)


def _theme_for(signal: EvidenceSignal) -> str:
    return _THEME_BY_SOURCE.get(signal.source, signal.source)


def correlate_evidence(
    signals: list[EvidenceSignal],
    threat_intel: list[ThreatIntelResult] | None = None,
    *,
    risk_level: str | None = None,
    classification_primary: str | None = None,
) -> CorrelationResult:
    """Deduplicate, group and score the consistency of evidence signals."""
    # dedupe by (source, signal)
    seen: set[tuple[str, str]] = set()
    unique: list[EvidenceSignal] = []
    for s in signals:
        key = (s.source, s.signal)
        if key in seen:
            continue
        seen.add(key)
        unique.append(s)

    themes: dict[str, list[EvidenceSignal]] = {}
    for s in unique:
        themes.setdefault(_theme_for(s), []).append(s)

    corroborating: list[str] = []
    for theme, items in themes.items():
        worst = max(items, key=lambda e: _SEV.get(e.severity, 1))
        if _SEV.get(worst.severity, 1) >= 2:
            corroborating.append(_theme_label(theme))

    conflicts: list[str] = []
    consistency = 1.0
    if threat_intel:
        verdicts = [t.verdict for t in threat_intel if t.verdict != "unknown"]
        if verdicts and all(v == "safe" for v in verdicts) and corroborating:
            conflicts.append("Threat intelligence reports the URL as safe while local signals are suspicious.")
            consistency -= 0.2
    if not corroborating:
        consistency = 0.4  # single-sourced or weak evidence
    elif len(corroborating) >= 3:
        consistency = 1.0
    elif len(corroborating) == 2:
        consistency = 0.9
    else:
        consistency = 0.75
    consistency = max(0.0, min(1.0, consistency))

    if risk_level is None:
        conclusion = (
            f"Evidence correlated: {len(corroborating)} corroborating theme(s) "
            + (", ".join(corroborating[:3]) if corroborating else "no corroborating themes") + "."
        )
    else:
        conclusion = _build_conclusion(corroborating, risk_level, classification_primary or "unknown")

    return CorrelationResult(
        themes=themes,
        corroborating=corroborating,
        conflicts=conflicts,
        consistency_score=round(consistency, 2),
        conclusion=conclusion,
        evidence=unique,
    )


# Evidence-sufficiency labels used to phrase LOW conclusions honestly.
_INSUFFICIENT_SUFFICIENCY = {"INSUFFICIENT", "PARTIAL"}


_SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _theme_label(theme: str) -> str:
    labels = {
        "url_risk": "Suspicious URL structure",
        "external_reputation": "External reputation flags",
        "scam_pattern": "Known scam patterns",
        "language_signals": "Urgency / pressure / request language",
        "brand_impersonation": "Brand impersonation indicators",
        "ml_prediction": "Machine-learning prediction",
    }
    return labels.get(theme, theme.replace("_", " ").title())


def build_conclusion(
    corroborating: list[str],
    risk_level: str,
    classification_primary: str,
    evidence_sufficiency: str | None = None,
) -> str:
    return _build_conclusion(
        corroborating, risk_level, classification_primary, evidence_sufficiency
    )


def _build_conclusion(
    corroborating: list[str],
    risk_level: str,
    classification_primary: str,
    evidence_sufficiency: str | None = None,
) -> str:
    """Deterministic conclusion text.

    LOW must never read as a verified "safe".  When the evidence is
    insufficient/partial the conclusion says the LOW score reflects the
    absence of scam indicators *in the little evidence provided*, not a
    clean bill of health.
    """
    if risk_level == "LOW":
        if evidence_sufficiency in _INSUFFICIENT_SUFFICIENCY:
            return (
                "The submission contained too little evidence for a confident assessment. "
                "No scam indicators were found in what was provided, but this is not a "
                "verified clean result — more context would be needed to rule a scam out."
            )
        return "No significant scam indicators were found across the checked evidence."
    if not corroborating:
        return "Some risk signals were detected but the evidence is insufficient for a confident conclusion."
    base = "corroborating evidence from "
    base += ", ".join(corroborating[:3])
    if len(corroborating) > 3:
        base += f" and {len(corroborating) - 3} more"
    from app.patterns.rules import CATEGORY_LABELS

    label = CATEGORY_LABELS.get(classification_primary, classification_primary)
    return (
        f"{risk_level} probability of a scam — {label} pattern supported by {base}. "
        "No single signal is conclusive; the risk is based on the combined weight of evidence."
    )
"""Text-analysis node.

Produces structured linguistic signals, matches scam patterns against the
rule engine and emits the initial (rules-based) classification.
"""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.analysis.text_signals import analyze_text_signals
from app.graph.state import InvestigationState
from app.patterns.engine import classify, matches_to_signals
from app.schemas.evidence import EvidenceSignal


@timed_node("analyze")
def text_analysis_node(state: InvestigationState) -> InvestigationState:
    text = state.get("normalized_text", "")
    entities = state.get("entities")
    text_signals = analyze_text_signals(text)
    classification, matches = classify(text, entities, text_signals)

    pattern_signals = matches_to_signals(matches)
    pattern_weight_sum = sum(m.rule.weight for m in matches)

    language_evidence: list[EvidenceSignal] = []
    if text_signals.urgency_score >= 0.5:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="urgency_language",
                severity="medium",
                confidence=text_signals.urgency_score,
                description=f"Strong urgency language detected ({len(text_signals.urgent_phrases)} phrase(s)).",
                detail={"phrases": text_signals.urgent_phrases},
            )
        )
    if text_signals.fear_threat_score >= 0.5:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="fear_threat_language",
                severity="high",
                confidence=text_signals.fear_threat_score,
                description="Threat or fear-inducing language detected (account closure, suspension, legal action…).",
                detail={"phrases": text_signals.threat_phrases},
            )
        )
    if text_signals.payment_request:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="payment_request",
                severity="high",
                confidence=0.8,
                description="The message requests a payment or transfer.",
                detail={"phrases": text_signals.payment_phrases},
            )
        )
    if text_signals.credential_request:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="credential_request",
                severity="high",
                confidence=0.8,
                description="The message asks for login credentials or account verification.",
                detail={"phrases": text_signals.credential_phrases},
            )
        )
    if text_signals.otp_request:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="otp_request",
                severity="critical",
                confidence=0.9,
                description="The message asks for a one-time password / verification code.",
            )
        )
    if text_signals.sensitive_info_request:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="sensitive_info_request",
                severity="high",
                confidence=0.75,
                description="The message requests sensitive personal or financial information.",
            )
        )
    if text_signals.suspicious_instructions:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="suspicious_instructions",
                severity="high",
                confidence=0.7,
                description="The message contains suspicious instructions (remote access, gift cards, disabling security…).",
            )
        )
    if text_signals.reward_score >= 0.5:
        language_evidence.append(
            EvidenceSignal(
                source="text_analysis",
                signal="reward_language",
                severity="medium",
                confidence=text_signals.reward_score,
                description="Reward or prize language detected.",
                detail={"phrases": text_signals.reward_phrases},
            )
        )

    return state_update(
        state,
        text_signals=text_signals,
        classification=classification,
        scam_patterns=pattern_signals,
        pattern_matches=[
            {
                "id": m.rule.id,
                "category": m.rule.category,
                "name": m.rule.name,
                "severity": m.rule.severity,
                "weight": m.rule.weight,
                "keywords": m.matched_keywords,
            }
            for m in matches
        ],
        evidence=[*pattern_signals, *language_evidence],
    )
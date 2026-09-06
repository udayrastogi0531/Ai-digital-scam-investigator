"""Deterministic evidence-based explanation/report generation.

Used by the mock LLM provider and as the controlled fallback when a real
LLM fails or returns invalid output.  Everything produced here is derived
strictly from the structured evidence in the context — nothing is
invented, and the output is explicitly labelled as not-LLM-generated when
appropriate.
"""
from __future__ import annotations

from app.patterns.rules import CATEGORY_LABELS
from app.schemas.llm import ExplanationResult, ReportContext
from app.schemas.report import InvestigationReport, ReportSection

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _top_signals(context: ReportContext, limit: int = 5) -> list:
    signals = sorted(
        context.evidence, key=lambda e: (_SEVERITY_RANK.get(e.severity, 1), e.confidence), reverse=True
    )
    return signals[:limit]


def _objectives(context: ReportContext) -> tuple[str | None, str]:
    ts = context.text_signals
    objectives: list[tuple[str, int]] = []
    if ts.otp_request or ts.credential_request:
        objectives.append(("credential theft", 3))
    if ts.payment_request or any(e.signal == "payment_upfront_fee" for e in context.evidence):
        objectives.append(("financial fraud", 3))
    if ts.sensitive_info_request or any(e.signal.startswith("identity_") for e in context.evidence):
        objectives.append(("identity theft", 2))
    if any(e.signal.startswith("account_") for e in context.evidence):
        objectives.append(("account takeover", 2))
    if any(e.signal.startswith("techsupport_") for e in context.evidence):
        objectives.append(("malware delivery / remote access", 3))
    if any(e.signal.startswith("lottery_") or e.signal.startswith("romance_") for e in context.evidence):
        objectives.append(("advance-fee fraud", 2))
    if not objectives:
        return None, "low"
    objectives.sort(key=lambda kv: kv[1], reverse=True)
    top = objectives[0][0]
    confidence = "high" if objectives[0][1] >= 3 else "medium"
    return top, confidence


def _recommendations(context: ReportContext) -> list[str]:
    recs: list[str] = []
    ts = context.text_signals
    risky_urls = any(u.risk_score >= 0.4 for u in context.urls) or any(
        t.verdict in ("suspicious", "malicious") for t in context.threat_intel
    )
    if risky_urls:
        recs.append("Do not click the link or open the attachment; treat it as potentially malicious.")
    if ts.payment_request:
        recs.append("Do not make any payment or transfer. Legitimate organizations do not demand urgent payments by message.")
    if ts.otp_request:
        recs.append("Never share OTP / one-time passcodes with anyone, including callers claiming to be support.")
    if ts.credential_request:
        recs.append("Do not enter or share your passwords, usernames or login details.")
    if ts.sensitive_info_request:
        recs.append("Do not send identity documents, bank details or personal identifiers.")
    if any(e.signal.startswith("techsupport_") for e in context.evidence):
        recs.append("Do not install remote-access software or follow 'run this command' instructions.")
    if context.entities and (context.entities.banks or context.entities.companies):
        recs.append("Verify the claim by contacting the organization through its official website or phone number — never via the contact details in the message.")
    if context.risk and context.risk.score >= 60:
        recs.append("Report the message to your email provider / messaging platform and, if relevant, to local fraud authorities.")
    if not recs:
        recs.append("No urgent action required based on the available evidence. When in doubt, verify through official channels.")
    return recs


def deterministic_explain(context: ReportContext) -> ExplanationResult:
    """Build an explanation strictly from structured evidence."""
    risk = context.risk
    classification = context.classification
    top = _top_signals(context)
    objective, obj_conf = _objectives(context)

    lines: list[str] = []
    if risk is None:
        lines.append("Risk could not be fully assessed due to missing evidence.")
    else:
        if risk.level == "LOW":
            # Low risk must never read as a verified "safe".  With little or
            # no evidence it explicitly says the score reflects the absence
            # of scam indicators in the *provided* evidence only.
            if risk.evidence_sufficiency in ("INSUFFICIENT", "PARTIAL"):
                lines.append(
                    "Insufficient evidence was provided for a confident assessment. "
                    "The low risk score reflects the absence of scam indicators in the "
                    "limited evidence submitted — it is not a verified safe/clean result."
                )
            else:
                lines.append(
                    "Low risk based on the available evidence: no significant scam "
                    "indicators were detected across the checked signals."
                )
        else:
            lines.append(
                f"The evidence indicates a {risk.level} probability that this is a scam "
                f"(risk score {risk.score:.0f}/100, confidence {risk.confidence * 100:.0f}%)."
            )
    if classification and classification.primary != "unknown":
        label = CATEGORY_LABELS.get(classification.primary, classification.primary)
        lines.append(
            f"The strongest matching scam pattern is '{label}' (rule-engine confidence "
            f"{classification.confidence * 100:.0f}%)."
        )
    if top:
        descriptions = "; ".join(f"{e.description or e.signal} ({e.severity})" for e in top[:4])
        lines.append(f"Key supporting evidence: {descriptions}.")
    if context.ml and context.ml.is_mock is False:
        lines.append(
            f"The machine-learning model estimates a {context.ml.probability_scam * 100:.0f}% "
            f"probability of scam-related content."
        )
    elif context.ml and context.ml.is_mock:
        lines.append(
            f"A heuristic estimate (no trained model available) suggests "
            f"{context.ml.probability_scam * 100:.0f}% probability of scam-related content."
        )
    summary = " ".join(lines)

    return ExplanationResult(
        summary=summary,
        likely_objective=objective,
        objective_confidence=obj_conf,
        limitations=_limitations(context),
        provider="deterministic",
        is_mock=True,
    )


def _limitations(context: ReportContext) -> str:
    parts: list[str] = []
    if any(t.is_mock for t in context.threat_intel) or not context.threat_intel:
        parts.append("no external threat-intelligence feed was consulted (demo mode)")
    if context.ml and context.ml.is_mock:
        parts.append("ML estimate is heuristic; no trained model available")
    if context.risk and context.risk.confidence < 0.5:
        parts.append("risk confidence is limited by sparse evidence")
    if context.urls and not context.threat_intel:
        parts.append("URL reputation could not be verified externally")
    if not parts:
        parts.append("reputation of the sender/domain could not be independently verified")
    return "Limitations: " + "; ".join(parts)


def deterministic_report(context: ReportContext) -> InvestigationReport:
    """Build the full structured report from evidence."""
    explanation = deterministic_explain(context)
    classification = context.classification
    risk = context.risk

    suspicious = []
    for e in sorted(
        context.evidence, key=lambda e: (_SEVERITY_RANK.get(e.severity, 1), e.confidence), reverse=True
    ):
        suspicious.append(
            {
                "indicator": e.description or e.signal,
                "evidence": e.signal,
                "severity": e.severity,
                "confidence": e.confidence,
            }
        )

    timeline_items = context.timeline or [
        {"stage": "input_received", "label": "Evidence submitted"},
        {"stage": "extraction", "label": "Entities and URLs extracted"},
        {"stage": "analysis", "label": "Pattern, URL, ML and intelligence analysis"},
        {"stage": "correlation", "label": "Evidence correlated"},
        {"stage": "risk", "label": "Risk assessed"},
        {"stage": "report", "label": "Report generated"},
    ]

    sections = [
        ReportSection(
            title="Summary",
            content=explanation.summary,
            kind="paragraph",
        ),
        ReportSection(
            title="How the conclusion was reached",
            content="The pipeline extracted structured evidence from the submission, matched known scam "
            "patterns, analyzed URLs deterministically, ran the machine-learning classifier and "
            "queried available threat-intelligence providers. Each finding was stored as a structured "
            "signal and aggregated by the deterministic risk engine. No conclusion rests on a single "
            "heuristic.",
            kind="paragraph",
        ),
        ReportSection(
            title="Investigation timeline",
            content="\n".join(f"{i + 1}. {t.get('label', t.get('stage', 'step'))}" for i, t in enumerate(timeline_items)),
            kind="list",
        ),
    ]
    if suspicious:
        sections.append(
            ReportSection(
                title="Suspicious indicators",
                content="\n".join(
                    f"- {s['indicator']} (severity {s['severity']}, confidence {s['confidence']:.0%})"
                    for s in suspicious[:8]
                ),
                kind="list",
            )
        )
    if risk and risk.level != "LOW":
        sections.append(
            ReportSection(
                title="Recommended actions",
                content="\n".join(f"- {r}" for r in explanation_like_recommendations(context)),
                kind="list",
            )
        )

    return InvestigationReport(
        summary=explanation.summary,
        likely_objective=explanation.likely_objective,
        objective_confidence=explanation.objective_confidence,
        recommendations=explanation_like_recommendations(context),
        suspicious_indicators=suspicious,
        limitations=explanation.limitations,
        sections=sections,
        provider="deterministic",
    )


def explanation_like_recommendations(context: ReportContext) -> list[str]:
    return _recommendations(context)
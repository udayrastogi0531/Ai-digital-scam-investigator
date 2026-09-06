"""URL-analysis node: deterministic per-URL structural analysis."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.extraction.url_analysis import analyze_url
from app.graph.state import InvestigationState
from app.schemas.evidence import EvidenceSignal


@timed_node("url_analysis")
def url_analysis_node(state: InvestigationState) -> InvestigationState:
    entities = state.get("entities")
    url_values = [e.value for e in (entities.urls if entities else [])]
    if not url_values:
        url_values = list(state.get("explicit_urls") or [])

    analyses = [analyze_url(u) for u in url_values]
    signals: list[EvidenceSignal] = []
    for analysis in analyses:
        severity = "critical" if analysis.risk_score >= 0.7 else "high" if analysis.risk_score >= 0.4 else "low" if analysis.risk_score < 0.15 else "medium"
        description = (
            f"URL {analysis.hostname} shows structural risk {analysis.risk_score:.0%}: "
            + (", ".join(analysis.signals) if analysis.signals else "no notable structural signals")
        )
        signals.append(
            EvidenceSignal(
                source="url_analysis",
                signal="url_risk" if analysis.risk_score >= 0.4 else "url_checked",
                severity=severity,
                confidence=min(0.95, 0.4 + analysis.risk_score),
                description=description,
                detail={
                    "url": analysis.url,
                    "domain": analysis.domain,
                    "risk_score": analysis.risk_score,
                    "signals": analysis.signals,
                },
            )
        )

    return state_update(state, urls=analyses, url_signals=signals, evidence=signals)
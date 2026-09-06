"""Evidence-correlation node: group signals, check consistency, summarize."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.graph.state import InvestigationState
from app.risk.correlation import CorrelationResult, correlate_evidence


@timed_node("correlate")
def correlation_node(state: InvestigationState) -> InvestigationState:
    signals = list(state.get("evidence") or [])

    result: CorrelationResult = correlate_evidence(
        signals,
        state.get("threat_intel"),
        risk_level=None,
        classification_primary=None,
    )

    return state_update(
        state,
        correlation={
            "themes": {k: [s.model_dump() for s in v] for k, v in result.themes.items()},
            "corroborating": result.corroborating,
            "conflicts": result.conflicts,
            "consistency_score": result.consistency_score,
            "conclusion": result.conclusion,
        },
    )
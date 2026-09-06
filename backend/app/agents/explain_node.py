"""Explanation node: LLM synthesizes evidence into a human-readable verdict.

The LLM only ever sees the structured evidence in the context — it cannot
invent external facts (enforced by the evidence-only prompt contract).
"""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.graph.state import InvestigationState
from app.llm import get_llm_provider
from app.schemas.llm import ReportContext


def build_context(state: InvestigationState) -> ReportContext:
    return ReportContext(
        investigation_id=state.get("investigation_id", "unknown"),
        input_types=state.get("input_types") or [],
        text_preview=(state.get("normalized_text") or "")[:2000],
        entities=state.get("entities"),
        urls=state.get("urls") or [],
        text_signals=state.get("text_signals"),
        pattern_signals=state.get("scam_patterns") or [],
        threat_intel=state.get("threat_intel") or [],
        ml=state.get("ml_prediction"),
        entity_analysis=state.get("entity_analysis"),
        classification=state.get("classification"),
        risk=state.get("risk"),
        evidence=state.get("evidence") or [],
        timeline=state.get("timeline") or [],
    )


@timed_node("explain")
async def explain_node(state: InvestigationState) -> InvestigationState:
    context = build_context(state)
    provider = get_llm_provider()
    explanation = await provider.explain(context)
    return state_update(state, explanation=explanation)
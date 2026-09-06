"""Report node: generate the final structured investigation report."""
from __future__ import annotations

from app.agents.common import state_update, timed_node
from app.agents.explain_node import build_context
from app.graph.state import InvestigationState
from app.llm import get_llm_provider


@timed_node("report")
async def report_node(state: InvestigationState) -> InvestigationState:
    context = build_context(state)
    provider = get_llm_provider()
    report = await provider.generate_report(context)
    return state_update(state, report=report, status="completed")
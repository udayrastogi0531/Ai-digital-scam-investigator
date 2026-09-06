"""LangGraph workflow builder.

Flow::

    START ─┬─ (image?) → ocr ─┐
           └─ (no image) ─────┴─> parse -> analyze -> route (conditional fan-out)
      ├─ url_analysis -> threat_intel_lookup ─┐
      ├─ brand_analysis -> brand_pad ─────────┼─> correlate -> assess_risk
      └─ ml_node -> ml_pad ───────────────────┘       -> explain -> generate_report -> END

Only the specialized branches that are actually needed run:
* ocr only when a screenshot was uploaded
* url_analysis + threat_intel_lookup only when URLs exist
* brand_analysis only when known organizations are mentioned
* ml always

The ``*_pad`` nodes are zero-op hops that give every active branch exactly
two supersteps before the merge.  langgraph 0.2.x mis-schedules nodes that
merge branches of *unequal* depth (the merged node and its downstream run
twice), so equalizing branch depth keeps execution deterministic.

Node names deliberately avoid colliding with state keys (LangGraph forbids a
node registered with the same name as a channel).
"""
from __future__ import annotations

import logging
from typing import Literal

from langgraph.graph import END, START, StateGraph

from app.agents.classify_node import classify_refine_node
from app.agents.correlation_node import correlation_node
from app.agents.entity_analysis_node import entity_analysis_node
from app.agents.explain_node import explain_node
from app.agents.ml_node import ml_node
from app.agents.ocr_node import ocr_node
from app.agents.parser_node import parse_node
from app.agents.report_node import report_node
from app.agents.risk_node import risk_node
from app.agents.text_analysis_node import text_analysis_node
from app.agents.threat_intel_node import threat_intel_node
from app.agents.url_analysis_node import url_analysis_node
from app.graph.state import InvestigationState
from app.patterns.engine import is_ambiguous

logger = logging.getLogger("scaminvestigator.graph")


def _needs_ocr(state: InvestigationState) -> Literal["ocr", "parse"]:
    raw = state.get("raw_inputs") or {}
    return "ocr" if raw.get("image_bytes") else "parse"


def _route(state: InvestigationState) -> list[str]:
    """Decide which specialized branches to run after text analysis."""
    next_nodes: list[str] = []
    entities = state.get("entities")
    urls = [u.value for u in (entities.urls if entities else [])] or state.get("explicit_urls")
    if urls:
        next_nodes.append("url_analysis")
    if entities and (entities.companies or entities.banks or entities.organizations):
        next_nodes.append("brand_analysis")
    next_nodes.append("ml_node")
    # LLM refinement runs only when the rules classification is ambiguous.
    if is_ambiguous(state.get("classification")):
        next_nodes.append("classify_refine")
    return next_nodes


def build_graph():
    builder = StateGraph(InvestigationState)

    builder.add_node("ocr", ocr_node)
    builder.add_node("parse", parse_node)
    builder.add_node("analyze", text_analysis_node)
    builder.add_node("url_analysis", url_analysis_node)
    builder.add_node("threat_intel_lookup", threat_intel_node)

    builder.add_node("brand_analysis", entity_analysis_node)
    builder.add_node("brand_pad", lambda state: {})
    builder.add_node("ml_node", ml_node)
    builder.add_node("ml_pad", lambda state: {})
    builder.add_node("classify_refine", classify_refine_node)
    builder.add_node("classify_pad", lambda state: {})
    builder.add_node("correlate", correlation_node)
    builder.add_node("assess_risk", risk_node)
    builder.add_node("explain", explain_node)
    builder.add_node("generate_report", report_node)

    # OCR only runs when a screenshot was actually uploaded.
    builder.add_conditional_edges(START, _needs_ocr, {"ocr": "ocr", "parse": "parse"})
    builder.add_edge("ocr", "parse")
    builder.add_edge("parse", "analyze")
    builder.add_conditional_edges("analyze", _route)
    builder.add_edge("url_analysis", "threat_intel_lookup")
    # Every branch is exactly two hops long, so all active branches arrive at
    # correlate in the same superstep (see module docstring for why).
    builder.add_edge("threat_intel_lookup", "correlate")
    builder.add_edge("brand_analysis", "brand_pad")
    builder.add_edge("brand_pad", "correlate")
    builder.add_edge("ml_node", "ml_pad")
    builder.add_edge("ml_pad", "correlate")
    builder.add_edge("classify_refine", "classify_pad")
    builder.add_edge("classify_pad", "correlate")
    builder.add_edge("correlate", "assess_risk")
    builder.add_edge("assess_risk", "explain")
    builder.add_edge("explain", "generate_report")
    builder.add_edge("generate_report", END)

    return builder.compile()


_graph = None


def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


async def run_investigation(state: InvestigationState) -> InvestigationState:
    """Execute the full investigation workflow for a prepared state."""
    graph = get_graph()
    try:
        result = await graph.ainvoke(state)
    except Exception as exc:  # noqa: BLE001
        logger.exception("investigation workflow failed")
        result = dict(state)
        result["status"] = "failed"
        result["errors"] = list(state.get("errors") or []) + [f"workflow failed: {exc}"]
        result["timeline"] = list(state.get("timeline") or [])
    else:
        result["status"] = "completed"
        timeline = list(result.get("timeline") or [])
        # Deterministic ordering + dedupe (a stage runs at most once per
        # investigation; guards against scheduler edge cases).
        timeline.sort(key=lambda t: str(t.get("at", "")))
        seen: set[str] = set()
        unique: list[dict] = []
        for entry in timeline:
            stage = entry.get("stage", "")
            if stage in seen:
                continue
            seen.add(stage)
            unique.append(entry)
        result["timeline"] = unique
    return result

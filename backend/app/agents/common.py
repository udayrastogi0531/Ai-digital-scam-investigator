"""Shared helpers for graph nodes: timing, timeline entries, error capture."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

from app.graph.state import InvestigationState

_TIMELINE_LABELS: dict[str, str] = {
    "parse": "Evidence parsed and normalized",
    "ocr": "Screenshot OCR",
    "analyze": "Text signals & scam patterns",
    "url_analysis": "URL analysis",
    "llm_classify": "LLM classification refinement",
    "entity_analysis": "Entity / brand analysis",
    "threat_intel": "Threat intelligence lookup",
    "ml": "Machine-learning prediction",
    "correlate": "Evidence correlation",
    "risk": "Risk assessment",
    "explain": "AI explanation",
    "report": "Report generation",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def node_timeline(stage: str) -> dict[str, Any]:
    return {"stage": stage, "label": _TIMELINE_LABELS.get(stage, stage.replace("_", " ").title())}


def _annotate_result(stage: str, started: float, result: dict[str, Any]) -> dict[str, Any]:
    """Add this node's timing/timeline contributions to its partial state update.

    ``timeline`` and ``processing_metadata`` are reducer channels, so each node
    returns only *its own* contribution and LangGraph merges them across the
    sequential steps and parallel branches.
    """
    duration_ms = int((time.perf_counter() - started) * 1000)
    out = dict(result or {})
    out.pop("skip_entry", None)  # node-level opt-out (e.g. OCR not needed)
    out["timeline"] = [dict(node_timeline(stage), at=now_iso(), duration_ms=duration_ms)]
    out["processing_metadata"] = {
        "stages": {stage: {"duration_ms": duration_ms, "status": "ok", "at": now_iso()}}
    }
    return out


def timed_node(stage: str):
    """Decorator: time a node and contribute one timeline/metadata entry.

    Works for both sync and async node functions.
    """

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(state: InvestigationState) -> InvestigationState:
            started = time.perf_counter()
            result = func(state)
            return _annotate_result(stage, started, result)

        @wraps(func)
        async def async_wrapper(state: InvestigationState) -> InvestigationState:
            started = time.perf_counter()
            result = await func(state)
            return _annotate_result(stage, started, result)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


def state_update(state: InvestigationState, **kwargs: Any) -> dict[str, Any]:
    """Build a partial-state dict preserving accumulated channels.

    Returns only the deltas for reducer channels (empty lists append nothing)
    plus the explicit keyword updates, so parallel nodes never clobber each
    other's contributions.
    """
    base: dict[str, Any] = {
        "timeline": [],
        "evidence": [],
        "errors": [],
        "warnings": [],
    }
    base.update({k: v for k, v in kwargs.items() if v is not None})
    return base

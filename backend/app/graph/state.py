"""Typed LangGraph state for an investigation.

List fields use LangGraph's ``operator.add`` reducer so parallel branch
nodes can each append evidence/timeline entries safely.
"""
from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict

from app.schemas.analysis import (
    EntityAnalysis,
    MLPrediction,
    ScamClassification,
    TextSignals,
    ThreatIntelResult,
    URLAnalysis,
)
from app.schemas.evidence import EvidenceSignal, ExtractedEntities
from app.schemas.llm import ExplanationResult
from app.schemas.report import InvestigationReport
from app.schemas.risk import RiskAssessment


def merge_metadata(current: dict[str, Any] | None, update: dict[str, Any] | None) -> dict[str, Any]:
    """Reducer merging per-node processing metadata across parallel branches.

    Nested ``stages`` dicts are merged per stage so parallel branch nodes can
    each record their own timing without clobbering the others.
    """
    merged = dict(current or {})
    for key, value in (update or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            sub = dict(merged[key])
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, dict) and isinstance(sub.get(sub_key), dict):
                    sub[sub_key] = {**sub[sub_key], **sub_value}
                else:
                    sub[sub_key] = sub_value
            merged[key] = sub
        else:
            merged[key] = value
    return merged


class InvestigationState(TypedDict, total=False):
    investigation_id: str
    raw_inputs: dict[str, Any]
    input_types: list[str]
    normalized_text: str
    explicit_urls: list[str]

    # extraction
    entities: ExtractedEntities
    ocr_text: str
    ocr_confidence: float
    ocr_provider: str
    ocr_mock: bool

    # analysis
    urls: list[URLAnalysis]
    text_signals: TextSignals
    url_signals: list[EvidenceSignal]
    threat_intel: list[ThreatIntelResult]
    scam_patterns: list[EvidenceSignal]
    pattern_matches: list[dict[str, Any]]
    ml_prediction: MLPrediction | None
    entity_analysis: EntityAnalysis | None
    classification: ScamClassification | None

    # correlation & risk
    correlation: Annotated[dict[str, Any], merge_metadata]
    risk: RiskAssessment | None

    # LLM output
    explanation: ExplanationResult | None
    report: InvestigationReport | None

    # accumulated channels
    evidence: Annotated[list[EvidenceSignal], add]
    timeline: Annotated[list[dict[str, Any]], add]
    errors: Annotated[list[str], add]
    warnings: Annotated[list[str], add]

    # metadata
    processing_metadata: Annotated[dict[str, Any], merge_metadata]
    status: str
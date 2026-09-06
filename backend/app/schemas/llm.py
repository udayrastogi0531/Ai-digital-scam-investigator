"""Structured context passed to LLM providers and their outputs."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .analysis import (
    EntityAnalysis,
    MLPrediction,
    ScamClassification,
    TextSignals,
    ThreatIntelResult,
    URLAnalysis,
)
from .evidence import EvidenceSignal, ExtractedEntities
from .risk import RiskAssessment


class ReportContext(BaseModel):
    """Everything an explanation/report agent is allowed to use.

    The prompt contract: the LLM may ONLY reference facts present in this
    context.  It is explicitly forbidden from inventing external facts,
    reputation results or confirmations by real organizations.
    """

    investigation_id: str
    input_types: list[str] = Field(default_factory=list)
    text_preview: str | None = None
    entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    urls: list[URLAnalysis] = Field(default_factory=list)
    text_signals: TextSignals = Field(default_factory=TextSignals)
    pattern_signals: list[EvidenceSignal] = Field(default_factory=list)
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    ml: MLPrediction | None = None
    entity_analysis: EntityAnalysis | None = None
    classification: ScamClassification | None = None
    risk: RiskAssessment | None = None
    evidence: list[EvidenceSignal] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)

    def evidence_json(self) -> str:
        import json

        return json.dumps(
            [
                {
                    "source": e.source,
                    "signal": e.signal,
                    "severity": e.severity,
                    "confidence": e.confidence,
                    "description": e.description,
                    "detail": e.detail,
                }
                for e in self.evidence
            ],
            default=str,
        )


class ExplanationResult(BaseModel):
    summary: str
    likely_objective: str | None = None
    objective_confidence: str = "low"
    limitations: str | None = None
    provider: str = "unknown"
    model: str | None = None
    is_mock: bool = False
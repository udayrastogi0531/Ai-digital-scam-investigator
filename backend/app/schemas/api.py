"""API-facing schemas (requests/responses)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .analysis import MLPrediction, ScamClassification
from .evidence import EvidenceSignal, ExtractedEntities
from .report import InvestigationReport
from .risk import RiskAssessment


class AnalysisStatus(BaseModel):
    """Processing status of one investigation."""

    status: str
    error: str | None = None
    progress: list[str] = Field(default_factory=list)


class InvestigationSummary(BaseModel):
    """Core result of an investigation, returned by the API."""

    investigation_id: str
    title: str
    status: str
    input_types: list[str] = Field(default_factory=list)
    risk: RiskAssessment | None = None
    scam_type: ScamClassification | None = None
    entities: ExtractedEntities | None = None
    evidence: list[EvidenceSignal] = Field(default_factory=list)
    report: InvestigationReport | None = None
    ml: MLPrediction | None = None
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)


class InvestigationView(InvestigationSummary):
    """Full detail view used by the frontend detail page."""

    processing_metadata: dict[str, Any] = Field(default_factory=dict)
    analyses: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationListItem(BaseModel):
    id: str
    title: str
    status: str
    risk_score: float | None = None
    risk_level: str | None = None
    scam_type: str | None = None
    input_types: list[str] = Field(default_factory=list)
    created_at: datetime | None = None


class PaginatedInvestigations(BaseModel):
    items: list[InvestigationListItem]
    total: int
    page: int
    page_size: int
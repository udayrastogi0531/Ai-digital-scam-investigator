"""Investigation report schemas."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .analysis import ScamClassification


class ScamTypeSummary(BaseModel):
    primary: str
    alternatives: list[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class ReportSection(BaseModel):
    title: str
    content: str
    kind: str = "paragraph"  # paragraph | list | warning


class InvestigationReport(BaseModel):
    summary: str
    likely_objective: str | None = None
    objective_confidence: str = "low"  # low | medium | high
    recommendations: list[str] = Field(default_factory=list)
    suspicious_indicators: list[dict[str, Any]] = Field(default_factory=list)
    limitations: str | None = None
    sections: list[ReportSection] = Field(default_factory=list)
    provider: str = "mock"
    model: str | None = None
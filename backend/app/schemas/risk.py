"""Risk assessment schemas."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RiskContributor(BaseModel):
    """A factor that pushed the risk score up or down."""

    name: str
    impact: float = Field(ge=-1.0, le=1.0)
    detail: str | None = None
    evidence_sources: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    score: float = Field(ge=0.0, le=100.0)
    level: str  # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float = Field(ge=0.0, le=1.0)
    contributors: list[RiskContributor] = Field(default_factory=list)
    weights: dict[str, float] = Field(default_factory=dict)
    method: str = "deterministic_weighted"
    # How much independent evidence backs the assessment.  Kept on the
    # schema (not a DB column) so sparse evidence is never reported with
    # artificially high confidence: INSUFFICIENT | PARTIAL | SUFFICIENT.
    evidence_sufficiency: str | None = None
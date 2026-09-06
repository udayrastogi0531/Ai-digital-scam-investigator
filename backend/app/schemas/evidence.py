"""Input payload and extracted-evidence schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class InputPayload(BaseModel):
    """Everything a user may submit for a single investigation."""

    text: str | None = Field(None, max_length=50_000, description="Free-form message text (email/SMS/chat…).")
    urls: list[str] = Field(default_factory=list, max_length=20, description="Explicit URLs, e.g. from a link.")
    title: str | None = Field(None, max_length=255, description="Optional user-chosen title.")
    source_label: str | None = Field(None, max_length=64, description="Where the message came from (email/sms/…).")

    @field_validator("urls")
    @classmethod
    def _strip_urls(cls, v: list[str]) -> list[str]:
        return [u.strip() for u in v if u and u.strip()]


class NormalizedInput(BaseModel):
    """Input after normalization and validation."""

    text: str
    urls: list[str] = Field(default_factory=list)
    source_label: str | None = None
    input_types: list[str] = Field(default_factory=list)


class ExtractedEntity(BaseModel):
    entity_type: str  # url/email/phone/company/bank/organization/amount/date/otp/credential/payment...
    value: str
    context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExtractedEntities(BaseModel):
    urls: list[ExtractedEntity] = Field(default_factory=list)
    emails: list[ExtractedEntity] = Field(default_factory=list)
    phones: list[ExtractedEntity] = Field(default_factory=list)
    companies: list[ExtractedEntity] = Field(default_factory=list)
    banks: list[ExtractedEntity] = Field(default_factory=list)
    organizations: list[ExtractedEntity] = Field(default_factory=list)
    amounts: list[ExtractedEntity] = Field(default_factory=list)
    dates: list[ExtractedEntity] = Field(default_factory=list)
    other: list[ExtractedEntity] = Field(default_factory=list)

    def all(self) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for field_name in self.model_fields:
            out.extend(getattr(self, field_name))
        return out

    def __len__(self) -> int:
        return len(self.all())


class EvidenceSignal(BaseModel):
    """One structured piece of evidence.

    This is the currency of the whole pipeline: every node contributes
    EvidenceSignal objects which are correlated and aggregated later.
    """

    source: str
    signal: str
    severity: str = "medium"  # low | medium | high | critical
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    description: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
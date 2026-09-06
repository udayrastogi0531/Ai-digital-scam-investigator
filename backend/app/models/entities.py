"""SQLAlchemy ORM entities.

Storage follows the structured-evidence principle: individual signals,
extracted entities and analysis results are stored as rows, not as one
giant JSON blob.  JSON columns are reserved for flexible AI metadata.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255), default="Untitled investigation")
    input_types: Mapped[list] = mapped_column(JSON, default=list)  # ["text","url","image"]
    raw_input_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_input_md5: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending/running/completed/failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    processing_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", lazy="selectin"
    )
    entities: Mapped[list["ExtractedEntity"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", lazy="selectin"
    )
    analyses: Mapped[list["AnalysisResult"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", lazy="selectin"
    )
    risk: Mapped["RiskAssessment | None"] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )
    report: Mapped["Report | None"] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )


class Evidence(Base):
    __tablename__ = "evidence"
    # No unique constraint on (source, signal): several URLs legitimately
    # produce the same signal (e.g. multiple "url_risk" findings).

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(64))  # e.g. "url_analysis"
    signal: Mapped[str] = mapped_column(String(128))  # e.g. "suspicious_domain"
    severity: Mapped[str] = mapped_column(String(16), default="medium")  # low/medium/high/critical
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="evidence")


class ExtractedEntity(Base):
    __tablename__ = "extracted_entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str] = mapped_column(String(32))  # url/email/phone/company/bank/...
    value: Mapped[str] = mapped_column(String(512))
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="entities")


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    __table_args__ = (UniqueConstraint("investigation_id", "agent", name="uq_analysis_agent"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    agent: Mapped[str] = mapped_column(String(64))  # graph node name
    status: Mapped[str] = mapped_column(String(16), default="ok")  # ok/error/skipped
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="analyses")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), unique=True, index=True
    )
    score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String(16))  # LOW/MEDIUM/HIGH/CRITICAL
    confidence: Mapped[float] = mapped_column(Float)
    contributors: Mapped[list] = mapped_column(JSON, default=list)
    weights_used: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="risk")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), unique=True, index=True
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    scam_type: Mapped[dict] = mapped_column(JSON, default=dict)
    likely_objective: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    suspicious_indicators: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    body: Mapped[dict] = mapped_column(JSON, default=dict)  # full structured report
    provider: Mapped[str] = mapped_column(String(32), default="mock")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="report")
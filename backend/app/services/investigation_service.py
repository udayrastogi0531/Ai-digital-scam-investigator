"""Investigation orchestration service.

Responsibilities:
* create investigation rows
* prepare the LangGraph initial state
* execute the workflow
* persist every structured result (evidence, entities, analyses, risk, report)
* query/delete investigations

The graph is deliberately independent of the database: all persistence
happens here, after the workflow completes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings

from app.graph import run_investigation
from app.graph.state import InvestigationState
from app.models import (
    AnalysisResult,
    Evidence,
    ExtractedEntity,
    Investigation,
    Report,
    RiskAssessment,
)
from app.patterns.rules import CATEGORY_LABELS
from app.schemas.api import (
    InvestigationListItem,
    InvestigationSummary,
    InvestigationView,
    PaginatedInvestigations,
)
from app.schemas.evidence import InputPayload
from app.utils.text import md5_hex, truncate

logger = logging.getLogger("scaminvestigator.service")

def _scam_type_expr(value: str):
    """Portable filter on ``reports.scam_type['primary']``.

    PostgreSQL exposes ``.astext`` (``->>``).  SQLAlchemy's SQLite JSON
    subscript wraps the value in ``JSON_QUOTE`` (``'"job_scam"'``), so it
    never equals a plain bound string — use ``json_extract`` directly there.
    """
    if get_settings().using_sqlite:
        return func.json_extract(Report.scam_type, "$.primary") == value
    return Report.scam_type["primary"].astext == value


_INVESTIGATION_LOADS = (
    selectinload(Investigation.evidence),
    selectinload(Investigation.entities),
    selectinload(Investigation.analyses),
    selectinload(Investigation.risk),
    selectinload(Investigation.report),
)


async def _get_investigation(db: AsyncSession, investigation_id: str) -> Investigation | None:
    """Fetch an investigation with all relationships eager-loaded.

    ``db.get`` does not apply ``lazy="selectin"`` loaders, and touching an
    unloaded relationship on an async session raises ``MissingGreenlet``.
    """
    result = await db.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(*_INVESTIGATION_LOADS)
    )
    return result.scalar_one_or_none()


def _title_from(payload: InputPayload, text: str) -> str:
    if payload.title:
        return payload.title[:255]
    preview = truncate(text, 60)
    return preview or "Untitled investigation"


def prepare_state(investigation_id: str, payload: InputPayload, image_bytes: bytes | None = None) -> InvestigationState:
    """Build the initial LangGraph state from user input."""
    return InvestigationState(
        investigation_id=investigation_id,
        raw_inputs={
            "text": payload.text or "",
            "urls": payload.urls or [],
            "source_label": payload.source_label,
            "input_types": [],
            "image_bytes": image_bytes,
        },
        input_types=[],
        normalized_text="",
        explicit_urls=list(payload.urls or []),
        entities=None,
        ocr_text="",
        ocr_confidence=0.0,
        ocr_provider="none",
        ocr_mock=False,
        urls=[],
        text_signals=None,
        url_signals=[],
        threat_intel=[],
        scam_patterns=[],
        pattern_matches=[],
        ml_prediction=None,
        entity_analysis=None,
        classification=None,
        correlation={},
        risk=None,
        explanation=None,
        report=None,
        evidence=[],
        timeline=[],
        errors=[],
        warnings=[],
        processing_metadata={"provider_mode": _provider_mode()},
        status="pending",
    )


async def create_and_run(
    db: AsyncSession,
    payload: InputPayload,
    image_bytes: bytes | None = None,
) -> InvestigationSummary:
    """Create the investigation row, run the workflow, persist results."""
    text = (payload.text or "").strip()
    investigation = Investigation(
        title=_title_from(payload, text),
        input_types=_derive_input_types(payload, image_bytes),
        raw_input_preview=truncate(text or "", 1000) or None,
        raw_input_md5=md5_hex(text or "") if text else None,
        status="running",
    )
    db.add(investigation)
    await db.flush()

    state = prepare_state(investigation.id, payload, image_bytes)
    result = await run_investigation(state)

    await _persist(db, investigation, result)
    return await to_summary(db, investigation.id)


def _provider_mode() -> str:
    from app.core.config import get_settings
    from app.intelligence import get_manager

    settings = get_settings()
    modes = []
    modes.append("mock-llm" if settings.using_mock_llm else f"llm:{settings.llm_model}")
    modes.append("mock-intel" if get_manager().uses_mock else "live-intel")
    return ",".join(modes)


def _derive_input_types(payload: InputPayload, image_bytes: bytes | None) -> list[str]:
    types: list[str] = []
    if payload.text:
        types.append("text")
    if payload.urls:
        types.append("url")
    if image_bytes:
        types.append("image")
    return types


async def _persist(db: AsyncSession, investigation: Investigation, result: dict) -> None:
    """Write graph output to the relational store."""
    investigation.status = result.get("status", "failed")
    metadata = dict(result.get("processing_metadata") or {})
    warnings = list(result.get("warnings") or [])
    if warnings:
        metadata["warnings"] = warnings
    # Structured ML prediction + evidence sufficiency for API/UI hydration
    # (kept on the existing metadata JSON column, no schema migration).
    ml = result.get("ml_prediction")
    if ml is not None:
        metadata["ml_prediction"] = ml.model_dump(exclude={"features"})
    risk_result = result.get("risk")
    if risk_result is not None and risk_result.evidence_sufficiency:
        metadata["risk_sufficiency"] = risk_result.evidence_sufficiency
    investigation.processing_metadata = metadata
    if result.get("errors"):
        investigation.error = "; ".join(result["errors"][:5])

    # --- evidence ---
    for signal in result.get("evidence") or []:
        db.add(
            Evidence(
                investigation_id=investigation.id,
                source=signal.source,
                signal=signal.signal,
                severity=signal.severity,
                confidence=signal.confidence,
                description=signal.description,
                detail=signal.detail,
            )
        )

    # --- extracted entities ---
    entities = result.get("entities")
    if entities:
        for entity in entities.all():
            db.add(
                ExtractedEntity(
                    investigation_id=investigation.id,
                    entity_type=entity.entity_type,
                    value=entity.value,
                    context=entity.context,
                    metadata_=entity.metadata,
                )
            )

    # --- analysis results (one row per timeline stage) ---
    for stage in result.get("timeline") or []:
        db.add(
            AnalysisResult(
                investigation_id=investigation.id,
                agent=stage.get("stage", "unknown"),
                status="ok",
                summary=stage.get("label"),
                payload={"duration_ms": stage.get("duration_ms"), "at": stage.get("at")},
                duration_ms=int(stage.get("duration_ms") or 0),
            )
        )

    # --- risk ---
    risk = result.get("risk")
    if risk:
        db.add(
            RiskAssessment(
                investigation_id=investigation.id,
                score=risk.score,
                level=risk.level,
                confidence=risk.confidence,
                contributors=[c.model_dump() for c in risk.contributors],
                weights_used=risk.weights,
            )
        )

    # --- report ---
    report = result.get("report")
    classification = result.get("classification")
    if report:
        db.add(
            Report(
                investigation_id=investigation.id,
                summary=report.summary,
                scam_type={
                    "primary": classification.primary if classification else "unknown",
                    "alternatives": list(classification.alternatives) if classification else [],
                    "confidence": classification.confidence if classification else 0.0,
                },
                likely_objective=report.likely_objective,
                recommendations=list(report.recommendations),
                suspicious_indicators=list(report.suspicious_indicators),
                limitations=report.limitations,
                body=report.model_dump(),
                provider=report.provider,
            )
        )

    investigation.updated_at = datetime.now(timezone.utc)
    await db.commit()


async def to_summary(db: AsyncSession, investigation_id: str) -> InvestigationSummary:
    """Build the API summary view for one investigation."""
    investigation = await _get_investigation(db, investigation_id)
    if investigation is None:
        raise KeyError(f"investigation {investigation_id} not found")
    risk = investigation.risk
    report = investigation.report
    return InvestigationSummary(
        investigation_id=investigation.id,
        title=investigation.title,
        status=investigation.status,
        input_types=investigation.input_types or [],
        risk=_risk_schema(risk, investigation.processing_metadata or {}),
        scam_type=_scam_type_schema(report),
        entities=_entities_schema(investigation),
        evidence=_evidence_schema(investigation),
        report=_report_schema(report),
        ml=_ml_schema(investigation.processing_metadata or {}),
        timeline=_timeline_from_analyses(investigation),
        created_at=investigation.created_at,
        warnings=_warnings(investigation),
    )


async def get_view(db: AsyncSession, investigation_id: str) -> InvestigationView:
    base = await to_summary(db, investigation_id)
    investigation = await _get_investigation(db, investigation_id)
    if investigation is None:
        raise KeyError(f"investigation {investigation_id} not found")
    view = InvestigationView.model_validate(base.model_dump())
    view.processing_metadata = investigation.processing_metadata or {}
    view.analyses = [
        {
            "agent": a.agent,
            "status": a.status,
            "summary": a.summary,
            "payload": a.payload,
            "duration_ms": a.duration_ms,
            "created_at": a.created_at,
        }
        for a in (investigation.analyses or [])
    ]
    timeline = _timeline_from_analyses(investigation)
    view.timeline = timeline or view.timeline
    return view


def _timeline_from_analyses(investigation: Investigation) -> list[dict]:
    stages = {
        "parse": "Evidence parsed and normalized",
        "ocr": "Screenshot OCR",
        "analyze": "Text signals & scam patterns",
        "llm_classify": "LLM classification refinement",
        "url_analysis": "URL analysis",
        "entity_analysis": "Entity / brand analysis",
        "threat_intel": "Threat intelligence lookup",
        "ml": "Machine-learning prediction",
        "correlate": "Evidence correlation",
        "risk": "Risk assessment",
        "explain": "AI explanation",
        "report": "Report generation",
    }
    order = list(stages.keys())
    rows = sorted(
        (a for a in (investigation.analyses or []) if a.agent in stages),
        key=lambda a: order.index(a.agent),
    )
    return [
        {
            "stage": a.agent,
            "label": stages.get(a.agent, a.agent),
            "duration_ms": a.duration_ms,
            "at": a.payload.get("at") if isinstance(a.payload, dict) else None,
        }
        for a in rows
    ]


async def list_investigations(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
    risk_level: str | None = None,
    scam_type: str | None = None,
) -> PaginatedInvestigations:
    query = select(Investigation)
    if search:
        query = query.where(Investigation.title.ilike(f"%{search}%"))
    if risk_level:
        query = query.join(RiskAssessment).where(RiskAssessment.level == risk_level.upper())
    if scam_type:
        query = query.join(Report).where(_scam_type_expr(scam_type))
    total = len((await db.execute(query)).scalars().all())
    query = (
        query.order_by(desc(Investigation.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(query)).scalars().all()
    items = [
        InvestigationListItem(
            id=inv.id,
            title=inv.title,
            status=inv.status,
            risk_score=inv.risk.score if inv.risk else None,
            risk_level=inv.risk.level if inv.risk else None,
            scam_type=_primary_type(inv),
            input_types=inv.input_types or [],
            created_at=inv.created_at,
        )
        for inv in rows
    ]
    return PaginatedInvestigations(items=items, total=total, page=page, page_size=page_size)


async def delete_investigation(db: AsyncSession, investigation_id: str) -> bool:
    investigation = await _get_investigation(db, investigation_id)
    if investigation is None:
        return False
    await db.delete(investigation)
    await db.commit()
    return True


# --- schema helpers ---------------------------------------------------------

def _risk_schema(risk: RiskAssessment | None, metadata: dict | None = None):
    if risk is None:
        return None
    from app.schemas.risk import RiskAssessment as RiskSchema

    return RiskSchema(
        score=risk.score,
        level=risk.level,
        confidence=risk.confidence,
        contributors=[dict(c) for c in (risk.contributors or [])],
        weights=risk.weights_used or {},
        evidence_sufficiency=(metadata or {}).get("risk_sufficiency"),
    )


def _ml_schema(metadata: dict | None):
    """Hydrate the ML prediction stored on the investigation metadata."""
    data = (metadata or {}).get("ml_prediction")
    if not isinstance(data, dict):
        return None
    from app.schemas.analysis import MLPrediction

    try:
        return MLPrediction(
            probability_scam=float(data.get("probability_scam", 0.0)),
            label=str(data.get("label", "benign")),
            model=str(data.get("model", "none")),
            is_mock=bool(data.get("is_mock", True)),
            features={},
            feature_importance=dict(data.get("feature_importance") or {}),
        )
    except (TypeError, ValueError):
        return None


def _scam_type_schema(report: Report | None):
    if report is None or not report.scam_type:
        return None
    from app.schemas.analysis import ScamClassification

    return ScamClassification(
        primary=report.scam_type.get("primary", "unknown"),
        alternatives=list(report.scam_type.get("alternatives", [])),
        confidence=float(report.scam_type.get("confidence", 0.0)),
        method="hybrid",
    )


def _entities_schema(investigation: Investigation):
    from app.schemas.evidence import ExtractedEntities, ExtractedEntity

    bucket = {name: [] for name in ExtractedEntities.model_fields}
    bucket.update(
        {
            "urls": [],
            "emails": [],
            "phones": [],
            "companies": [],
            "banks": [],
            "organizations": [],
            "amounts": [],
            "dates": [],
            "other": [],
        }
    )
    for entity in investigation.entities or []:
        item = ExtractedEntity(
            entity_type=entity.entity_type,
            value=entity.value,
            context=entity.context,
            metadata=entity.metadata_ or {},
        )
        bucket.setdefault(_entity_bucket(entity.entity_type), []).append(item)
    return ExtractedEntities(**bucket)


def _entity_bucket(entity_type: str) -> str:
    if entity_type in ("url", "email", "phone", "company", "bank", "organization", "amount", "date"):
        plural = {"company": "companies", "bank": "banks", "organization": "organizations"}
        return plural.get(entity_type, entity_type + "s")
    return "other"


def _evidence_schema(investigation: Investigation):
    from app.schemas.evidence import EvidenceSignal

    return [
        EvidenceSignal(
            source=e.source,
            signal=e.signal,
            severity=e.severity,
            confidence=e.confidence,
            description=e.description,
            detail=e.detail or {},
        )
        for e in (investigation.evidence or [])
    ]


def _report_schema(report: Report | None):
    if report is None:
        return None
    return report.body or None


def _primary_type(investigation: Investigation) -> str | None:
    if investigation.report and investigation.report.scam_type:
        primary = investigation.report.scam_type.get("primary")
        return CATEGORY_LABELS.get(primary, primary)
    return None


def _warnings(investigation: Investigation) -> list[str]:
    """Warnings surfaced to the UI: graph warnings plus derived OCR notes."""
    metadata = investigation.processing_metadata or {}
    warnings = list(metadata.get("warnings") or [])
    # OCR mock warning
    if investigation.input_types and "image" in investigation.input_types:
        stages = metadata.get("stages", {})
        if not stages.get("ocr"):
            warnings.append("Screenshot received but OCR did not run.")
    return warnings
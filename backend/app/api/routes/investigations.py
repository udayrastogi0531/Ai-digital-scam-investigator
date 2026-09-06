"""Investigation CRUD and combined-submission endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rate_limit import rate_limit
from app.core.security import read_image_upload
from app.database import get_db
from app.schemas.api import (
    InvestigationSummary,
    InvestigationView,
    PaginatedInvestigations,
)
from app.schemas.evidence import InputPayload
from app.services import investigation_service as svc

logger = logging.getLogger("scaminvestigator.api")

router = APIRouter(prefix="/investigations", tags=["investigations"])


async def _run_submission(
    db: AsyncSession,
    payload: InputPayload,
    image_bytes: bytes | None = None,
) -> InvestigationSummary:
    """Shared runner used by all submission endpoints."""
    try:
        return await svc.create_and_run(db, payload, image_bytes=image_bytes)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("investigation run failed")
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}") from exc


@router.post("", response_model=InvestigationSummary, dependencies=[Depends(rate_limit())])
async def create_investigation(
    text: str | None = Form(None, max_length=50_000),
    urls: list[str] = Form(default=[]),
    title: str | None = Form(None),
    source_label: str | None = Form(None),
    image: UploadFile | None = File(None),
    db: AsyncSession = Depends(get_db),
) -> InvestigationSummary:
    """Submit combined evidence: text + explicit URLs + screenshot."""
    payload = InputPayload(text=text, urls=urls, title=title, source_label=source_label)
    if not payload.text and not payload.urls and image is None:
        raise HTTPException(status_code=422, detail="Provide text, at least one URL, or an image.")
    image_bytes = await read_image_upload(image) if image is not None else None
    return await _run_submission(db, payload, image_bytes=image_bytes)


@router.get("", response_model=PaginatedInvestigations)
async def list_investigations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None, max_length=200),
    risk_level: str | None = Query(None, pattern="^(?i)(LOW|MEDIUM|HIGH|CRITICAL)$"),
    scam_type: str | None = Query(None, max_length=64),
    db: AsyncSession = Depends(get_db),
) -> PaginatedInvestigations:
    return await svc.list_investigations(
        db,
        page=page,
        page_size=page_size,
        search=search,
        risk_level=risk_level,
        scam_type=scam_type,
    )


@router.get("/{investigation_id}", response_model=InvestigationView)
async def get_investigation(investigation_id: str, db: AsyncSession = Depends(get_db)) -> InvestigationView:
    try:
        return await svc.get_view(db, investigation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.delete("/{investigation_id}", status_code=204)
async def delete_investigation(investigation_id: str, db: AsyncSession = Depends(get_db)) -> None:
    deleted = await svc.delete_investigation(db, investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
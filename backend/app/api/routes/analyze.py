"""Convenience analysis endpoints (text / url / image / combined)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes.investigations import _run_submission
from app.core.rate_limit import rate_limit
from app.core.security import read_image_upload
from app.database import get_db
from app.schemas.api import InvestigationSummary
from app.schemas.evidence import InputPayload

router = APIRouter(prefix="/analyze", tags=["analyze"], dependencies=[Depends(rate_limit())])


@router.post("/text", response_model=InvestigationSummary)
async def analyze_text(payload: InputPayload, db: AsyncSession = Depends(get_db)) -> InvestigationSummary:
    if not payload.text and not payload.urls:
        raise HTTPException(status_code=422, detail="Provide 'text', 'urls', or both.")
    return await _run_submission(db, payload)


@router.post("/url", response_model=InvestigationSummary)
async def analyze_url(
    url: str = Form(...), title: str | None = Form(None), db: AsyncSession = Depends(get_db)
) -> InvestigationSummary:
    payload = InputPayload(urls=[url], title=title)
    return await _run_submission(db, payload)


@router.post("/image", response_model=InvestigationSummary)
async def analyze_image(
    image: UploadFile = File(...),
    text: str | None = Form(None),
    title: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
) -> InvestigationSummary:
    image_bytes = await read_image_upload(image)
    payload = InputPayload(text=text, title=title)
    return await _run_submission(db, payload, image_bytes=image_bytes)
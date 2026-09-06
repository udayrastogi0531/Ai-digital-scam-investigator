"""Demo cases.

Runs one of the bundled *fictional* sample cases through the full pipeline.
All domains/numbers/persons in these cases are fictional; they exist to
exercise the product without the user having to type anything.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes.investigations import _run_submission
from app.core.rate_limit import rate_limit
from app.database import get_db
from app.schemas.api import InvestigationSummary
from app.schemas.evidence import InputPayload
from app.services.demo_cases import DEMO_CASES, list_demo_cases

router = APIRouter(prefix="/demo", tags=["demo"], dependencies=[Depends(rate_limit())])


@router.get("")
async def demo_index() -> dict:
    return {"demo_mode": True, "cases": [{"slug": s, "title": t} for s, t in list_demo_cases()]}


@router.post("/{slug}", response_model=InvestigationSummary)
async def run_demo_case(slug: str, db: AsyncSession = Depends(get_db)) -> InvestigationSummary:
    case = DEMO_CASES.get(slug)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Unknown demo case '{slug}'")
    payload = InputPayload(text=case["text"], urls=case.get("urls", []), title=case["title"])
    return await _run_submission(db, payload)
"""Health and capability endpoint."""
from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings
from app.intelligence import get_manager
from app.llm import get_llm_provider
from app.ml import get_classifier

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    settings = get_settings()
    llm = get_llm_provider()
    manager = get_manager()
    classifier = get_classifier()
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "database": "postgresql" if not settings.using_sqlite else "sqlite (local fallback)",
        "providers": {
            "llm": {"name": llm.name, "is_mock": llm.is_mock, "model": getattr(llm, "model", None)},
            "threat_intel": {"active": manager.active_names, "uses_mock": manager.uses_mock},
            "ml": {"available": classifier.available, "model": classifier.model_name},
            "ocr": _ocr_status(),
        },
        "demo_mode": llm.is_mock and manager.uses_mock,
    }


def _ocr_status() -> dict:
    from app.extraction.ocr import get_ocr_provider

    provider = get_ocr_provider()
    return {"provider": provider.name, "is_mock": provider.is_mock}
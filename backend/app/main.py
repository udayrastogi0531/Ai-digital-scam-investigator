"""FastAPI application entry point.

Run locally::

    uvicorn app.main:app --reload

OpenAPI docs: http://localhost:8000/docs
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import analyze, demo, health, investigations
from app.core.config import get_settings
from app.core.logging import setup_logging

setup_logging()
logger = logging.getLogger("scaminvestigator.main")

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.database import create_tables

    try:
        await create_tables()
        logger.info("database tables ready (%s)", "postgres" if not settings.using_sqlite else "sqlite")
    except Exception as exc:  # noqa: BLE001
        logger.exception("failed to initialize database: %s", exc)
        raise
    if settings.using_mock_llm:
        logger.warning("DEMO MODE: LLM provider is mock — explanations are deterministic, not LLM-generated.")
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Agentic investigation engine for suspicious digital communications. "
        "Submits evidence → LangGraph pipeline → structured report."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix=settings.api_prefix)
app.include_router(investigations.router, prefix=settings.api_prefix)
app.include_router(analyze.router, prefix=settings.api_prefix)
app.include_router(demo.router, prefix=settings.api_prefix)


@app.get("/")
async def root() -> dict:
    return {
        "app": settings.app_name,
        "docs": "/docs",
        "health": "/api/health",
    }
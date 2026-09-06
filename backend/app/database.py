"""Async SQLAlchemy engine/session management.

Default local URL is SQLite (zero setup); docker-compose overrides it with
PostgreSQL via ``DATABASE_URL``.
"""
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        # allow concurrency across async tasks in tests
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True}


settings = get_settings()
engine = create_async_engine(settings.database_url, **_engine_kwargs(settings.database_url))
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a database session."""
    async with SessionLocal() as session:
        yield session


async def create_tables() -> None:
    """Create all tables.  Idempotent — used for dev and tests.

    Production deployments may prefer Alembic migrations (see ml/docs or
    README); auto-create is harmless since it only adds missing tables.
    """
    from . import models  # noqa: F401  (register models on Base)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
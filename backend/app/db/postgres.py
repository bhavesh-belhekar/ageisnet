"""PostgreSQL/TimescaleDB persistence. Phase 1 placeholder; implemented in Phase 3."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config.settings import get_settings


def build_engine():
    """Build and return the async SQLAlchemy engine from settings."""
    settings = get_settings()
    dsn = (
        f"postgresql+asyncpg://{settings.postgres_user}:{settings.postgres_password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
    )
    return create_async_engine(dsn, echo=settings.debug)


def session_factory():
    """Return an async sessionmaker bound to the configured engine."""
    return async_sessionmaker(build_engine(), expire_on_commit=False)

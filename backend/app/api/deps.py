"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from app.db.postgres import DatabaseUnavailableError


def get_pool(request: Request):
    """Return the app's Postgres pool, or fail fast with a typed error."""
    pool = getattr(request.app.state, "pool", None)
    if pool is None:
        raise DatabaseUnavailableError("postgres pool not initialized")
    return pool

"""Historical raw-event query API (PRD.md Section 10)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Request

from app.api.deps import get_pool
from app.db import postgres as db
from app.models.event import Event

router = APIRouter(prefix="/api/events", tags=["events"])

MAX_LIMIT = 1000


@router.get("", response_model=list[Event])
async def get_events(
    request: Request,
    container_id: str | None = Query(default=None, max_length=12),
    direction: Literal["internal", "external"] | None = None,
    event_type: Literal["open", "close"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """List raw events, newest first, filterable by container/direction/time."""
    return await db.list_events(
        get_pool(request),
        container_id=container_id,
        direction=direction,
        event_type=event_type,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )

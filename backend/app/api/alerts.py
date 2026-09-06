"""Alert query API (PRD.md Section 10) — list, detail, acknowledge."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

from app.api.deps import get_pool
from app.db import postgres as db
from app.models.alert import Alert
from app.models.schemas import AckRequest

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

MAX_LIMIT = 1000


def _not_found(alert_id: int) -> None:
    """Raise the standardized 404 error body (RULES.md §4.3)."""
    raise HTTPException(
        status_code=404,
        detail={"error": "not_found", "message": f"Alert with id {alert_id} not found"},
    )


@router.get("", response_model=list[Alert])
async def get_alerts(
    request: Request,
    severity: Literal["low", "medium", "high"] | None = None,
    container_id: str | None = Query(default=None, max_length=12),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """List alerts, newest first, filterable by severity/container/time range."""
    return await db.list_alerts(
        get_pool(request),
        severity=severity,
        container_id=container_id,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=Alert)
async def get_one_alert(request: Request, alert_id: int) -> dict:
    """Return the full alert record, including shap_explanation (nullable)."""
    alert = await db.get_alert(get_pool(request), alert_id)
    if alert is None:
        _not_found(alert_id)
    return alert


@router.patch("/{alert_id}/ack", response_model=Alert)
async def acknowledge(request: Request, alert_id: int, body: AckRequest) -> dict:
    """Set the acknowledged flag; returns the updated alert record."""
    alert = await db.ack_alert(get_pool(request), alert_id, body.acknowledged)
    if alert is None:
        _not_found(alert_id)
    return alert

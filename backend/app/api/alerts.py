"""Alert query API (PRD.md Section 10) — list, detail, acknowledge."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.api.deps import get_pool
from app.db import postgres as db
from app.mitre_mapper.mapper import get_mitre_info_by_technique
from app.models.alert import Alert, DetectionType, Severity
from app.models.schemas import AckRequest

logger = logging.getLogger("api.alerts")

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

MAX_LIMIT = 1000


class CreateTestAlertRequest(BaseModel):
    """Payload for manual/testing alert injection."""

    container_id: str = Field(default="demo-attacker", max_length=12)
    severity: Literal["low", "medium", "high"] = "high"
    detection_type: Literal["rule", "ml"] = "rule"
    technique_id: str = "T1071"
    description: str = "Manual test alert: C2 activity detected"


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


@router.post("/test", response_model=Alert, status_code=201)
async def trigger_test_alert(
    request: Request,
    body: CreateTestAlertRequest | None = None,
) -> dict:
    """Trigger a test alert and broadcast it live to all connected WebSocket clients.

    Useful for manual testing, verification, and end-to-end demo inspection.
    """
    req_data = body or CreateTestAlertRequest()
    mitre_info = get_mitre_info_by_technique(req_data.technique_id)

    now = datetime.now(UTC)
    fake_event_id = int(now.timestamp() * 1000) % 1_000_000

    alert = Alert(
        event_id=fake_event_id,
        container_id=req_data.container_id,
        timestamp=now,
        detection_type=DetectionType(req_data.detection_type),
        severity=Severity(req_data.severity),
        mitre_technique_id=mitre_info.technique_id if mitre_info else req_data.technique_id,
        mitre_technique_name=mitre_info.technique_name if mitre_info else None,
        mitre_tactic_id=mitre_info.tactic_id if mitre_info else None,
        mitre_tactic_name=mitre_info.tactic_name if mitre_info else None,
        description=req_data.description,
        acknowledged=False,
    )

    alert_id = fake_event_id
    try:
        pool = get_pool(request)
        if pool is not None:
            alert_id = await db.save_alert(pool, alert.model_dump())
    except Exception as exc:
        logger.info("DB save skipped for test alert (%s) — broadcasting in-memory", exc)

    payload = alert.model_dump(mode="json")
    payload["alert_id"] = alert_id

    hub = getattr(request.app.state, "alert_hub", None)
    if hub is not None:
        await hub.publish(payload)
        logger.info("Test alert %s broadcast to WebSocket subscribers", alert_id)

    return payload

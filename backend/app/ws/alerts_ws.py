"""Real-time alert push over WebSocket (FR-7.2 / ARCHITECTURE.md §3.5).

``AlertHub`` is an in-process fan-out: the event consumer publishes each newly
persisted alert; every connected /ws/alerts subscriber receives it.  Only
alerts at or above ``delivery.push_min_severity`` (medium by default) are
pushed — Low alerts stay in the audit trail.

SHAP follow-up messages (``update_type == "shap_attachment"``) bypass the
severity filter: the parent alert has already passed the filter; the follow-up
only attaches an explanation to an alert the subscriber already holds.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.models.alert import Severity
from app.risk_scoring.scorer import get_push_min_severity

logger = logging.getLogger("ws.alerts_ws")

router = APIRouter()

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _json_default(obj: Any) -> Any:
    """Safe serializer fallback for non-primitive types (datetime, UUID, Enum, set)."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def serialize_alert_payload(data: Any) -> str:
    """Serialize alert payload to a JSON string without crashing on datetime/UUID/Enum."""
    return json.dumps(data, default=_json_default)


class AlertHub:
    """Fan-out of new alerts to connected WebSocket subscribers."""

    def __init__(self, min_severity: Severity | None = None) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._min_severity = min_severity or get_push_min_severity()

    @property
    def subscriber_count(self) -> int:
        """Return the number of currently connected subscribers."""
        return len(self._subscribers)

    def subscribe(self) -> asyncio.Queue:
        """Register a subscriber queue and return it."""
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        logger.debug("Subscriber registered (total: %d)", len(self._subscribers))
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Deregister a subscriber queue."""
        self._subscribers.discard(queue)
        logger.debug("Subscriber deregistered (total: %d)", len(self._subscribers))

    async def publish(self, alert: dict) -> None:
        """Fan out one persisted alert dict, filtered by push severity (FR-7.2).

        SHAP follow-up messages (``update_type == "shap_attachment"``) do not
        carry a ``severity`` field and must bypass the severity filter — they
        update an alert that has already passed the filter and been pushed.
        """
        if alert.get("update_type") != "shap_attachment":
            raw_sev = alert.get("severity")
            if raw_sev is None:
                return
            severity = raw_sev if isinstance(raw_sev, Severity) else Severity(str(raw_sev).lower())
            if _SEVERITY_RANK.get(severity.value, 0) < _SEVERITY_RANK.get(self._min_severity.value, 1):
                return
        for queue in list(self._subscribers):
            queue.put_nowait(alert)


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """Stream newly persisted Medium+ alerts to one dashboard client."""
    await websocket.accept()
    hub: AlertHub | None = getattr(websocket.app.state, "alert_hub", None)
    if hub is None:
        hub = AlertHub()
        websocket.app.state.alert_hub = hub

    queue = hub.subscribe()
    try:
        while True:
            alert = await queue.get()
            payload_str = serialize_alert_payload(alert)
            await websocket.send_text(payload_str)
    except (WebSocketDisconnect, RuntimeError):
        logger.info("ws subscriber disconnected")
    except Exception as exc:
        logger.warning("ws subscriber error: %s", exc)
    finally:
        hub.unsubscribe(queue)

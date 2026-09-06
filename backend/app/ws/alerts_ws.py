"""Real-time alert push over WebSocket (FR-7.2 / ARCHITECTURE.md §3.5).

``AlertHub`` is an in-process fan-out: the event consumer publishes each newly
persisted alert; every connected /ws/alerts subscriber receives it.  Only
alerts at or above ``delivery.push_min_severity`` (medium by default) are
pushed — Low alerts stay in the audit trail.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.models.alert import Severity
from app.risk_scoring.scorer import get_push_min_severity

logger = logging.getLogger("ws.alerts_ws")

router = APIRouter()

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


class AlertHub:
    """Fan-out of new alerts to connected WebSocket subscribers."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._min_severity = get_push_min_severity()

    def subscribe(self) -> asyncio.Queue:
        """Register a subscriber queue and return it."""
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Deregister a subscriber queue."""
        self._subscribers.discard(queue)

    async def publish(self, alert: dict) -> None:
        """Fan out one persisted alert dict, filtered by push severity (FR-7.2)."""
        severity = Severity(alert["severity"])
        if _SEVERITY_RANK[severity.value] < _SEVERITY_RANK[self._min_severity.value]:
            return
        for queue in list(self._subscribers):
            queue.put_nowait(alert)


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """Stream newly persisted Medium+ alerts to one dashboard client."""
    await websocket.accept()
    hub: AlertHub = websocket.app.state.alert_hub
    queue = hub.subscribe()
    try:
        while True:
            alert = await queue.get()
            await websocket.send_json(alert)
    except (WebSocketDisconnect, RuntimeError):
        logger.info("ws subscriber disconnected")
    finally:
        hub.unsubscribe(queue)

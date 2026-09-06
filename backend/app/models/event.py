from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class Direction(StrEnum):
    """Direction of a raw network event."""

    INTERNAL = "internal"
    EXTERNAL = "external"


class EventType(StrEnum):
    """Phase of a TCP connection lifecycle."""

    OPEN = "open"
    CLOSE = "close"


class Event(BaseModel):
    """Frozen raw capture schema (PRD.md Section 9)."""

    event_id: int
    container_id: str
    timestamp: datetime
    event_type: EventType
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    direction: Direction

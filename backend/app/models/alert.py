from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class DetectionType(StrEnum):
    """Origin of a detection."""

    RULE = "rule"
    ML = "ml"


class Severity(StrEnum):
    """Alert severity label."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Alert(BaseModel):
    """Frozen alert schema (PRD.md Section 9)."""

    alert_id: int | None = None
    event_id: int
    container_id: str
    timestamp: datetime
    detection_type: DetectionType
    severity: Severity
    mitre_technique_id: str | None = None
    description: str
    shap_explanation: dict | None = None
    acknowledged: bool = False

"""Shared Pydantic request/response schemas for the API layer."""

from __future__ import annotations

from pydantic import BaseModel


class AckRequest(BaseModel):
    """Request body for PATCH /api/alerts/{id}/ack."""

    acknowledged: bool = True

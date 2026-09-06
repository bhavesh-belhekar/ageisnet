"""Historical raw-event query API. Phase 1 placeholder; endpoint added in Phase 3."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/events", tags=["events"])

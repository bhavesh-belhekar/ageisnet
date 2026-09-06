"""AlertHub WebSocket fan-out tests (FR-7.2: only Medium+ alerts are pushed)."""

import asyncio

import pytest
from app.models.alert import Severity
from app.ws.alerts_ws import AlertHub

ALERT = {
    "alert_id": 1,
    "event_id": 1,
    "container_id": "abc",
    "timestamp": "2026-09-06T00:00:00+00:00",
    "detection_type": "rule",
    "severity": "medium",
    "mitre_technique_id": "T1043",
    "description": "test",
    "shap_explanation": None,
    "acknowledged": False,
}


@pytest.fixture()
def hub() -> AlertHub:
    return AlertHub()


@pytest.mark.asyncio
async def test_medium_alert_is_delivered(hub: AlertHub) -> None:
    queue = hub.subscribe()
    await hub.publish({**ALERT, "severity": Severity.MEDIUM.value})
    got = await asyncio.wait_for(queue.get(), timeout=1)
    assert got["alert_id"] == 1
    hub.unsubscribe(queue)


@pytest.mark.asyncio
async def test_high_alert_is_delivered(hub: AlertHub) -> None:
    queue = hub.subscribe()
    await hub.publish({**ALERT, "severity": Severity.HIGH.value})
    got = await asyncio.wait_for(queue.get(), timeout=1)
    assert got["severity"] == Severity.HIGH.value
    hub.unsubscribe(queue)


@pytest.mark.asyncio
async def test_low_alert_is_not_pushed(hub: AlertHub) -> None:
    queue = hub.subscribe()
    await hub.publish({**ALERT, "severity": Severity.LOW.value})
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(queue.get(), timeout=0.2)
    hub.unsubscribe(queue)


@pytest.mark.asyncio
async def test_unsubscribed_queue_receives_nothing(hub: AlertHub) -> None:
    queue = hub.subscribe()
    hub.unsubscribe(queue)
    await hub.publish(ALERT)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(queue.get(), timeout=0.2)


@pytest.mark.asyncio
async def test_multiple_subscribers_all_receive(hub: AlertHub) -> None:
    q1 = hub.subscribe()
    q2 = hub.subscribe()
    await hub.publish(ALERT)
    got1 = await asyncio.wait_for(q1.get(), timeout=1)
    got2 = await asyncio.wait_for(q2.get(), timeout=1)
    assert got1 == got2 == ALERT.copy()
    hub.unsubscribe(q1)
    hub.unsubscribe(q2)

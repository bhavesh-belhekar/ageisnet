import pytest
from app.api import health as health_module
from app.db import postgres as db_module
from app.db.postgres import DatabaseUnavailableError
from app.main import app
from httpx import ASGITransport, AsyncClient

TEST_ALERT = {
    "alert_id": 42,
    "event_id": 16421,
    "container_id": "5bf7a9363c99",
    "timestamp": "2026-09-06T15:59:44.034992+00:00",
    "detection_type": "rule",
    "severity": "medium",
    "mitre_technique_id": "T1043",
    "description": "Connection to known-bad port 445",
    "shap_explanation": None,
    "acknowledged": False,
}

TEST_EVENT = {
    "event_id": 16421,
    "container_id": "5bf7a9363c99",
    "timestamp": "2026-09-06T15:59:44.034992+00:00",
    "event_type": "open",
    "src_ip": "172.18.0.8",
    "dst_ip": "172.18.0.4",
    "src_port": 39131,
    "dst_port": 445,
    "protocol": "tcp",
    "bytes_sent": 0,
    "bytes_received": 0,
    "direction": "internal",
}


@pytest.fixture()
def client():
    app.state.pool = object()  # monkeypatched repo fns ignore the real pool
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    )


@pytest.mark.asyncio
async def test_health_returns_ok_when_all_dependencies_reachable(monkeypatch) -> None:
    async def ok() -> bool:
        return True

    monkeypatch.setattr(health_module, "check_postgres", ok)
    monkeypatch.setattr(health_module, "check_redis", ok)
    monkeypatch.setattr(health_module, "check_neo4j", ok)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_returns_503_when_a_dependency_is_down(monkeypatch) -> None:
    async def ok() -> bool:
        return True

    async def down() -> bool:
        return False

    monkeypatch.setattr(health_module, "check_postgres", ok)
    monkeypatch.setattr(health_module, "check_redis", ok)
    monkeypatch.setattr(health_module, "check_neo4j", down)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.get("/api/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


@pytest.mark.asyncio
async def test_get_alerts_lists_and_forwards_filters(monkeypatch, client) -> None:
    captured = {}

    async def fake_list_alerts(pool, **kwargs):
        captured.update(kwargs)
        return [TEST_ALERT]

    monkeypatch.setattr(db_module, "list_alerts", fake_list_alerts)
    async with client as c:
        response = await c.get(
            "/api/alerts", params={"severity": "medium", "limit": 5, "offset": 10}
        )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["mitre_technique_id"] == "T1043"
    assert captured["severity"] == "medium"
    assert captured["limit"] == 5
    assert captured["offset"] == 10


@pytest.mark.asyncio
async def test_get_one_alert_returns_detail(monkeypatch, client) -> None:
    async def fake_get_alert(pool, alert_id: int):
        return TEST_ALERT if alert_id == 42 else None

    monkeypatch.setattr(db_module, "get_alert", fake_get_alert)
    async with client as c:
        response = await c.get("/api/alerts/42")

    assert response.status_code == 200
    assert response.json()["alert_id"] == 42


@pytest.mark.asyncio
async def test_get_one_alert_404_uses_standard_shape(monkeypatch, client) -> None:
    async def fake_get_alert(pool, alert_id: int):
        return None

    monkeypatch.setattr(db_module, "get_alert", fake_get_alert)
    async with client as c:
        response = await c.get("/api/alerts/999")

    assert response.status_code == 404
    assert response.json() == {
        "error": "not_found",
        "message": "Alert with id 999 not found",
    }


@pytest.mark.asyncio
async def test_ack_marks_alert_and_returns_updated(monkeypatch, client) -> None:
    updated = {**TEST_ALERT, "alert_id": 42, "acknowledged": True}

    async def fake_ack(pool, alert_id: int, acknowledged: bool):
        return updated if alert_id == 42 else None

    monkeypatch.setattr(db_module, "ack_alert", fake_ack)
    async with client as c:
        response = await c.patch("/api/alerts/42/ack", json={"acknowledged": True})

    assert response.status_code == 200
    assert response.json()["acknowledged"] is True


@pytest.mark.asyncio
async def test_ack_missing_alert_404(monkeypatch, client) -> None:
    async def fake_ack(pool, alert_id: int, acknowledged: bool):
        return None

    monkeypatch.setattr(db_module, "ack_alert", fake_ack)
    async with client as c:
        response = await c.patch("/api/alerts/999/ack", json={"acknowledged": True})

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


@pytest.mark.asyncio
async def test_get_events_lists_and_forwards_filters(monkeypatch, client) -> None:
    captured = {}

    async def fake_list_events(pool, **kwargs):
        captured.update(kwargs)
        return [TEST_EVENT]

    monkeypatch.setattr(db_module, "list_events", fake_list_events)
    async with client as c:
        response = await c.get(
            "/api/events", params={"direction": "internal", "event_type": "open"}
        )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["event_id"] == 16421
    assert captured["direction"] == "internal"
    assert captured["event_type"] == "open"


@pytest.mark.asyncio
async def test_db_unavailable_returns_503_shape(monkeypatch, client) -> None:
    async def boom(pool, **kwargs):
        raise DatabaseUnavailableError("postgres is down")

    monkeypatch.setattr(db_module, "list_alerts", boom)
    async with client as c:
        response = await c.get("/api/alerts")

    assert response.status_code == 503
    assert response.json() == {"error": "db_unavailable", "message": "postgres is down"}


@pytest.mark.asyncio
async def test_invalid_severity_filter_rejected(client) -> None:
    async with client as c:
        response = await c.get("/api/alerts", params={"severity": "critical"})

    assert response.status_code == 422

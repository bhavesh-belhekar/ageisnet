import pytest
from app.api import health as health_module
from app.main import app
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_health_returns_ok_when_all_dependencies_reachable(monkeypatch) -> None:
    async def ok() -> bool:
        return True

    monkeypatch.setattr(health_module, "check_postgres", ok)
    monkeypatch.setattr(health_module, "check_redis", ok)
    monkeypatch.setattr(health_module, "check_neo4j", ok)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")

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
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"

import asyncpg
from fastapi import APIRouter, Response
from neo4j import AsyncGraphDatabase
from redis import asyncio as aioredis

from app.config.settings import get_settings

router = APIRouter(tags=["health"])

HEALTH_TIMEOUT = 2.0


async def check_postgres() -> bool:
    """Return True if PostgreSQL accepts a connection and answers SELECT 1."""
    settings = get_settings()
    try:
        conn = await asyncpg.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            user=settings.postgres_user,
            password=settings.postgres_password,
            database=settings.postgres_db,
            timeout=HEALTH_TIMEOUT,
        )
        try:
            await conn.fetchval("SELECT 1")
        finally:
            await conn.close()
        return True
    except Exception:
        return False


async def check_redis() -> bool:
    """Return True if Redis answers a PING."""
    settings = get_settings()
    client = aioredis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        socket_timeout=HEALTH_TIMEOUT,
    )
    try:
        return bool(await client.ping())
    except Exception:
        return False
    finally:
        await client.aclose()


async def check_neo4j() -> bool:
    """Return True if the Neo4j driver can run a trivial query."""
    settings = get_settings()
    driver = AsyncGraphDatabase.driver(
        f"bolt://{settings.neo4j_host}:{settings.neo4j_port}",
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    try:
        async with driver.session() as session:
            await session.run("RETURN 1")
        return True
    except Exception:
        return False
    finally:
        await driver.close()


@router.get("/api/health")
async def health(response: Response) -> dict:
    """Report backend and dependency health; degraded dependencies yield 503."""
    checks = {
        "postgres": await check_postgres(),
        "redis": await check_redis(),
        "neo4j": await check_neo4j(),
    }
    healthy = all(checks.values())
    response.status_code = 200 if healthy else 503
    return {"status": "ok" if healthy else "degraded", "checks": checks}

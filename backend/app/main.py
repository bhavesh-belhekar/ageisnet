"""AegisNet FastAPI application entry point.

The consumer background task (Phase 3 ingestion) is started on application
lifespan and shut down cleanly on SIGTERM/SIGINT.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from logging.config import dictConfig

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from app.api.alerts import router as alerts_router
from app.api.events import router as events_router
from app.api.health import router as health_router
from app.config.settings import get_settings
from app.consumers.event_consumer import consumer_loop
from app.db.postgres import DatabaseUnavailableError, create_pool, ensure_schema
from app.ws.alerts_ws import AlertHub
from app.ws.alerts_ws import router as ws_router

_LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)s %(name)s: %(message)s",
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "loggers": {
        "event_consumer": {"level": "INFO", "handlers": ["default"]},
        "postgres": {"level": "INFO", "handlers": ["default"]},
        "risk_scoring": {"level": "INFO", "handlers": ["default"]},
        "rule_engine": {"level": "INFO", "handlers": ["default"]},
        "ws.alerts_ws": {"level": "INFO", "handlers": ["default"]},
    },
}

dictConfig(_LOGGING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create pool, ensure schema, launch consumer.  Shutdown: clean up."""
    settings = get_settings()
    pool = await create_pool()
    await ensure_schema(pool)
    hub = AlertHub()
    app.state.pool = pool
    app.state.alert_hub = hub
    redis = aioredis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
    )
    task = asyncio.create_task(consumer_loop(redis, pool, hub))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await pool.close()
    await redis.aclose()


app = FastAPI(title="AegisNet Backend", version="0.1.0", lifespan=lifespan)

app.include_router(health_router)
app.include_router(alerts_router)
app.include_router(events_router)
app.include_router(ws_router)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Return HTTPException detail as the flat body (RULES.md §4.3 shape)."""
    return JSONResponse(status_code=exc.status_code, content=exc.detail)


@app.exception_handler(DatabaseUnavailableError)
async def db_unavailable_handler(request: Request, exc: DatabaseUnavailableError):
    """Map DB availability failures to a consistent 503 body (RULES.md §4.3)."""
    return JSONResponse(
        status_code=503,
        content={"error": "db_unavailable", "message": str(exc)},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    """Never leak internals to API responses (RULES.md §4.3)."""
    return JSONResponse(
        status_code=500,
        content={"error": "internal", "message": "Internal server error"},
    )

"""AegisNet FastAPI application entry point.

The consumer background task (Phase 3 ingestion) is started on application
lifespan and shut down cleanly on SIGTERM/SIGINT.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from logging.config import dictConfig

import redis.asyncio as aioredis
from fastapi import FastAPI

from app.api.health import router as health_router
from app.config.settings import get_settings
from app.consumers.event_consumer import consumer_loop
from app.db.postgres import create_pool, ensure_schema

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
    },
}

dictConfig(_LOGGING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create pool, ensure schema, launch consumer.  Shutdown: clean up."""
    settings = get_settings()
    pool = await create_pool()
    await ensure_schema(pool)
    redis = aioredis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
    )
    task = asyncio.create_task(consumer_loop(redis, pool))
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

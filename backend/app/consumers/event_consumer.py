"""Redis Streams consumer that drives the detection pipeline on every event.

Reads from ``events:raw`` via a consumer group, validates each event against
the frozen Pydantic schema, and persists to Postgres.

Error handling (RULES.md Section 4.3): one bad/malformed event never stops
the consumer loop — the event is logged at ERROR and processing continues.
Unprocessable events are left un-ACKed in the pending entry list for future
redelivery.
"""

from __future__ import annotations

import json
import logging
import traceback

import asyncpg
import redis.asyncio as aioredis

from app.db.postgres import save_event
from app.models.event import Event

logger = logging.getLogger("event_consumer")

STREAM = "events:raw"
GROUP = "aegisnet-detection"
CONSUMER = "backend-1"
BLOCK_MS = 5000
BATCH_SIZE = 10


async def _ensure_group(redis: aioredis.Redis) -> None:
    """Create the consumer group if it does not already exist."""
    try:
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("created consumer group %s on stream %s", GROUP, STREAM)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def _process_one(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    raw_id: bytes,
    fields: dict[bytes, bytes],
) -> None:
    """Validate, persist, and ACK a single stream message."""
    try:
        payload = json.loads(fields[b"event"])
        event = Event.model_validate(payload)
    except Exception:
        logger.error(
            "malformed event from stream id=%s, payload=%s\n%s",
            raw_id,
            fields.get(b"event", b"<missing>"),
            traceback.format_exc(),
        )
        return  # don't ACK — message stays in PEL for redelivery

    try:
        await save_event(pool, event.model_dump())
    except Exception:
        logger.error(
            "db persist failed for event_id=%s, payload=%s\n%s",
            event.event_id,
            json.dumps(payload, default=str),
            traceback.format_exc(),
        )
        return  # don't ACK — redeliver on next consumer start

    await redis.xack(STREAM, GROUP, raw_id)


async def consumer_loop(redis: aioredis.Redis, pool: asyncpg.Pool) -> None:
    """Main consumer loop.  Runs until cancelled."""
    await _ensure_group(redis)
    logger.info("consumer loop started — reading from %s", STREAM)

    # --- Phase 1: drain pending messages left by a previous run ---
    pending = True
    while pending:
        results = await redis.xreadgroup(
            GROUP,
            CONSUMER,
            streams={STREAM: "0"},
            count=BATCH_SIZE,
        )
        if not results:
            break
        stream_messages = results[0][1]
        for raw_id, fields in stream_messages:
            await _process_one(redis, pool, raw_id, fields)
        pending = bool(stream_messages)

    logger.info("pending drain complete — switching to live stream")

    # --- Phase 2: read new messages ---
    while True:
        results = await redis.xreadgroup(
            GROUP,
            CONSUMER,
            streams={STREAM: ">"},
            count=BATCH_SIZE,
            block=BLOCK_MS,
        )
        if not results:
            continue
        stream_messages = results[0][1]
        for raw_id, fields in stream_messages:
            await _process_one(redis, pool, raw_id, fields)

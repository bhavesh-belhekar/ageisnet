"""Redis Streams consumer that drives the detection pipeline on every event.

Reads from ``events:raw`` via a consumer group, validates each event against
the frozen Pydantic schema, persists to Postgres, and ACKs on success.

After persistence, each event is handed to the rule engine; generated alerts
are persisted to ``raw_alerts``.

Error handling (RULES.md Section 4.3): one bad/malformed event never stops
the consumer loop — the event is logged at ERROR and processing continues.
Unprocessable events are left un-ACKed in the pending entry list.  Events that
exceed ``MAX_DELIVERIES`` delivery attempts are dead-lettered to
``events:deadletter`` and ACKed, preventing an infinite retry loop.
"""

from __future__ import annotations

import json
import logging
import traceback

import asyncpg
import redis.asyncio as aioredis

from app.db.postgres import save_alert, save_event
from app.models.event import Event
from app.risk_scoring.scorer import RiskScorer
from app.rule_engine.engine import RuleEngine
from app.ws.alerts_ws import AlertHub

logger = logging.getLogger("event_consumer")

STREAM = "events:raw"
GROUP = "aegisnet-detection"
CONSUMER = "backend-1"
DEAD_LETTER = "events:deadletter"
BLOCK_MS = 5000
BATCH_SIZE = 10
MAX_DELIVERIES = 5

_engine: RuleEngine | None = None
_scorer: RiskScorer | None = None


def _get_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine


def _get_scorer() -> RiskScorer:
    global _scorer
    if _scorer is None:
        _scorer = RiskScorer()
    return _scorer


async def _ensure_group(redis: aioredis.Redis) -> None:
    """Create the consumer group if it does not already exist."""
    try:
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("created consumer group %s on stream %s", GROUP, STREAM)
    except aioredis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def _sweep_dead_letters(redis: aioredis.Redis) -> None:
    """Move PEL messages exceeding MAX_DELIVERIES to the dead-letter stream."""
    try:
        plist = await redis.xpending(STREAM, GROUP)
    except aioredis.ResponseError:
        return
    if not plist or plist.get("pending", 0) == 0:
        return
    total_pending = plist["pending"]
    if not total_pending:
        return

    page = await redis.xpending_range(STREAM, GROUP, min="-", max="+", count=100)
    dead = [m for m in page if m["times_delivered"] >= MAX_DELIVERIES]
    for entry in dead:
        raw_id = entry["message_id"]
        try:
            data = await redis.xrange(STREAM, min=raw_id, max=raw_id)
            fields = data[0][1] if data else None
        except (IndexError, aioredis.ResponseError):
            fields = None
        # Move: write to dead-letter, then ACK (removes from PEL)
        await redis.xadd(
            DEAD_LETTER,
            {
                "event": (
                    fields.get(b"event", b"<payload-unavailable>")
                    if fields
                    else b"<payload-unavailable>"
                ),
                "deliveries": entry["times_delivered"],
                "last_delivered_by": entry["consumer"],
                "dead_letter_reason": "max_deliveries_exceeded",
            },
        )
        await redis.xack(STREAM, GROUP, raw_id)
        logger.critical(
            "dead-lettered event stream_id=%s after %d deliveries " "(consumer=%s) — moving to %s",
            raw_id,
            entry["times_delivered"],
            entry["consumer"],
            DEAD_LETTER,
        )


async def _run_rules(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    event: Event,
    hub: AlertHub | None = None,
) -> None:
    """Evaluate the event against the rule engine; persist any alerts.

    Persist+push pipeline per event (FR-6 / FR-7.1 / FR-7.2):
    1. rule engine produces the signal alerts for this event
    2. risk scoring combines them into a single severity label per event,
       which overrides each alert's own severity
    3. every alert is persisted (rule hit -> audit record, regardless of
       severity)
    4. each persisted alert is fanned out to WebSocket subscribers (only
       Medium+ actually leave the hub, FR-7.2)
    """
    try:
        alerts = _get_engine().evaluate(event)
    except Exception:
        logger.error(
            "rule engine failed for event_id=%s\n%s", event.event_id, traceback.format_exc()
        )
        return  # event already persisted — rule failure is non-fatal

    if not alerts:
        return

    combined = _get_scorer().score(
        [{"kind": "rule", "severity": alert.severity.value} for alert in alerts]
    )
    for alert in alerts:
        try:
            alert.severity = combined
            alert_id = await save_alert(pool, alert.model_dump())
            logger.info(
                "alert %s persisted: event_id=%s mitre=%s container=%s severity=%s",
                alert_id,
                event.event_id,
                alert.mitre_technique_id,
                alert.container_id,
                combined.value,
            )
            if hub is not None:
                payload = alert.model_dump(mode="json")
                payload["alert_id"] = alert_id
                await hub.publish(payload)
        except Exception:
            logger.error(
                "alert persist failed for event_id=%s\n%s", event.event_id, traceback.format_exc()
            )


async def _process_one(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    raw_id: bytes,
    fields: dict[bytes, bytes],
    hub: AlertHub | None = None,
) -> None:
    """Validate, persist, evaluate rules, and ACK a single stream message."""
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

    await _run_rules(redis, pool, event, hub)

    await redis.xack(STREAM, GROUP, raw_id)


async def consumer_loop(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    hub: AlertHub | None = None,
) -> None:
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
            await _process_one(redis, pool, raw_id, fields, hub)
        pending = bool(stream_messages)

    # --- Phase 1b: sweep dead letters (after first drain) ---
    await _sweep_dead_letters(redis)

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
            await _process_one(redis, pool, raw_id, fields, hub)
        await _sweep_dead_letters(redis)

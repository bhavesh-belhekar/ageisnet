"""Redis Streams consumer that drives the detection pipeline on every event.

Reads from ``events:raw`` via a consumer group, validates each event against
the frozen Pydantic schema, persists to Postgres, and ACKs on success.

After persistence, each event is handed to the rule engine AND the ML
engine in sequence; generated alerts are persisted to ``raw_alerts``.

Error handling (RULES.md Section 4.3): one bad/malformed event never stops
the consumer loop — the event is logged at ERROR and processing continues.
Unprocessable events are left un-ACKed in the pending entry list.  Events that
exceed ``MAX_DELIVERIES`` delivery attempts are dead-lettered to
``events:deadletter`` and ACKed, preventing an infinite retry loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import traceback

import asyncpg
import redis.asyncio as aioredis

from app.db.postgres import save_alert, save_event, update_alert_shap
from app.models.alert import Alert, DetectionType, Severity
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

# Bound concurrent SHAP computations to prevent event-loop overload (FR-11.2)
_SHAP_SEMAPHORE = asyncio.Semaphore(5)
_shap_queue: asyncio.Queue | None = None
_shap_workers_started = False


def _get_shap_queue() -> asyncio.Queue:
    """Return the singleton SHAP work queue (created on first call)."""
    global _shap_queue
    if _shap_queue is None:
        _shap_queue = asyncio.Queue(maxsize=100)
    return _shap_queue


async def _shap_worker(pool, hub):
    """Background worker that processes SHAP computation requests."""
    queue = _get_shap_queue()
    while True:
        item = await queue.get()
        try:
            await _compute_shap_inline(pool, hub, **item)
        except Exception:
            logger.error("SHAP worker failed\n%s", traceback.format_exc())
        finally:
            queue.task_done()


def _ensure_shap_workers(pool, hub):
    """Start SHAP worker tasks if not already running."""
    global _shap_workers_started
    if _shap_workers_started:
        return
    _shap_workers_started = True
    for i in range(3):
        asyncio.create_task(_shap_worker(pool, hub))
        logger.info("SHAP worker %d started", i)


# --- Lazy imports for ML (avoids circular / heavy imports at module load) ---


def _get_flow_inference():
    """Lazy-import the flow model inference module."""
    from app.ml_engine.flow_model import infer as flow_infer

    return flow_infer


def _get_graph_inference():
    """Lazy-import the graph model inference module."""
    from app.ml_engine.graph_model import infer as graph_infer

    return graph_infer


def _get_shap_explainer():
    """Lazy-import the SHAP explainability module."""
    from app.explainability import shap_explainer

    return shap_explainer


async def _compute_shap_inline(
    pool: asyncpg.Pool,
    hub: AlertHub | None,
    alert_id: int,
    event: Event,
    signal: dict,
    features: dict | None = None,
    scaled_vector: list[float] | None = None,
    detail: dict | None = None,
    baseline_size: int = 0,
) -> None:
    """Compute SHAP/rule-based explanation and attach to the alert.

    Runs inside a bounded worker (FR-11.2).
    """
    try:
        explainer = _get_shap_explainer()

        async with _SHAP_SEMAPHORE:
            if signal.get("kind") == "ml_flow" and features is not None and scaled_vector is not None:
                from app.ml_engine.flow_model.features import FEATURE_ORDER

                explanation = await explainer.explain_flow(
                    alert_id, FEATURE_ORDER, features, scaled_vector,
                )
            elif signal.get("kind") == "ml_graph" and detail is not None:
                explanation = await explainer.explain_graph(alert_id, detail, baseline_size)
            else:
                logger.debug("no explainer path for signal kind=%s — skipping", signal.get("kind"))
                return

            if explanation is None:
                logger.warning("explanation returned None for alert %d — skipping DB update", alert_id)
                return

            success = await update_alert_shap(pool, alert_id, explanation)
            if not success:
                return

            # Push WebSocket follow-up so the dashboard can populate the SHAP panel
            if hub is not None:
                try:
                    await hub.publish({
                        "alert_id": alert_id,
                        "event_id": event.event_id,
                        "shap_explanation": explanation,
                        "update_type": "shap_attachment",
                    })
                except Exception:
                    logger.warning("WebSocket follow-up push failed for alert %d", alert_id)

    except Exception:
        logger.error(
            "async SHAP computation failed for alert %d\n%s",
            alert_id,
            traceback.format_exc(),
        )


async def _compute_shap_async(
    pool: asyncpg.Pool,
    hub: AlertHub | None,
    alert_id: int,
    event: Event,
    signal: dict,
    features: dict | None = None,
    scaled_vector: list[float] | None = None,
    detail: dict | None = None,
    baseline_size: int = 0,
) -> None:
    """Enqueue SHAP computation for bounded async processing (FR-11.2).

    Instead of fire-and-forget create_task (which overwhelms the event loop
    at high alert rates), this enqueues work items for a fixed pool of
    background workers.
    """
    queue = _get_shap_queue()
    _ensure_shap_workers(pool, hub)
    try:
        queue.put_nowait({
            "alert_id": alert_id,
            "event": event,
            "signal": signal,
            "features": features,
            "scaled_vector": scaled_vector,
            "detail": detail,
            "baseline_size": baseline_size,
        })
    except asyncio.QueueFull:
        logger.warning("SHAP queue full — dropping SHAP for alert %d", alert_id)


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


async def _run_graph_ml(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    event: Event,
    hub: AlertHub | None = None,
) -> None:
    """Run graph-model anomaly scoring on internal events; persist any alerts.

    Only scores internal (east-west) events.  Flags new container-to-container
    edges that were not seen during the 24-hour baseline window (FR-2.2 / FR-5.2).
    """
    from app.models.event import Direction

    if event.direction != Direction.INTERNAL:
        return

    graph_infer = _get_graph_inference()
    try:
        signal = await graph_infer.score_graph_event(event)
    except Exception:
        logger.error(
            "graph model scoring failed for event_id=%s\n%s",
            event.event_id,
            traceback.format_exc(),
        )
        return

    if signal is None:
        return

    # The graph model returns score=1.0 for new edges (binary heuristic).
    # Check against the graph_new_edge_threshold from config.
    scorer = _get_scorer()
    threshold = scorer._ml_thresholds.get("graph_new_edge_threshold", 1.0)
    if signal["score"] < threshold:
        return

    # Build severity from graph signal alone
    combined = scorer.score([signal])

    # Map to MITRE technique (FR-12) — use specific technique for lateral movement
    detail = signal.get("detail", {})
    reason = detail.get("reason", "")
    mitre_id = _resolve_mitre("ml", "graph_lateral_movement")

    description = (
        f"New internal edge detected: {detail.get('src', '?')} → "
        f"{detail.get('dst', '?')}:{detail.get('port', '?')} "
        f"({reason})"
    )

    alert = Alert(
        event_id=event.event_id,
        container_id=event.container_id,
        timestamp=event.timestamp,
        detection_type=DetectionType.ML,
        severity=combined,
        mitre_technique_id=mitre_id,
        description=description,
        shap_explanation=None,
    )

    try:
        alert_id = await save_alert(pool, alert.model_dump())
        logger.info(
            "graph ML alert %s persisted: event_id=%s container=%s score=%.4f severity=%s",
            alert_id,
            event.event_id,
            event.container_id,
            signal["score"],
            combined.value,
        )
        if hub is not None:
            payload = alert.model_dump(mode="json")
            payload["alert_id"] = alert_id
            await hub.publish(payload)

        # Async explanation — fire-and-forget (FR-11.2)
        asyncio.create_task(
            _compute_shap_async(
                pool, hub, alert_id, event, signal,
                detail=detail,
                baseline_size=detail.get("baseline_size", 0),
            )
        )
    except Exception:
        logger.error(
            "graph ML alert persist failed for event_id=%s\n%s",
            event.event_id,
            traceback.format_exc(),
        )


async def _run_ml(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    event: Event,
    hub: AlertHub | None = None,
) -> None:
    """Run ML anomaly scoring on the event; persist any ML alerts.

    Runs in parallel logic to ``_run_rules`` but against the flow model.
    The ML signal is also fed into the risk scorer so that ML-only alerts
    get a proper severity label (FR-6).
    """
    flow_infer = _get_flow_inference()
    try:
        signal = await flow_infer.score_flow_event(redis, event)
    except Exception:
        logger.error(
            "flow model scoring failed for event_id=%s\n%s",
            event.event_id,
            traceback.format_exc(),
        )
        return

    if signal is None:
        logger.info(
            "flow model returned None for event_id=%s container=%s direction=%s",
            event.event_id, event.container_id, event.direction.value,
        )
        return

    # Check if the score crosses the anomaly threshold
    scorer = _get_scorer()
    threshold = scorer._ml_thresholds.get("flow_model_anomaly_threshold", 0.6)
    logger.info(
        "flow model score=%.4f threshold=%.2f event_id=%s",
        signal["score"], threshold, event.event_id,
    )
    if signal["score"] < threshold:
        logger.debug(
            "flow model score %.4f below threshold %.2f for event_id=%s — no alert",
            signal["score"],
            threshold,
            event.event_id,
        )
        return

    # Build severity from ML signal alone (no rule hits mixed here)
    combined = scorer.score([signal])

    # Map to MITRE technique (FR-12)
    mitre_id = _resolve_mitre("ml", "ml_flow_anomaly")

    description = (
        f"Flow anomaly detected: score={signal['score']:.4f} "
        f"(threshold={threshold:.2f})"
    )

    alert = Alert(
        event_id=event.event_id,
        container_id=event.container_id,
        timestamp=event.timestamp,
        detection_type=DetectionType.ML,
        severity=combined,
        mitre_technique_id=mitre_id,
        description=description,
        shap_explanation=None,  # Phase 5: computed asynchronously
    )

    try:
        alert_id = await save_alert(pool, alert.model_dump())
        logger.info(
            "ML alert %s persisted: event_id=%s container=%s score=%.4f severity=%s",
            alert_id,
            event.event_id,
            event.container_id,
            signal["score"],
            combined.value,
        )
        if hub is not None:
            payload = alert.model_dump(mode="json")
            payload["alert_id"] = alert_id
            await hub.publish(payload)

        # Async SHAP — fire-and-forget after alert is visible on dashboard (FR-11.2)
        asyncio.create_task(
            _compute_shap_async(
                pool, hub, alert_id, event, signal,
                features=signal.get("features"),
                scaled_vector=signal.get("scaled_vector"),
            )
        )
    except Exception:
        logger.error(
            "ML alert persist failed for event_id=%s\n%s",
            event.event_id,
            traceback.format_exc(),
        )


def _resolve_mitre(detection_category: str, specific_type: str) -> str | None:
    """Look up the MITRE ATT&CK technique ID for a detection type."""
    try:
        from pathlib import Path

        import yaml

        config_path = (
            Path(__file__).resolve().parents[1] / "config" / "mitre_mapping.yaml"
        )
        with open(config_path) as f:
            mapping = yaml.safe_load(f)

        # Try specific type first, fall back to category-level
        techniques = mapping.get("detection_type_to_technique", {})
        return techniques.get(detection_category, {}).get(
            specific_type, techniques.get("fallback", {}).get(specific_type)
        )
    except Exception:
        logger.warning("MITRE lookup failed for %s/%s", detection_category, specific_type)
        return None


async def _process_one(
    redis: aioredis.Redis,
    pool: asyncpg.Pool,
    raw_id: bytes,
    fields: dict[bytes, bytes],
    hub: AlertHub | None = None,
) -> None:
    """Validate, persist, evaluate rules, and ACK a single stream message."""
    # --- Detection latency measurement (NFR: <2s) ---
    # Redis stream ID format: <millisecondsTime>-<sequenceNumber>
    try:
        stream_ms = int(raw_id.decode().split(b"-")[0])
        stream_ts = stream_ms / 1000.0
    except Exception:
        stream_ts = time.time()  # fallback to wall clock

    t_start = time.monotonic()

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

    t_after_validate = time.monotonic()

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

    t_after_save = time.monotonic()
    await _run_rules(redis, pool, event, hub)
    t_after_rules = time.monotonic()
    await _run_ml(redis, pool, event, hub)
    t_after_ml = time.monotonic()
    await _run_graph_ml(redis, pool, event, hub)
    t_after_graph = time.monotonic()

    await redis.xack(STREAM, GROUP, raw_id)

    # --- Log detection latency ---
    wall_now = time.time()
    e2e_latency_ms = (wall_now - stream_ts) * 1000
    pipeline_ms = (t_after_graph - t_start) * 1000
    logger.info(
        "detection_latency event_id=%s e2e=%.1fms pipeline=%.1fms "
        "(validate=%.1f save=%.1f rules=%.1f ml=%.1f graph=%.1f)",
        event.event_id,
        e2e_latency_ms,
        pipeline_ms,
        (t_after_validate - t_start) * 1000,
        (t_after_save - t_after_validate) * 1000,
        (t_after_rules - t_after_save) * 1000,
        (t_after_ml - t_after_rules) * 1000,
        (t_after_graph - t_after_ml) * 1000,
    )


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

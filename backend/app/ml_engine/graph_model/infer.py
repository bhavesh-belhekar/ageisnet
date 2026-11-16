"""Graph-model inference — score an internal event against the baseline.

Wraps :class:`GraphDiffDetector` for use by the event consumer.  Only
internal (east-west) events are scored; external events return ``None``.

Usage (called by ``event_consumer._run_graph_ml()``)::

    signal = await score_graph_event(event)
    # signal is {\"kind\": \"ml_graph\", \"score\": 1.0, \"detail\": {...},
    #            \"lateral_signals\": [...]} or None

The base score is ``1.0`` for a new edge (binary heuristic, per FR-5.2) and
``0.0`` for a known edge.  The risk scorer combines this with other signals to
produce a severity label (FR-6).

``lateral_signals`` carries zero or more additional anomaly dicts from
:class:`~app.ml_engine.graph_model.lateral_movement.LateralMovementDetector`:

* ``{\"kind\": \"graph_sensitive_port\", ...}`` — new edge to a sensitive service
* ``{\"kind\": \"graph_lateral_path\", ...}`` — two-hop lateral movement chain
"""

from __future__ import annotations

import logging
import traceback

from app.db.neo4j_client import get_graph_client
from app.ml_engine.graph_model.graph_diff import GraphDiffDetector
from app.ml_engine.graph_model.lateral_movement import LateralMovementDetector

logger = logging.getLogger("graph_model.infer")

# Server-side event mirrors carry the client's ephemeral port as dst_port
# (e.g., postgres seeing a client connect from 58230).  These change every
# connection and must not be treated as distinct edges.  Matches the
# EPHEMERAL_PORT_MIN filter used by RULE-003 in rule_engine/engine.py.
EPHEMERAL_PORT_MIN = 32768

_detector: GraphDiffDetector | None = None
_lateral_detector: LateralMovementDetector | None = None
_init_failed = False


async def _ensure_detector() -> GraphDiffDetector | None:
    """Lazily initialise the detector and load the baseline."""
    global _detector, _lateral_detector, _init_failed

    if _init_failed:
        return None
    if _detector is not None and _detector.is_loaded:
        return _detector

    try:
        client = get_graph_client()
        if not client.is_connected:
            await client.connect()

        _detector = GraphDiffDetector()
        count = await _detector.load_baseline()
        _lateral_detector = LateralMovementDetector()
        logger.info("graph model ready — baseline contains %d edges", count)
        return _detector
    except Exception:
        _init_failed = True
        logger.critical("graph model init failed\n%s", traceback.format_exc())
        return None


async def score_graph_event(event) -> dict | None:
    """Score an internal event against the graph baseline.

    Returns:
        A dict with keys ``kind``, ``score``, ``detail``, and
        ``lateral_signals`` if the edge is new (anomalous), or ``None`` if
        the edge is already known or on error.

        ``lateral_signals`` is a list (possibly empty) of additional anomaly
        dicts from :class:`LateralMovementDetector`.

    Only internal (east-west) events are scored.
    """
    from app.models.event import Direction

    if event.direction != Direction.INTERNAL:
        return None

    detector = await _ensure_detector()
    if detector is None:
        return None

    try:
        # For internal events the source container is the event's container_id.
        # The destination container is derived from the dst_ip — for internal
        # traffic the dst_ip resolves to another container's IP.  The loader
        # attributes the event to the socket-owner, so src = container_id,
        # dst is resolved by the caller or left as dst_ip for now.
        #
        # In the eBPF pipeline the loader sets dst_ip to the peer's IP; we
        # use it directly as a container proxy for the heuristic detector.
        # A proper netns → container_id lookup on the dst side is a future
        # improvement (not needed for the heuristic graph-diff).
        src = event.container_id
        dst = event.dst_ip  # proxy for destination container
        port = event.dst_port

        # Skip server-side event mirrors: dst_port is the client's ephemeral
        # port, not a real service port.  These change every connection and
        # would generate false "new edge" alerts.
        if port >= EPHEMERAL_PORT_MIN:
            return None

        result = detector.check_edge(src, dst, port)
        if result is not None:
            # Record the edge so it is not re-flagged on the next connection
            detector.record_edge(src, dst, port)
            # Also persist to Neo4j / local cache
            client = get_graph_client()
            await client.merge_edge(src, dst, port, event.protocol)
            await client.mark_edge_anomalous(src, dst, port)

            logger.info(
                "graph anomaly: %s → %s:%d (baseline had %d edges)",
                src, dst, port, result["baseline_size"],
            )

            # Run lateral movement / sensitive-port heuristics on the new edge
            lateral_signals: list[dict] = []
            if _lateral_detector is not None:
                ts = None
                if hasattr(event, "timestamp") and event.timestamp is not None:
                    try:
                        ts = event.timestamp.timestamp()
                    except Exception:
                        ts = None
                lateral_signals = _lateral_detector.record_new_edge(
                    src, dst, port, timestamp=ts
                )

            return {
                "kind": "ml_graph",
                "score": 1.0,
                "detail": result,
                "lateral_signals": lateral_signals,
            }

        # Known edge — still update last_seen in the graph
        client = get_graph_client()
        await client.merge_edge(src, dst, port, event.protocol)
        return None

    except Exception:
        logger.error(
            "graph scoring failed for event_id=%s\n%s",
            event.event_id,
            traceback.format_exc(),
        )
        return None

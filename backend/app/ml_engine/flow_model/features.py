"""Flow-model feature extraction from the Redis stream (on-the-fly).

For a given container, reads the last N minutes of external events from
the ``events:raw`` Redis stream and aggregates them into the 6-feature
vector the Isolation Forest expects:

    total_bytes_sent, total_bytes_received, connection_count,
    unique_dst_ports, unique_dst_ips, window_seconds

Window size is read from ``risk_policy.yaml`` →
``windows.flow_model_feature_minutes`` (default 5).

Usage (called by the inference path in ``infer.py``)::

    features = extract_flow_features(redis_client, container_id="abc123")
    # → {"total_bytes_sent": 3200, "total_bytes_received": 2900, ...}
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import redis.asyncio as aioredis
import yaml

logger = logging.getLogger("flow_model.features")

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "app" / "config" / "risk_policy.yaml"

STREAM_KEY = "events:raw"


@lru_cache
def _window_minutes() -> int:
    """Return the feature-window size in minutes from config."""
    with open(_CONFIG_PATH) as f:
        policy = yaml.safe_load(f)
    return policy.get("windows", {}).get("flow_model_feature_minutes", 5)


def _parse_event(raw: bytes | str) -> dict | None:
    """Parse a single event payload from the stream.  Returns None on failure."""
    try:
        if isinstance(raw, bytes):
            raw = raw.decode()
        payload = json.loads(raw)
        # The stream wraps the event in an "event" key
        if "event" in payload and isinstance(payload["event"], str):
            return json.loads(payload["event"])
        return payload
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


async def extract_flow_features(
    redis: aioredis.Redis,
    container_id: str,
    window_minutes: int | None = None,
) -> dict | None:
    """Extract flow-model features for *container_id* from the last N minutes.

    Returns a dict of the 6 features, or ``None`` if fewer than 2 events
    fall within the window (not enough data to form a meaningful aggregate).
    """
    if window_minutes is None:
        window_minutes = _window_minutes()

    now = time.time()
    window_start = now - (window_minutes * 60)

    # Read the last 2000 stream IDs (IDs are millisecond timestamps).
    # For a 5-minute window this is more than sufficient; if the stream
    # is much larger we'd switch to XRANGE with a time-based min, but
    # 2000 is a safe bound for demo-scale traffic.
    stream_min = f"{int(window_start * 1000)}-0"
    try:
        entries = await redis.xrevrange(
            STREAM_KEY, count=2000
        )
    except aioredis.ResponseError:
        logger.warning("failed to read stream %s", STREAM_KEY)
        return None

    # Filter to: correct container, external direction, within window
    bytes_sent = 0
    bytes_received = 0
    connection_count = 0
    dst_ports: set[int] = set()
    dst_ips: set[str] = set()
    timestamps: list[float] = []

    for entry_id, fields in entries:
        # Stream ID is millisecond timestamp — compare directly
        try:
            ts_ms = int(entry_id.split(b"-")[0])
        except (ValueError, IndexError):
            continue
        ts_s = ts_ms / 1000.0
        if ts_s < window_start:
            continue  # older than our window (stream is reverse-ordered)

        event = _parse_event(fields.get(b"event", b""))
        if event is None:
            continue
        if event.get("container_id") != container_id:
            continue
        if event.get("direction") != "external":
            continue

        bytes_sent += event.get("bytes_sent", 0)
        bytes_received += event.get("bytes_received", 0)
        if event.get("event_type") == "close":
            connection_count += 1
        dst_ports.add(event.get("dst_port", 0))
        dst_ips.add(event.get("dst_ip", ""))
        timestamps.append(ts_s)

    if len(timestamps) < 2:
        return None

    window_span = max(timestamps[-1] - timestamps[0], 1.0) if len(timestamps) >= 2 else float(window_minutes * 60)

    return {
        "total_bytes_sent": bytes_sent,
        "total_bytes_received": bytes_received,
        "connection_count": connection_count,
        "unique_dst_ports": len(dst_ports),
        "unique_dst_ips": len(dst_ips),
        "window_seconds": round(window_span, 2),
    }


FEATURE_ORDER = [
    "total_bytes_sent",
    "total_bytes_received",
    "connection_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "window_seconds",
]


def features_to_vector(features: dict) -> list[float]:
    """Convert a features dict to the ordered list the model expects."""
    return [float(features[k]) for k in FEATURE_ORDER]

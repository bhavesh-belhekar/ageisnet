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
from functools import lru_cache
from pathlib import Path

import numpy as np
import redis.asyncio as aioredis
import yaml

logger = logging.getLogger("flow_model.features")

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "app" / "config" / "risk_policy.yaml"

STREAM_KEY = "events:raw"

FEATURE_ORDER = [
    "total_bytes_sent",
    "total_bytes_received",
    "connection_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "window_seconds",
]

# Features that represent outbound/inbound data transfer volumes.
# These must NEVER be clamped during live inference or validation,
# because clamping massive byte transfers to baseline percentiles (e.g. 99th)
# would artificially normalize data exfiltration attacks and hide them from the model.
UNRESTRICTED_TRANSFER_FEATURES = {"total_bytes_sent", "total_bytes_received"}


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
    window_start_ms = int(window_start * 1000)
    min_stream_id = f"{window_start_ms}-0"

    # Paginated, time-bounded stream retrieval
    PAGE_SIZE = 1000
    MAX_PAGES = 10  # Ceiling: 10,000 entries (approx. 33.3 events/sec across cluster)
    entries: list[tuple[bytes, dict]] = []
    current_max = "+"
    truncated = False

    try:
        for page_idx in range(MAX_PAGES):
            page = await redis.xrevrange(
                STREAM_KEY,
                max=current_max,
                min=min_stream_id,
                count=PAGE_SIZE,
            )
            if not page:
                break
            entries.extend(page)
            if len(page) < PAGE_SIZE:
                # Reached end of time range
                break

            last_entry_id = page[-1][0]
            last_id_str = last_entry_id.decode() if isinstance(last_entry_id, bytes) else str(last_entry_id)
            current_max = f"({last_id_str}"

            # If this is the last allowed page and it was completely full,
            # probe if there are remaining entries beyond the 10,000 ceiling.
            if page_idx == MAX_PAGES - 1:
                probe = await redis.xrevrange(
                    STREAM_KEY,
                    max=current_max,
                    min=min_stream_id,
                    count=1,
                )
                if probe:
                    truncated = True
    except aioredis.ResponseError:
        logger.warning("failed to read stream %s", STREAM_KEY)
        return None

    if truncated:
        logger.warning(
            "stream retrieval for container=%s exceeded safety ceiling of %d entries; "
            "window incomplete — aborting feature extraction to prevent corrupted ML scoring",
            container_id,
            PAGE_SIZE * MAX_PAGES,
        )
        return None

    # Filter to: correct container, external direction, within window
    bytes_sent = 0
    bytes_received = 0
    connection_count = 0
    dst_ports: set[int] = set()
    dst_ips: set[str] = set()
    timestamps: list[float] = []

    for entry_id, fields in entries:
        event = _parse_event(fields.get(b"event", b""))
        if event is None:
            continue
        if event.get("container_id") != container_id:
            continue
        if event.get("direction") != "external":
            continue

        # Check payload timestamp for delayed arrivals
        event_ts = None
        if "timestamp" in event:
            try:
                raw_ts = event["timestamp"]
                if isinstance(raw_ts, (int, float)):
                    event_ts = float(raw_ts)
                else:
                    from datetime import datetime
                    event_ts = datetime.fromisoformat(str(raw_ts)).timestamp()
            except Exception:
                event_ts = None

        if event_ts is not None:
            if event_ts < window_start:
                continue
            effective_ts = event_ts
        else:
            try:
                ts_ms = int(entry_id.split(b"-")[0])
                effective_ts = ts_ms / 1000.0
            except (ValueError, IndexError):
                continue
            if effective_ts < window_start:
                continue

        bytes_sent += event.get("bytes_sent", 0)
        bytes_received += event.get("bytes_received", 0)
        if event.get("event_type") == "close":
            connection_count += 1
        dst_ports.add(event.get("dst_port", 0))
        dst_ips.add(event.get("dst_ip", ""))
        timestamps.append(effective_ts)

    if len(timestamps) < 2:
        return None

    window_span = max(max(timestamps) - min(timestamps), 1.0)

    return {
        "total_bytes_sent": bytes_sent,
        "total_bytes_received": bytes_received,
        "connection_count": connection_count,
        "unique_dst_ports": len(dst_ports),
        "unique_dst_ips": len(dst_ips),
        "window_seconds": round(window_span, 2),
    }


def features_to_vector(
    features: dict,
    feature_order: list[str] | None = None,
) -> list[float]:
    """Convert a features dict to the ordered list the model expects.

    If feature_order is provided, uses that order to ensure strict consistency
    with the model artifact's trained feature ordering.
    """
    order = feature_order or FEATURE_ORDER
    return [float(features[k]) for k in order]


def preprocess_features(
    data: dict | list[float] | np.ndarray,
    scaler,
    feature_names: list[str] | None = None,
    cap_values: dict[str, float] | np.ndarray | None = None,
    cap_exclude: list[str] | set[str] | None = None,
    apply_caps: bool = False,
) -> tuple[np.ndarray, np.ndarray]:
    """Preprocess flow features consistently across training, validation, and inference.

    Args:
        data: Feature dict, 1D vector, or 2D feature matrix.
        scaler: Fitted StandardScaler instance with transform().
        feature_names: Ordered list of feature names expected by the model.
        cap_values: Optional per-feature cap thresholds from training.
        cap_exclude: Feature names excluded from capping.
        apply_caps: Whether to apply capping. If True, byte-transfer features
            ('total_bytes_sent', 'total_bytes_received') are strictly EXCLUDED
            from capping so that massive outbound data transfers (data exfiltration)
            remain detectable as extreme anomalies.

    Returns:
        (unscaled_matrix, scaled_matrix) as 2D float64 numpy arrays of shape (N, 6).
    """
    expected_order = feature_names or FEATURE_ORDER

    if isinstance(data, dict):
        matrix = np.array([[float(data[k]) for k in expected_order]], dtype=np.float64)
    elif isinstance(data, list):
        matrix = np.array([data], dtype=np.float64)
    elif isinstance(data, np.ndarray):
        matrix = np.array(data, dtype=np.float64, copy=True)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)
    else:
        raise TypeError(f"Unsupported data type for flow feature preprocessing: {type(data)}")

    if matrix.shape[1] != len(expected_order):
        raise ValueError(
            f"Feature count mismatch: expected {len(expected_order)} features ({expected_order}), "
            f"got {matrix.shape[1]}"
        )

    if apply_caps and cap_values is not None:
        exclude_set = set(cap_exclude or []) | UNRESTRICTED_TRANSFER_FEATURES
        if isinstance(cap_values, dict):
            cap_arr = np.array([float(cap_values.get(k, np.inf)) for k in expected_order])
        else:
            cap_arr = np.array(cap_values, dtype=np.float64)

        for i, name in enumerate(expected_order):
            if name not in exclude_set and i < len(cap_arr):
                matrix[:, i] = np.minimum(matrix[:, i], cap_arr[i])

    scaled = scaler.transform(matrix)
    return matrix, scaled

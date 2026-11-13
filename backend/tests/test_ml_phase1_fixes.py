"""Tests for Phase 1 ML Engine Fixes.

Covers:
1. Chronological splitting via production split_chronological().
2. Raising ValueError when unique timestamps < 2.
3. Dropping sparse (< 2 events) single-event windows in _aggregate().
4. Path resolution parity on host and environment overrides with module reloading.
5. Redis cursor pagination with exclusive max and inclusive min boundaries: no duplicates or skips.
6. Exact 10,000 entries accepted without truncation.
7. Over-10,000 entries ceiling detection, warning logging, and graceful abort (None).
8. Late-arriving event filtering by inner payload timestamp.
9. Mid-pagination new event arrival isolation (excluded in pass 1, included in pass 2).
10. Application-level SHAP artifact loading via app.explainability.shap_explainer._ensure_explainer().
"""

from __future__ import annotations

import importlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, mock_open, patch

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ---------------------------------------------------------------------------
# 1. Chronological Dataset Splitting Tests
# ---------------------------------------------------------------------------


def test_production_split_chronological_ordering():
    """Verify production split_chronological enforces train timestamps < val timestamps."""
    from scripts.collect_baseline import split_chronological

    rows = []
    for i in range(10):
        # 10 distinct 5-minute windows
        ts = f"2026-11-13T10:{i*5:02d}:00+00:00"
        rows.append({"container_id": "c1", "window_start": ts, "total_bytes_sent": 100})

    train_rows, val_rows = split_chronological(rows, train_ratio=0.8)

    assert len(train_rows) == 8
    assert len(val_rows) == 2
    assert max(r["window_start"] for r in train_rows) < min(r["window_start"] for r in val_rows)


def test_production_split_chronological_rejects_insufficient_timestamps():
    """Verify split_chronological raises ValueError when unique timestamps < 2."""
    from scripts.collect_baseline import split_chronological

    # All rows share the same window_start timestamp
    rows = [
        {"container_id": f"c{i}", "window_start": "2026-11-13T10:00:00+00:00"}
        for i in range(5)
    ]

    with pytest.raises(ValueError, match="Chronological validation requires at least 2 distinct timestamps"):
        split_chronological(rows, train_ratio=0.8)


# ---------------------------------------------------------------------------
# 2. Single-Event Window Filtering in _aggregate()
# ---------------------------------------------------------------------------


def test_aggregate_drops_single_event_windows():
    """Verify _aggregate drops windows with < 2 events and computes max - min span."""
    from scripts.collect_baseline import _aggregate

    t_base = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    t_ev1 = datetime.fromtimestamp(t_base.timestamp() + 5, tz=timezone.utc)
    t_ev2 = datetime.fromtimestamp(t_base.timestamp() + 25, tz=timezone.utc)

    events = [
        # Container A: 1 event -> must be dropped
        {"container_id": "cA", "timestamp": t_ev1, "event_type": "open", "dst_ip": "1.1.1.1", "dst_port": 80, "bytes_sent": 10, "bytes_received": 10},
        # Container B: 2 events -> kept with span = 20.0s
        {"container_id": "cB", "timestamp": t_ev1, "event_type": "open", "dst_ip": "1.1.1.1", "dst_port": 80, "bytes_sent": 10, "bytes_received": 10},
        {"container_id": "cB", "timestamp": t_ev2, "event_type": "close", "dst_ip": "1.1.1.1", "dst_port": 80, "bytes_sent": 20, "bytes_received": 20},
    ]

    rows = _aggregate(events)
    assert len(rows) == 1
    assert rows[0]["container_id"] == "cB"
    assert rows[0]["window_seconds"] == 20.0


# ---------------------------------------------------------------------------
# 3. Path Resolution Parity (Host & Environment Overrides)
# ---------------------------------------------------------------------------


def test_artifact_and_baseline_paths_parity(monkeypatch):
    """Verify ARTIFACT_PATH, TRAIN_CSV, and VAL_CSV resolve identically across train & infer."""
    import app.ml_engine.flow_model.infer as infer_mod
    import app.ml_engine.flow_model.train as train_mod

    # 1. Host Mode (no environment variables set)
    monkeypatch.delenv("MODEL_ARTIFACT_DIR", raising=False)
    monkeypatch.delenv("TRAINING_BASELINE_DIR", raising=False)
    importlib.reload(infer_mod)
    importlib.reload(train_mod)

    repo_root = Path(train_mod.__file__).resolve().parents[4]
    expected_artifact = repo_root / "data" / "model_artifacts" / "flow_model_v2.pkl"
    expected_train_csv = repo_root / "data" / "training_baselines" / "normal_baseline_train.csv"
    expected_val_csv = repo_root / "data" / "training_baselines" / "normal_baseline_val.csv"

    assert infer_mod.ARTIFACT_PATH == expected_artifact
    assert train_mod.ARTIFACT_PATH == expected_artifact
    assert train_mod.TRAIN_CSV == expected_train_csv
    assert train_mod.VAL_CSV == expected_val_csv

    # 2. Docker / Custom Override Mode
    monkeypatch.setenv("MODEL_ARTIFACT_DIR", "/custom/model_artifacts")
    monkeypatch.setenv("TRAINING_BASELINE_DIR", "/custom/training_baselines")
    importlib.reload(infer_mod)
    importlib.reload(train_mod)

    assert infer_mod.ARTIFACT_PATH == Path("/custom/model_artifacts/flow_model_v2.pkl")
    assert train_mod.ARTIFACT_PATH == Path("/custom/model_artifacts/flow_model_v2.pkl")
    assert train_mod.TRAIN_CSV == Path("/custom/training_baselines/normal_baseline_train.csv")
    assert train_mod.VAL_CSV == Path("/custom/training_baselines/normal_baseline_val.csv")


# ---------------------------------------------------------------------------
# 4. Redis Cursor Pagination, Exclusive Max & Inclusive Min Bounds
# ---------------------------------------------------------------------------


def _build_cursor_aware_redis_mock(stream_data: list[tuple[bytes, dict]], queries_log: list[str]):
    """Helper to mock Redis xrevrange honoring exclusive max cursor and inclusive min boundary."""
    mock_redis = AsyncMock()

    async def mock_xrevrange(key, max="+", min="-", count=1000):
        queries_log.append(max)

        min_bound = min.encode() if isinstance(min, str) and min != "-" else None

        eligible = []
        for item in stream_data:
            # Exclusive upper bound
            if max != "+":
                assert max.startswith("(")
                max_bound = max[1:].encode()
                if item[0] >= max_bound:
                    continue

            # Inclusive lower bound
            if min_bound is not None:
                if item[0] < min_bound:
                    continue

            eligible.append(item)

        return eligible[:count]

    mock_redis.xrevrange.side_effect = mock_xrevrange
    return mock_redis


@pytest.mark.asyncio
async def test_redis_pagination_exclusive_bounds_no_duplicates_or_skips():
    """Verify pagination passes exclusive bound '(' and processes all items without duplicates."""
    from app.ml_engine.flow_model.features import extract_flow_features

    now = datetime.now(timezone.utc).timestamp()
    cid = "cont_page_test"

    # Create 2,500 sequential entries with unique timestamps
    stream_data = []
    for i in range(2500):
        ts = now - 250 + (i * 0.1)
        eid = f"{int(ts * 1000)}-0".encode()
        payload = json.dumps({
            "container_id": cid,
            "direction": "external",
            "event_type": "close",
            "dst_ip": "1.1.1.1",
            "dst_port": 80,
            "bytes_sent": 1,
            "bytes_received": 1,
            "timestamp": ts,
        })
        stream_data.append((eid, {b"event": payload.encode()}))

    # Reverse order: newest first
    stream_data.reverse()

    received_queries: list[str] = []
    mock_redis = _build_cursor_aware_redis_mock(stream_data, received_queries)

    features = await extract_flow_features(mock_redis, cid, window_minutes=5)

    assert features is not None
    assert features["connection_count"] == 2500
    assert features["total_bytes_sent"] == 2500
    assert len(received_queries) == 3
    assert received_queries[0] == "+"
    assert received_queries[1].startswith("(")
    assert received_queries[2].startswith("(")


@pytest.mark.asyncio
async def test_redis_pagination_exactly_10000_events_succeeds():
    """Verify exactly 10,000 entries (10 full pages, probe returns empty) succeeds without duplicates."""
    from app.ml_engine.flow_model.features import extract_flow_features

    now = datetime.now(timezone.utc).timestamp()
    cid = "cont_10k_test"

    # Exactly 10,000 distinct entries spanning 200 seconds
    stream_data = []
    for i in range(10000):
        ts = now - 200 + (i * 0.02)
        eid = f"{int(ts * 1000)}-{i}".encode()
        payload = json.dumps({
            "container_id": cid,
            "direction": "external",
            "event_type": "close",
            "dst_ip": "1.1.1.1",
            "dst_port": 80,
            "bytes_sent": 1,
            "bytes_received": 1,
            "timestamp": ts,
        })
        stream_data.append((eid, {b"event": payload.encode()}))

    stream_data.reverse()

    received_queries: list[str] = []
    mock_redis = _build_cursor_aware_redis_mock(stream_data, received_queries)

    features = await extract_flow_features(mock_redis, cid, window_minutes=5)

    assert features is not None
    assert features["connection_count"] == 10000
    assert features["total_bytes_sent"] == 10000
    # 10 full pages + 1 probe query
    assert len(received_queries) == 11


@pytest.mark.asyncio
async def test_redis_pagination_over_10000_events_triggers_ceiling_and_aborts(caplog):
    """Verify > 10,000 entries causes the probe to detect truncation, returning None and logging a warning."""
    from app.ml_engine.flow_model.features import extract_flow_features

    now = datetime.now(timezone.utc).timestamp()
    cid = "cont_overflow_test"

    # 10,050 distinct entries (50 entries beyond the 10,000 ceiling)
    stream_data = []
    for i in range(10050):
        ts = now - 200 + (i * 0.015)
        eid = f"{int(ts * 1000)}-{i}".encode()
        payload = json.dumps({
            "container_id": cid,
            "direction": "external",
            "event_type": "close",
            "dst_ip": "1.1.1.1",
            "dst_port": 80,
            "bytes_sent": 1,
            "bytes_received": 1,
            "timestamp": ts,
        })
        stream_data.append((eid, {b"event": payload.encode()}))

    stream_data.reverse()

    received_queries: list[str] = []
    mock_redis = _build_cursor_aware_redis_mock(stream_data, received_queries)

    with caplog.at_level(logging.WARNING):
        features = await extract_flow_features(mock_redis, cid, window_minutes=5)

    assert features is None
    assert any("exceeded safety ceiling of 10000 entries" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# 5. Mid-Pagination New Event Arrival Isolation Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_pagination_new_event_arriving_mid_pagination():
    """Verify an event arriving at the stream head during pagination is excluded from
    the current backwards pass, but captured in a subsequent independent pass.
    """
    from app.ml_engine.flow_model.features import extract_flow_features

    now = datetime.now(timezone.utc).timestamp()
    cid = "cont_mid_stream_test"

    # Initial 1,500 entries (spanning now - 200s to now - 50.1s)
    stream_data = []
    for i in range(1500):
        ts = now - 200 + (i * 0.1)
        eid = f"{int(ts * 1000)}-0".encode()
        payload = json.dumps({
            "container_id": cid,
            "direction": "external",
            "event_type": "close",
            "dst_ip": "1.1.1.1",
            "dst_port": 80,
            "bytes_sent": 10,
            "bytes_received": 10,
            "timestamp": ts,
        })
        stream_data.append((eid, {b"event": payload.encode()}))

    stream_data.reverse()

    page_query_count = 0

    async def mock_xrevrange(key, max="+", min="-", count=1000):
        nonlocal page_query_count, stream_data
        page_query_count += 1

        min_bound = min.encode() if isinstance(min, str) and min != "-" else None

        if page_query_count == 1:
            # During Page 1 retrieval, insert a fresh in-window event (now - 1.0s)
            new_ts = now - 1.0
            new_eid = f"{int(new_ts * 1000)}-0".encode()
            new_payload = json.dumps({
                "container_id": cid,
                "direction": "external",
                "event_type": "close",
                "dst_ip": "1.1.1.1",
                "dst_port": 80,
                "bytes_sent": 999,
                "bytes_received": 999,
                "timestamp": new_ts,
            })
            # Insert at the very front of Redis stream (newest entry)
            stream_data.insert(0, (new_eid, {b"event": new_payload.encode()}))
            # Page 1 returns the top 1,000 items from the original slice
            return stream_data[1 : count + 1]

        # Subsequent pages: honor exclusive upper bound and inclusive lower bound
        assert max.startswith("(")
        max_bound = max[1:].encode()

        eligible = []
        for item in stream_data:
            if item[0] >= max_bound:
                continue
            if min_bound is not None and item[0] < min_bound:
                continue
            eligible.append(item)

        return eligible[:count]

    mock_redis = AsyncMock()
    mock_redis.xrevrange.side_effect = mock_xrevrange

    # Pass 1: Current backwards traversal must NOT see the newly inserted event
    features_pass1 = await extract_flow_features(mock_redis, cid, window_minutes=5)
    assert features_pass1 is not None
    assert features_pass1["connection_count"] == 1500
    assert features_pass1["total_bytes_sent"] == 15000

    # Pass 2: A new independent extraction pass starts fresh with max="+"
    async def fresh_xrevrange(key, max="+", min="-", count=1000):
        min_bound = min.encode() if isinstance(min, str) and min != "-" else None
        eligible = []
        for item in stream_data:
            if max != "+":
                max_bound = max[1:].encode()
                if item[0] >= max_bound:
                    continue
            if min_bound is not None and item[0] < min_bound:
                continue
            eligible.append(item)
        return eligible[:count]

    mock_redis.xrevrange.side_effect = fresh_xrevrange
    features_pass2 = await extract_flow_features(mock_redis, cid, window_minutes=5)
    assert features_pass2 is not None
    assert features_pass2["connection_count"] == 1501
    assert features_pass2["total_bytes_sent"] == 15999


# ---------------------------------------------------------------------------
# 6. Late-Arriving Event Filtering Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_late_arriving_event_filtered_by_payload_timestamp():
    """Verify late-arriving events are excluded by inner timestamp.

    Setup:
      - 2 valid in-window events (bytes_sent=100 each).
      - 1 late-arriving event with a fresh stream ID (now - 5s) but an expired
        payload timestamp (now - 600s, 10 min ago) with bytes_sent=9999.
    Assertion:
      - Features are computed from the 2 valid events (total_bytes_sent == 200, count == 2).
      - The test strictly fails if inner timestamp filtering is missing.
    """
    from app.ml_engine.flow_model.features import extract_flow_features

    now = datetime.now(timezone.utc).timestamp()
    cid = "cont_late_arrival"

    # Event 1: Valid (now - 40s)
    ts1 = now - 40
    eid1 = f"{int(ts1 * 1000)}-0".encode()
    payload1 = json.dumps({
        "container_id": cid,
        "direction": "external",
        "event_type": "close",
        "dst_ip": "1.1.1.1",
        "dst_port": 80,
        "bytes_sent": 100,
        "bytes_received": 50,
        "timestamp": ts1,
    }).encode()

    # Event 2: Valid (now - 10s)
    ts2 = now - 10
    eid2 = f"{int(ts2 * 1000)}-0".encode()
    payload2 = json.dumps({
        "container_id": cid,
        "direction": "external",
        "event_type": "close",
        "dst_ip": "1.1.1.1",
        "dst_port": 80,
        "bytes_sent": 100,
        "bytes_received": 50,
        "timestamp": ts2,
    }).encode()

    # Event 3: Late arrival — stream ID is fresh (now - 5s), but payload is 10 min old (now - 600s)
    eid3 = f"{int((now - 5) * 1000)}-0".encode()
    payload3 = json.dumps({
        "container_id": cid,
        "direction": "external",
        "event_type": "close",
        "dst_ip": "1.1.1.1",
        "dst_port": 80,
        "bytes_sent": 9999,
        "bytes_received": 9999,
        "timestamp": now - 600,
    }).encode()

    stream_entries = [
        (eid3, {b"event": payload3}),
        (eid2, {b"event": payload2}),
        (eid1, {b"event": payload1}),
    ]

    mock_redis = AsyncMock()
    mock_redis.xrevrange.return_value = stream_entries

    features = await extract_flow_features(mock_redis, cid, window_minutes=5)

    assert features is not None
    assert features["total_bytes_sent"] == 200
    assert features["total_bytes_received"] == 100
    assert features["connection_count"] == 2


# ---------------------------------------------------------------------------
# 7. Application SHAP Loader Verification via _ensure_explainer()
# ---------------------------------------------------------------------------


def test_app_shap_ensure_explainer_with_mocked_bundle():
    """Verify app.explainability.shap_explainer._ensure_explainer() executes its loader logic
    and instantiates TreeExplainer without any filesystem access.
    
    Guarantees:
      - builtins.open is intercepted via mock_open() so no file is touched.
      - pickle.load returns the structured mock bundle.
      - Cached application globals are safely restored in cleanup.
    """
    import app.explainability.shap_explainer as shap_mod
    from app.ml_engine.flow_model.features import FEATURE_ORDER

    # Snapshot existing cached application globals
    saved_explainer = shap_mod._tree_explainer
    saved_bundle = shap_mod._model_bundle

    try:
        # Create minimal fitted IsolationForest model & bundle
        X = np.random.normal(0, 1, (40, len(FEATURE_ORDER)))
        scaler = StandardScaler().fit(X)
        model = IsolationForest(n_estimators=10, random_state=42).fit(scaler.transform(X))

        mock_bundle = {
            "model": model,
            "scaler": scaler,
            "feature_names": FEATURE_ORDER,
            "cap_values": dict(zip(FEATURE_ORDER, [50.0] * len(FEATURE_ORDER))),
        }

        # Clear globals to force execution of the _ensure_explainer loader
        shap_mod._tree_explainer = None
        shap_mod._model_bundle = None

        with (
            patch.object(Path, "exists", return_value=True),
            patch("builtins.open", mock_open()),
            patch("pickle.load", return_value=mock_bundle),
        ):
            result = shap_mod._ensure_explainer()

        assert result is not None
        explainer, bundle = result
        assert bundle is mock_bundle
        assert explainer is not None
        assert hasattr(explainer, "shap_values")

    finally:
        # Strictly restore original application globals
        shap_mod._tree_explainer = saved_explainer
        shap_mod._model_bundle = saved_bundle


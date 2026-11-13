"""Integration tests for the complete AegisNet detection and delivery pipeline.

Verifies end-to-end event flow through:
Event Consumer -> Validation -> Persistence -> Rule Engine -> Graph ML -> Risk Scorer -> DB Alert Storage -> AlertHub / WebSocket.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.consumers import event_consumer
from app.db import postgres as db_module
from app.models.alert import Severity
from app.models.event import Direction, Event, EventType
from app.ws.alerts_ws import AlertHub


@pytest.fixture()
def mock_pool() -> MagicMock:
    pool = MagicMock()
    conn = AsyncMock()
    # Mock save_alert returning alert_id = 101
    conn.fetchrow = AsyncMock(return_value={"alert_id": 101})
    conn.execute = AsyncMock(return_value="UPDATE 1")
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool


@pytest.fixture()
def mock_redis() -> AsyncMock:
    redis = AsyncMock()
    redis.xack = AsyncMock(return_value=1)
    redis.xadd = AsyncMock(return_value=b"1000-0")
    redis.xpending_range = AsyncMock(return_value=[])
    return redis


@pytest.mark.asyncio
async def test_pipeline_rule_detection_to_alert_and_websocket(mock_redis, mock_pool) -> None:
    """External event with known-bad IP triggers RULE-001, saves alert, and pushes to WebSocket."""
    hub = AlertHub()
    ws_queue = hub.subscribe()

    raw_event = {
        "event_id": 9001,
        "container_id": "c_attacker",
        "timestamp": "2026-09-06T15:00:00+00:00",
        "event_type": "open",
        "src_ip": "198.51.100.7",  # known-bad IP from threat_intel/known_bad_indicators.csv
        "dst_ip": "172.18.0.2",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": "tcp",
        "bytes_sent": 100,
        "bytes_received": 200,
        "direction": "external",
    }
    raw_id = b"9001-0"
    fields = {b"event": json.dumps(raw_event).encode()}

    saved_events = []
    saved_alerts = []

    async def fake_save_event(pool, event_dict):
        saved_events.append(event_dict)

    async def fake_save_alert(pool, alert_dict):
        saved_alerts.append(alert_dict)
        return 101

    with (
        patch.object(event_consumer, "save_event", fake_save_event),
        patch.object(event_consumer, "save_alert", fake_save_alert),
    ):
        await event_consumer._process_one(mock_redis, mock_pool, raw_id, fields, hub=hub)

    # 1. Event was validated and persisted to raw_events
    assert len(saved_events) == 1
    assert saved_events[0]["event_id"] == 9001

    # 2. Alert was generated, scored HIGH by RiskScorer, and saved to raw_alerts
    assert len(saved_alerts) >= 1
    alert = saved_alerts[0]
    assert alert["event_id"] == 9001
    assert alert["severity"] == Severity.HIGH
    assert alert["mitre_technique_id"] == "T1071"
    assert alert["detection_type"] == "rule"

    # 3. Alert was published to AlertHub and received on subscriber queue
    pushed = await asyncio.wait_for(ws_queue.get(), timeout=1.0)
    assert pushed["alert_id"] == 101
    assert pushed["severity"] == "high"
    assert pushed["event_id"] == 9001

    # 4. Message was ACKed in Redis
    mock_redis.xack.assert_awaited_once_with(
        event_consumer.STREAM, event_consumer.GROUP, raw_id
    )
    hub.unsubscribe(ws_queue)


@pytest.mark.asyncio
async def test_pipeline_graph_detection_to_alert_and_websocket(mock_redis, mock_pool) -> None:
    """Internal event with new edge to sensitive port triggers graph ML, saves alert, and pushes to WS."""
    hub = AlertHub()
    ws_queue = hub.subscribe()

    raw_event = {
        "event_id": 9002,
        "container_id": "c_compromised",
        "timestamp": "2026-09-06T15:05:00+00:00",
        "event_type": "open",
        "src_ip": "172.18.0.5",
        "dst_ip": "172.18.0.9",
        "src_port": 40100,
        "dst_port": 5432,  # PostgreSQL sensitive service port
        "protocol": "tcp",
        "bytes_sent": 0,
        "bytes_received": 0,
        "direction": "internal",
    }
    raw_id = b"9002-0"
    fields = {b"event": json.dumps(raw_event).encode()}

    saved_alerts = []

    async def fake_save_event(pool, event_dict):
        pass

    async def fake_save_alert(pool, alert_dict):
        saved_alerts.append(alert_dict)
        return 202

    # Provide a clean baseline where (c_compromised, 172.18.0.9, 5432) has not been seen
    from app.ml_engine.graph_model import infer as graph_infer
    from app.ml_engine.graph_model.graph_diff import GraphDiffDetector
    from app.ml_engine.graph_model.lateral_movement import LateralMovementDetector

    detector = GraphDiffDetector()
    detector.load_baseline_from_set(set())
    lateral_detector = LateralMovementDetector()

    with (
        patch.object(event_consumer, "save_event", fake_save_event),
        patch.object(event_consumer, "save_alert", fake_save_alert),
        patch.object(graph_infer, "_detector", detector),
        patch.object(graph_infer, "_lateral_detector", lateral_detector),
        patch.object(graph_infer, "_init_failed", False),
    ):
        await event_consumer._process_one(mock_redis, mock_pool, raw_id, fields, hub=hub)

    # Graph ML alert was generated (score >= 1.0, sensitive port weight=2 -> MEDIUM)
    assert len(saved_alerts) == 1
    alert = saved_alerts[0]
    assert alert["event_id"] == 9002
    assert alert["severity"] == Severity.MEDIUM
    assert alert["detection_type"] == "ml"
    assert "postgresql" in alert["description"].lower()

    # Alert pushed to WebSocket
    pushed = await asyncio.wait_for(ws_queue.get(), timeout=1.0)
    assert pushed["alert_id"] == 202
    assert pushed["severity"] == "medium"

    # Message ACKed
    mock_redis.xack.assert_awaited_once_with(
        event_consumer.STREAM, event_consumer.GROUP, raw_id
    )
    hub.unsubscribe(ws_queue)


@pytest.mark.asyncio
async def test_pipeline_missing_ml_artifact_graceful_degradation(mock_redis, mock_pool) -> None:
    """Missing flow model artifact does not crash pipeline; benign event is still persisted and ACKed."""
    hub = AlertHub()

    raw_event = {
        "event_id": 9003,
        "container_id": "c_benign",
        "timestamp": "2026-09-06T15:10:00+00:00",
        "event_type": "open",
        "src_ip": "172.18.0.3",
        "dst_ip": "93.184.216.34",  # example.com (benign)
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "tcp",
        "bytes_sent": 500,
        "bytes_received": 1500,
        "direction": "external",
    }
    raw_id = b"9003-0"
    fields = {b"event": json.dumps(raw_event).encode()}

    saved_events = []
    saved_alerts = []

    async def fake_save_event(pool, event_dict):
        saved_events.append(event_dict)

    async def fake_save_alert(pool, alert_dict):
        saved_alerts.append(alert_dict)
        return 303

    from app.ml_engine.flow_model import infer as flow_infer

    with (
        patch.object(event_consumer, "save_event", fake_save_event),
        patch.object(event_consumer, "save_alert", fake_save_alert),
        patch.object(flow_infer, "_load_model", return_value=None),
    ):
        await event_consumer._process_one(mock_redis, mock_pool, raw_id, fields, hub=hub)

    # Event persisted, 0 alerts raised, message ACKed
    assert len(saved_events) == 1
    assert len(saved_alerts) == 0
    mock_redis.xack.assert_awaited_once_with(
        event_consumer.STREAM, event_consumer.GROUP, raw_id
    )


@pytest.mark.asyncio
async def test_pipeline_db_failure_leaves_message_unacked(mock_redis, mock_pool) -> None:
    """If DB persistence fails, message is NOT ACKed (stays in PEL for redelivery)."""
    raw_event = {
        "event_id": 9004,
        "container_id": "c_test",
        "timestamp": "2026-09-06T15:15:00+00:00",
        "event_type": "open",
        "src_ip": "172.18.0.3",
        "dst_ip": "8.8.8.8",
        "src_port": 50000,
        "dst_port": 53,
        "protocol": "udp",
        "bytes_sent": 50,
        "bytes_received": 100,
        "direction": "external",
    }
    raw_id = b"9004-0"
    fields = {b"event": json.dumps(raw_event).encode()}

    async def failing_save_event(pool, event_dict):
        raise RuntimeError("Postgres connection dropped")

    with patch.object(event_consumer, "save_event", failing_save_event):
        await event_consumer._process_one(mock_redis, mock_pool, raw_id, fields)

    # xack must NOT have been called
    mock_redis.xack.assert_not_awaited()


def test_database_row_mappings_and_shap_deserialization() -> None:
    """Verify postgres row transformation helpers handle event_timestamp and JSONB SHAP strings."""
    # 1. _event_row maps event_timestamp to timestamp
    raw_row = {
        "event_id": 123,
        "container_id": "abc123",
        "event_timestamp": "2026-09-06T12:00:00+00:00",
        "event_type": "open",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "tcp",
        "bytes_sent": 0,
        "bytes_received": 0,
        "direction": "internal",
    }
    transformed = db_module._event_row(raw_row)
    assert "event_timestamp" not in transformed
    assert transformed["timestamp"] == "2026-09-06T12:00:00+00:00"

    # Event model validates cleanly from transformed dict
    ev = Event.model_validate(transformed)
    assert ev.event_id == 123

    # 2. _parse_shap deserializes stringified JSON from asyncpg JSONB
    alert_row = {
        "alert_id": 1,
        "shap_explanation": json.dumps({"explanation_type": "rule_based", "trigger": "new_edge"}),
    }
    parsed = db_module._parse_shap(alert_row)
    assert isinstance(parsed["shap_explanation"], dict)
    assert parsed["shap_explanation"]["trigger"] == "new_edge"

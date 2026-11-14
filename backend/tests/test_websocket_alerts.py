"""End-to-end WebSocket alert delivery tests (FR-7.2, FR-12).

Tests:
1. Client connection and graceful disconnection cleanup.
2. Real-time alert broadcast delivery to single and multiple simultaneous clients.
3. End-to-end payload integrity (including all MITRE ATT&CK fields).
4. Safe serialization of non-primitive types (datetime, UUID, Enum) without dropping the WS connection.
5. SHAP attachment follow-up message delivery.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.alert import DetectionType, Severity
from app.ws.alerts_ws import AlertHub, router as ws_router


@pytest.fixture()
def test_app() -> tuple[FastAPI, AlertHub]:
    app = FastAPI(title="WebSocket Test App")
    hub = AlertHub(min_severity=Severity.MEDIUM)
    app.state.alert_hub = hub
    app.include_router(ws_router)
    return app, hub


SAMPLE_ALERT = {
    "alert_id": 501,
    "event_id": 9001,
    "container_id": "bfa91286e27b",
    "timestamp": "2026-09-06T15:00:00+00:00",
    "detection_type": "rule",
    "severity": "high",
    "mitre_technique_id": "T1071",
    "mitre_technique_name": "Application Layer Protocol",
    "mitre_tactic_id": "TA0011",
    "mitre_tactic_name": "Command and Control",
    "description": "Known-bad IP 192.0.2.10 contacted",
    "shap_explanation": None,
    "acknowledged": False,
}


def test_client_connection_and_graceful_disconnect_cleanup(test_app):
    """Client connects, increments subscriber count, and cleans up on disconnect."""
    app, hub = test_app
    client = TestClient(app)

    assert hub.subscriber_count == 0

    with client.websocket_connect("/ws/alerts") as ws:
        assert hub.subscriber_count == 1
        # Send a ping/close
        ws.close()

    # After context exit, the subscriber queue must be cleanly deregistered
    assert hub.subscriber_count == 0


def test_single_client_receives_alert_broadcast(test_app):
    """Connected client receives real-time broadcast of a High severity alert."""
    app, hub = test_app
    client = TestClient(app)

    with client.websocket_connect("/ws/alerts") as ws:
        # Publish alert via hub
        asyncio.run(hub.publish(SAMPLE_ALERT))

        received = ws.receive_json()
        assert received["alert_id"] == 501
        assert received["severity"] == "high"
        assert received["container_id"] == "bfa91286e27b"


def test_payload_integrity_including_mitre_attack_fields(test_app):
    """Payload delivered via WebSocket contains full MITRE ATT&CK metadata."""
    app, hub = test_app
    client = TestClient(app)

    lateral_alert = {
        "alert_id": 502,
        "event_id": 9002,
        "container_id": "c_compromised",
        "timestamp": "2026-09-06T15:05:00+00:00",
        "detection_type": "ml",
        "severity": "high",
        "mitre_technique_id": "T1021",
        "mitre_technique_name": "Remote Services",
        "mitre_tactic_id": "TA0008",
        "mitre_tactic_name": "Lateral Movement",
        "description": "Suspicious multi-hop communication sequence observed",
        "shap_explanation": None,
        "acknowledged": False,
    }

    with client.websocket_connect("/ws/alerts") as ws:
        asyncio.run(hub.publish(lateral_alert))

        data = ws.receive_json()
        # Verify core fields
        assert data["alert_id"] == 502
        assert data["detection_type"] == "ml"
        assert data["severity"] == "high"

        # Verify all 4 MITRE ATT&CK fields are intact
        assert data["mitre_technique_id"] == "T1021"
        assert data["mitre_technique_name"] == "Remote Services"
        assert data["mitre_tactic_id"] == "TA0008"
        assert data["mitre_tactic_name"] == "Lateral Movement"


def test_low_severity_alert_filtered_out(test_app):
    """Low severity alerts stay in audit trail and are NOT pushed to WebSocket."""
    app, hub = test_app
    client = TestClient(app)

    low_alert = {**SAMPLE_ALERT, "alert_id": 503, "severity": "low"}
    high_alert = {**SAMPLE_ALERT, "alert_id": 504, "severity": "high"}

    with client.websocket_connect("/ws/alerts") as ws:
        asyncio.run(hub.publish(low_alert))
        asyncio.run(hub.publish(high_alert))

        # First message received should be the high_alert (low was dropped)
        received = ws.receive_json()
        assert received["alert_id"] == 504


def test_multiple_simultaneous_subscribers_receive_broadcast(test_app):
    """All simultaneously connected WebSocket clients receive the alert broadcast."""
    app, hub = test_app
    client = TestClient(app)

    with client.websocket_connect("/ws/alerts") as ws1:
        with client.websocket_connect("/ws/alerts") as ws2:
            assert hub.subscriber_count == 2

            broadcast_alert = {**SAMPLE_ALERT, "alert_id": 505}
            asyncio.run(hub.publish(broadcast_alert))

            msg1 = ws1.receive_json()
            msg2 = ws2.receive_json()

            assert msg1["alert_id"] == 505
            assert msg2["alert_id"] == 505
            assert msg1 == msg2

    assert hub.subscriber_count == 0


def test_serialization_of_datetime_and_enum_objects(test_app):
    """Non-primitive types (datetime, UUID, Enum) do not crash json.dumps during broadcast."""
    app, hub = test_app
    client = TestClient(app)

    raw_object_alert = {
        "alert_id": 506,
        "event_id": 9006,
        "container_id": "c_raw",
        "timestamp": datetime(2026, 9, 6, 15, 30, 0, tzinfo=UTC),  # raw datetime
        "detection_type": DetectionType.RULE,  # raw Enum
        "severity": Severity.HIGH,  # raw Enum
        "correlation_id": uuid4(),  # raw UUID
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_tactic_id": "TA0007",
        "mitre_tactic_name": "Discovery",
        "description": "Port scan detected with raw python objects",
        "shap_explanation": None,
        "acknowledged": False,
    }

    with client.websocket_connect("/ws/alerts") as ws:
        # Should NOT raise TypeError
        asyncio.run(hub.publish(raw_object_alert))

        msg = ws.receive_json()
        assert msg["alert_id"] == 506
        assert msg["severity"] == "high"
        assert msg["detection_type"] == "rule"
        assert "2026-09-06T15:30:00" in msg["timestamp"]
        assert isinstance(msg["correlation_id"], str)
        assert msg["mitre_technique_id"] == "T1046"


def test_shap_attachment_delivered_to_websocket(test_app):
    """SHAP explanation updates bypass severity filter and reach the dashboard client."""
    app, hub = test_app
    client = TestClient(app)

    shap_update = {
        "alert_id": 501,
        "event_id": 9001,
        "update_type": "shap_attachment",
        "shap_explanation": {
            "explanation_type": "shap",
            "model": "isolation_forest",
            "top_features": [
                {"feature": "total_bytes_sent", "value": 150000, "shap": 0.42, "direction": "anomaly_push"}
            ],
        },
    }

    with client.websocket_connect("/ws/alerts") as ws:
        asyncio.run(hub.publish(shap_update))

        received = ws.receive_json()
        assert received["update_type"] == "shap_attachment"
        assert received["alert_id"] == 501
        assert received["shap_explanation"]["explanation_type"] == "shap"

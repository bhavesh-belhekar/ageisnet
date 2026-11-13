"""Tests for graph-based attack detection and lateral movement (Stage 3E & 3E.1)."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

from app.models.alert import Severity
from app.models.event import Direction, Event
from app.ml_engine.graph_model.lateral_movement import (
    LateralMovementDetector,
    SENSITIVE_PORTS,
    SENSITIVE_PORT_MITRE,
)
from app.risk_scoring.scorer import RiskScorer
from app.explainability.shap_explainer import explain_graph


# ===================================================================
# 1. MITRE ATT&CK Accuracy & Evidence-Based Mapping Tests
# ===================================================================


def test_database_port_access_not_labeled_t1078():
    """A TCP connection to a database port must NOT claim proof of valid accounts (T1078)."""
    detector = LateralMovementDetector()
    signals = detector.record_new_edge("container-api", "container-db", 5432)
    assert len(signals) == 1
    sig = signals[0]
    assert sig["kind"] == "graph_sensitive_port"
    assert sig["service"] == "postgresql"
    assert sig["port"] == 5432
    # Must leave technique unassigned rather than inventing certainty
    assert sig["mitre"] is None
    assert sig["connection_count"] == 1
    assert "Unusual connection attempt" in sig["reason"]
    assert "postgresql" in sig["reason"]


def test_ssh_and_docker_port_access_not_confirmed_techniques():
    """Port 22 alone must not claim confirmed SSH session (T1021.004) and Docker port 2375 must not claim T1609."""
    detector = LateralMovementDetector()

    # SSH: generic T1021 (Remote Services), NOT T1021.004
    signals_ssh = detector.record_new_edge("container-a", "container-b", 22)
    assert len(signals_ssh) == 1
    assert signals_ssh[0]["mitre"] == "T1021"
    assert signals_ssh[0]["mitre"] != "T1021.004"

    # Docker API: None (unassigned), NOT T1609
    signals_docker = detector.record_new_edge("container-a", "container-daemon", 2375)
    assert len(signals_docker) == 1
    assert signals_docker[0]["mitre"] is None
    assert signals_docker[0]["mitre"] != "T1609"


def test_lateral_movement_detector_normal_port_not_flagged_sensitive():
    detector = LateralMovementDetector()
    signals = detector.record_new_edge("container-a", "container-b", 8080)
    assert len(signals) == 0


# ===================================================================
# 2. Temporal Correlation & Two-Hop Detection Tests
# ===================================================================


def test_two_hop_correlation_within_15_minutes():
    """Two-hop detection connects events occurring within the 900s correlation window."""
    detector = LateralMovementDetector(correlation_window=900.0)
    t0 = 1_000_000.0

    # Hop 1: A -> B at t0
    s1 = detector.record_new_edge("comp-a", "comp-b", 8080, timestamp=t0)
    assert len(s1) == 0

    # Hop 2: B -> C at t0 + 420s (7 minutes later, well within 15 mins)
    s2 = detector.record_new_edge("comp-b", "comp-c", 5432, timestamp=t0 + 420.0)
    # Should trigger sensitive_port and lateral_path
    path_sig = next((s for s in s2 if s["kind"] == "graph_lateral_path"), None)
    assert path_sig is not None
    assert path_sig["path"] == ["comp-a", "comp-b", "comp-c"]
    assert path_sig["port"] == 5432
    assert path_sig["mitre"] == "T1021"
    assert "Suspicious multi-hop communication sequence observed" in path_sig["reason"]


def test_rejection_of_paths_outside_time_window():
    """Events occurring days or hours apart (>900s) must NOT be correlated as an attack chain."""
    detector = LateralMovementDetector(correlation_window=900.0)
    t0 = 1_000_000.0

    # Hop 1: A -> B on Monday at t0
    detector.record_new_edge("comp-a", "comp-b", 8080, timestamp=t0)

    # Hop 2: B -> C 2 days later (172,800s > 900s)
    s2 = detector.record_new_edge("comp-b", "comp-c", 8080, timestamp=t0 + 172_800.0)
    # Must NOT correlate
    assert not any(s["kind"] == "graph_lateral_path" for s in s2)


def test_expiration_of_old_first_hop_entries():
    """Expired first-hop attribution entries are pruned during processing."""
    detector = LateralMovementDetector(correlation_window=900.0)
    t0 = 1000.0
    detector.record_new_edge("host-a", "host-b", 80, timestamp=t0)
    assert "host-b" in detector._first_hop_sources

    # Trigger processing at t0 + 1000s (> 900s)
    detector.record_new_edge("host-x", "host-y", 80, timestamp=t0 + 1000.0)
    # Old host-b entry must have expired and been cleaned up
    assert "host-b" not in detector._first_hop_sources


def test_legitimate_proxy_gateway_traffic_no_lateral_alert():
    """Unrelated clients of a gateway or proxy must not generate false lateral movement paths."""
    # 1. Named proxy keyword: ingress-proxy
    detector = LateralMovementDetector(correlation_window=900.0)
    t0 = 1000.0
    # Client 1 connects to ingress proxy
    detector.record_new_edge("client-1", "ingress-proxy", 443, timestamp=t0)
    # Ingress proxy forwards to backend service
    s_backend = detector.record_new_edge("ingress-proxy", "backend-svc", 8080, timestamp=t0 + 10.0)
    # Ingress proxy should not generate a lateral movement path for client-1
    assert not any(s["kind"] == "graph_lateral_path" for s in s_backend)

    # 2. Dynamic fan-in threshold: high fan-in intermediary node
    detector_fanin = LateralMovementDetector(correlation_window=900.0, max_fanin=3)
    # 3 distinct clients reach router-node
    detector_fanin.record_new_edge("user-1", "router-node", 80, timestamp=t0)
    detector_fanin.record_new_edge("user-2", "router-node", 80, timestamp=t0 + 1.0)
    detector_fanin.record_new_edge("user-3", "router-node", 80, timestamp=t0 + 2.0)

    # router-node connects to internal-target
    s_out = detector_fanin.record_new_edge("router-node", "internal-target", 8080, timestamp=t0 + 5.0)
    # High fan-in node is recognized as shared gateway, avoiding false alerts
    assert not any(s["kind"] == "graph_lateral_path" for s in s_out)


# ===================================================================
# 3. Deduplication and TTL Expiration Tests
# ===================================================================


def test_alert_deduplication_within_one_hour():
    """Duplicate paths within 3600s are suppressed."""
    detector = LateralMovementDetector(dedup_ttl=3600.0, correlation_window=900.0)
    t0 = 1000.0
    detector.record_new_edge("h1", "h2", 80, timestamp=t0)
    s1 = detector.record_new_edge("h2", "h3", 8080, timestamp=t0 + 10.0)
    assert any(s["kind"] == "graph_lateral_path" for s in s1)

    # Same path repeated 5 minutes later (300s < 3600s)
    s2 = detector.record_new_edge("h2", "h3", 8080, timestamp=t0 + 310.0)
    assert not any(s["kind"] == "graph_lateral_path" for s in s2)


def test_re_alerting_after_dedup_ttl_expires():
    """After 3600s deduplication TTL expires, the same path is eligible to alert again."""
    detector = LateralMovementDetector(dedup_ttl=3600.0, correlation_window=900.0)
    t0 = 1000.0
    detector.record_new_edge("h1", "h2", 80, timestamp=t0)
    s1 = detector.record_new_edge("h2", "h3", 8080, timestamp=t0 + 10.0)
    assert any(s["kind"] == "graph_lateral_path" for s in s1)

    # Fresh hop 1 and hop 2 after 4000s (> 3600s deduplication TTL)
    t_new = t0 + 4000.0
    detector.record_new_edge("h1", "h2", 80, timestamp=t_new)
    s_renewed = detector.record_new_edge("h2", "h3", 8080, timestamp=t_new + 10.0)
    # Should re-alert!
    assert any(s["kind"] == "graph_lateral_path" for s in s_renewed)


def test_reconnaissance_state_expiration():
    """Port probing state older than correlation_window expires; deduplication expires after TTL."""
    detector = LateralMovementDetector(correlation_window=900.0, dedup_ttl=3600.0)
    t0 = 1000.0

    # Probe 2 ports at t0
    detector.record_new_edge("scanner", "target", 80, timestamp=t0)
    detector.record_new_edge("scanner", "target", 443, timestamp=t0 + 10.0)

    # 3rd port probed 1000s later (> 900s correlation window)
    s3 = detector.record_new_edge("scanner", "target", 8080, timestamp=t0 + 1000.0)
    # The first two probes expired, so only 1 active port remains -> no recon alert
    assert not any(s["kind"] == "graph_internal_recon" for s in s3)

    # Now probe 3 ports in rapid succession at t0 + 2000s (all previous ports expired)
    t_burst = t0 + 2000.0
    s_p1 = detector.record_new_edge("scanner", "target", 21, timestamp=t_burst)
    s_p2 = detector.record_new_edge("scanner", "target", 25, timestamp=t_burst + 5.0)
    s_recon = detector.record_new_edge("scanner", "target", 110, timestamp=t_burst + 10.0)
    assert not any(s["kind"] == "graph_internal_recon" for s in s_p1)
    assert not any(s["kind"] == "graph_internal_recon" for s in s_p2)
    assert any(s["kind"] == "graph_internal_recon" for s in s_recon)


def test_memory_capacity_limits():
    """All internal tracking collections respect max_entries limit."""
    detector = LateralMovementDetector(max_entries=5)
    t0 = 1000.0

    # Insert 10 different destinations
    for i in range(10):
        detector.record_new_edge(f"src-{i}", f"dst-{i}", 80, timestamp=t0 + i)

    # Enforced capacity must not exceed 5
    assert len(detector._first_hop_sources) <= 5
    assert len(detector._edge_counts) <= 5
    assert len(detector._probed_ports) <= 5


def test_lateral_movement_detector_reset():
    detector = LateralMovementDetector()
    detector.record_new_edge("node-a", "node-b", 80)
    detector.reset()
    assert len(detector._first_hop_sources) == 0
    assert len(detector._alerted_paths) == 0
    assert len(detector._edge_counts) == 0
    assert len(detector._probed_ports) == 0
    assert len(detector._alerted_recon) == 0


# ===================================================================
# 4. Risk Scoring Integration Tests
# ===================================================================


def test_risk_scorer_ml_graph_alone_is_low():
    scorer = RiskScorer()
    signals = [{"kind": "ml_graph", "score": 1.0}]
    severity = scorer.score(signals)
    assert severity == Severity.LOW


def test_risk_scorer_graph_sensitive_port_reaches_medium():
    scorer = RiskScorer()
    signals = [
        {"kind": "ml_graph", "score": 1.0},
        {"kind": "graph_sensitive_port", "score": 1.0},
    ]
    severity = scorer.score(signals)
    assert severity == Severity.MEDIUM


def test_risk_scorer_graph_lateral_path_reaches_high():
    scorer = RiskScorer()
    signals = [
        {"kind": "ml_graph", "score": 1.0},
        {"kind": "graph_lateral_path", "score": 1.0},
    ]
    severity = scorer.score(signals)
    assert severity == Severity.HIGH


def test_risk_scorer_graph_internal_recon_reaches_medium():
    scorer = RiskScorer()
    signals = [
        {"kind": "ml_graph", "score": 1.0},
        {"kind": "graph_internal_recon", "score": 1.0},
    ]
    severity = scorer.score(signals)
    assert severity == Severity.MEDIUM


# ===================================================================
# 5. Explainability Integration Tests
# ===================================================================


def test_explain_graph_new_edge():
    detail = {"src": "c1", "dst": "c2", "port": 80, "reason": "not in baseline"}
    explanation = asyncio.run(explain_graph(101, detail, baseline_size=50))
    assert explanation["explanation_type"] == "rule_based"
    assert explanation["trigger"] == "new_edge"
    assert explanation["src_container"] == "c1"
    assert explanation["dst_container"] == "c2"
    assert explanation["port"] == 80
    assert explanation["baseline_edges_seen"] == 50


def test_explain_graph_sensitive_port():
    detail = {
        "src": "c1",
        "dst": "db",
        "port": 5432,
        "service": "postgresql",
        "reason": "sensitive db port",
    }
    explanation = asyncio.run(explain_graph(102, detail, baseline_size=50))
    assert explanation["explanation_type"] == "rule_based"
    assert explanation["trigger"] == "sensitive_port"
    assert explanation["service"] == "postgresql"
    assert explanation["port"] == 5432


def test_explain_graph_lateral_path():
    detail = {
        "src": "c2",
        "dst": "c3",
        "port": 5432,
        "path": ["c1", "c2", "c3"],
        "reason": "multi-hop path",
    }
    explanation = asyncio.run(explain_graph(103, detail, baseline_size=50))
    assert explanation["explanation_type"] == "rule_based"
    assert explanation["trigger"] == "lateral_path"
    assert explanation["path"] == ["c1", "c2", "c3"]


def test_explain_graph_internal_recon():
    detail = {
        "src": "c1",
        "dst": "c2",
        "port": 8080,
        "port_count": 4,
        "reason": "internal port scan",
    }
    explanation = asyncio.run(explain_graph(104, detail, baseline_size=50))
    assert explanation["explanation_type"] == "rule_based"
    assert explanation["trigger"] == "internal_recon"
    assert explanation["port_count"] == 4


# ===================================================================
# 6. Inference Integration Tests (score_graph_event)
# ===================================================================


def test_score_graph_event_external_returns_none():
    from app.ml_engine.graph_model.infer import score_graph_event
    event = MagicMock()
    event.direction = Direction.EXTERNAL
    result = asyncio.run(score_graph_event(event))
    assert result is None


def test_score_graph_event_ephemeral_port_returns_none():
    from app.ml_engine.graph_model.infer import score_graph_event, EPHEMERAL_PORT_MIN
    event = MagicMock()
    event.direction = Direction.INTERNAL
    event.container_id = "cont-123"
    event.dst_ip = "172.18.0.5"
    event.dst_port = EPHEMERAL_PORT_MIN + 100
    event.protocol = "tcp"
    event.event_id = 999
    with patch("app.ml_engine.graph_model.infer._ensure_detector") as mock_ensure:
        mock_ensure.return_value = MagicMock()
        result = asyncio.run(score_graph_event(event))
        assert result is None

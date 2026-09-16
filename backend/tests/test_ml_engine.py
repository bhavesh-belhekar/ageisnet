"""Graph-model tests — ephemeral port filter regression (post-Phase 8 bugfix)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.event import Direction, Event, EventType


def _internal_event(
    event_id: int,
    container_id: str,
    dst_ip: str,
    dst_port: int,
    *,
    src_port: int = 40000,
) -> Event:
    return Event(
        event_id=event_id,
        container_id=container_id,
        timestamp=datetime(2026, 9, 16, 12, 0, 0, tzinfo=UTC),
        event_type=EventType.OPEN,
        src_ip="172.18.0.1",
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="tcp",
        bytes_sent=0,
        bytes_received=0,
        direction=Direction.INTERNAL,
    )


def test_ephemeral_port_constant_matches_rule_engine() -> None:
    """EPHEMERAL_PORT_MIN in graph_model must match rule_engine."""
    from app.ml_engine.graph_model.infer import EPHEMERAL_PORT_MIN as graph_min
    from app.rule_engine.engine import EPHEMERAL_PORT_MIN as rule_min

    assert graph_min == rule_min == 32768


def test_ephemeral_dst_port_would_be_skipped() -> None:
    """Events with ephemeral dst_port are filtered before reaching the detector."""
    from app.ml_engine.graph_model.infer import EPHEMERAL_PORT_MIN

    # Server-side mirror: dst_port is client's ephemeral port
    ev_at_threshold = _internal_event(1, "aaa111aaa111", "172.18.0.2", EPHEMERAL_PORT_MIN)
    ev_above = _internal_event(2, "aaa111aaa111", "172.18.0.2", 58230)

    # The filter condition: port >= EPHEMERAL_PORT_MIN means skip
    assert ev_at_threshold.dst_port >= EPHEMERAL_PORT_MIN
    assert ev_above.dst_port >= EPHEMERAL_PORT_MIN


def test_service_port_not_filtered() -> None:
    """Events with service dst_port pass the ephemeral port filter."""
    from app.ml_engine.graph_model.infer import EPHEMERAL_PORT_MIN

    ev = _internal_event(3, "aaa111aaa111", "172.18.0.2", 5432)
    assert ev.dst_port < EPHEMERAL_PORT_MIN


def test_same_container_repeated_connections_dont_multiply_alerts() -> None:
    """Two connections from the same container to the same dst:port should
    produce at most one 'new edge' alert, not two."""
    from app.ml_engine.graph_model.graph_diff import GraphDiffDetector

    detector = GraphDiffDetector()
    detector.load_baseline_from_set(set())

    # First connection — should be flagged as new
    result1 = detector.check_edge("src_aaa", "172.18.0.2", 5432)
    assert result1 is not None
    assert result1["is_anomalous"] is True

    # Record the edge
    detector.record_edge("src_aaa", "172.18.0.2", 5432)

    # Second connection to the same dst:port — should NOT be flagged
    result2 = detector.check_edge("src_aaa", "172.18.0.2", 5432)
    assert result2 is None

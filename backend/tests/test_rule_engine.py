"""Rule-engine tests for RULE-001..004 (Phase 3 sub-step 2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.models.alert import Alert, Severity
from app.models.event import Direction, Event, EventType
from app.rule_engine import indicators
from app.rule_engine.engine import (
    EPHEMERAL_PORT_MIN,
    RuleEngine,
)


def _event(
    event_id: int,
    container_id: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    *,
    src_port: int = 40000,
    timestamp: datetime | None = None,
    event_type: EventType = EventType.OPEN,
) -> Event:
    return Event(
        event_id=event_id,
        container_id=container_id,
        timestamp=timestamp or datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC),
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="tcp",
        direction=Direction.INTERNAL,
    )


def _engine_that_fires(eng: RuleEngine, events: list[Event]) -> dict[int, list[Alert]]:
    return {e.event_id: eng.evaluate(e) for e in events}


class TestRuleKnownBadIp:
    def test_fires_on_known_bad_src(self) -> None:
        eng = RuleEngine()
        ev = _event(1, "bfa91286e27b", "192.0.2.10", "172.18.0.9", 8000)
        alerts = eng.evaluate(ev)
        assert len(alerts) == 1
        a = alerts[0]
        assert a.mitre_technique_id == "T1071"
        assert a.severity == Severity.HIGH
        assert "192.0.2.10" in a.description

    def test_fires_on_known_bad_dst(self) -> None:
        eng = RuleEngine()
        ev = _event(2, "bfa91286e27b", "172.18.0.9", "198.51.100.7", 80)
        alerts = eng.evaluate(ev)
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1071"

    def test_quiet_on_benign(self) -> None:
        eng = RuleEngine()
        ev = _event(3, "bfa91286e27b", "172.18.0.9", "172.18.0.8", 80)
        assert eng.evaluate(ev) == []


class TestRuleKnownBadPort:
    def test_fires_on_known_bad_port(self) -> None:
        eng = RuleEngine()
        ev = _event(4, "bfa91286e27b", "172.18.0.9", "172.18.0.4", 23)
        alerts = eng.evaluate(ev)
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1043"
        assert alerts[0].severity == Severity.MEDIUM

    def test_quiet_on_clean_port(self) -> None:
        eng = RuleEngine()
        ev = _event(5, "bfa91286e27b", "172.18.0.9", "172.18.0.4", 5432)
        assert eng.evaluate(ev) == []


class TestRulePortScan:
    def test_fires_after_threshold_distinct_ports(self) -> None:
        eng = RuleEngine()
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
        events = [
            _event(
                100 + i,
                "a1b2c3d4e5f6",
                "172.18.0.20",
                "172.18.0.21",
                20000 + i,
                src_port=45000 + i,
                timestamp=now + timedelta(seconds=i),
            )
            for i in range(7)
        ]
        results = _engine_that_fires(eng, events)
        fired_events = [eid for eid, alerts in results.items() if alerts]
        assert fired_events, "expected at least one event to fire the port-scan rule"
        # exactly one alert across the whole window (dedup per container)
        fired_alerts = [a for alerts in results.values() for a in alerts]
        assert fired_alerts
        assert fired_alerts[0].mitre_technique_id == "T1046"
        assert fired_alerts[0].severity == Severity.HIGH
        assert len(fired_alerts) == 1

    def test_scan_alert_deduped_within_window(self) -> None:
        """Once fired, subsequent scan events in the same window produce no
        duplicate alerts (per-container)."""
        eng = RuleEngine()
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
        events = [
            _event(
                100 + i,
                "a1b2c3d4e5f6",
                "172.18.0.20",
                "172.18.0.21",
                20000 + i,
                src_port=45000 + i,
                timestamp=now + timedelta(seconds=i),
            )
            for i in range(9)
        ]
        results = _engine_that_fires(eng, events)
        all_alerts = [a for alerts in results.values() for a in alerts]
        assert len(all_alerts) == 1

    def test_ignores_ephemeral_server_side_mirrors(self) -> None:
        """A server receiving many inbound connects must NOT look like a scan."""
        eng = RuleEngine()
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
        # postgres (172.18.0.2) seeing backend connect from many ephemeral ports
        events = [
            _event(
                200 + i,
                "83f6c669fc4a",
                "172.18.0.2",
                "172.18.0.9",
                50000 + i,  # client ephemeral port as dst_port (>= EPHEMERAL_PORT_MIN)
                src_port=5432,
                timestamp=now + timedelta(seconds=i),
            )
            for i in range(15)
        ]
        for ev in events:
            assert ev.dst_port >= EPHEMERAL_PORT_MIN
        assert _engine_that_fires(eng, events) == {e.event_id: [] for e in events}

    def test_window_expires(self) -> None:
        eng = RuleEngine()
        now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
        # 6 distinct ports, each 60s apart -> at most one ever inside the 30s
        # window, so the rule must never fire
        events = [
            _event(
                300 + i,
                "abc",
                "172.18.0.20",
                "172.18.0.21",
                21000 + i,
                src_port=46000 + i,
                timestamp=now + timedelta(seconds=60 * i),
            )
            for i in range(7)
        ]
        for _eid, alerts in _engine_that_fires(eng, events).items():
            assert alerts == []


class TestRuleRestrictedProtocol:
    @pytest.fixture(autouse=True)
    def _stub_dns(self, monkeypatch) -> None:
        """demo-db is unresolvable from the test host; stub the resolver."""
        monkeypatch.setattr(
            indicators,
            "_resolve_container_ips",
            lambda name: {"172.18.0.4"} if name == "demo-db" else set(),
        )
        indicators._resolve_restricted_connections.cache_clear()

    def test_fires_on_restricted_port(self) -> None:
        eng = RuleEngine()
        ev = _event(10, "bfa91286e27b", "172.18.0.9", "172.18.0.4", 22)
        alerts = eng.evaluate(ev)
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1571"
        assert alerts[0].severity == Severity.HIGH

    def test_fires_lateral_movement_to_restricted_db_from_unknown(self) -> None:
        eng = RuleEngine()
        # demo-web (unknown source) reaching demo-db:5432 -> lateral movement
        ev = _event(11, "5bf7a9363c99", "172.18.0.8", "172.18.0.4", 5432)
        alerts = eng.evaluate(ev)
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1571"
        assert "lateral movement" in alerts[0].description

    def test_allowed_source_connecting_demo_db_is_quiet(self) -> None:
        eng = RuleEngine()
        # demo-api is the whitelisted source for demo-db:5432
        ev = _event(12, "bfa91286e27b", "172.18.0.7", "172.18.0.4", 5432)
        assert eng.evaluate(ev) == []

    def test_backend_to_metadata_postgres_is_not_lateral_movement(self) -> None:
        """Backend talking to its own metadata postgres (172.18.0.2) is not the
        restricted demo-db (172.18.0.4) — the FP this fix targets."""
        eng = RuleEngine()
        ev = _event(13, "82f1a40a277c", "172.18.0.9", "172.18.0.2", 5432)
        assert eng.evaluate(ev) == []

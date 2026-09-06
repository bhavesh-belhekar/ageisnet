"""Rule engine — evaluates each event against RULE-001..004.

All four rules run on every persisted event.  The engine returns a (possibly
empty) list of ``Alert`` dicts that the caller persists to ``raw_alerts``.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from app.models.alert import Alert, DetectionType, Severity
from app.models.event import Event
from app.rule_engine.indicators import (
    get_known_bad_ips,
    get_known_bad_ports,
    get_port_scan_threshold,
    get_port_scan_window_seconds,
    get_restricted_connections,
    get_restricted_ports,
)

logger = logging.getLogger("rule_engine")

# Server-side event mirrors always carry the client's ephemeral port as the
# destination port (e.g. postgres seeing a client connect from 58230).  Real
# port scans probe service ports below the Linux client ephemeral range
# (ip_local_port_range, default 32768-60999), so a destination port in that
# range is treated as an inbound-connection mirror, not a scanned port.
EPHEMERAL_PORT_MIN = 32768

# Each connection produces a 4-event shape (open+close on both peers); without
# dedup the open and close events both fire the same rule, doubling alerts.
# Suppress a repeat alert for the same (container, rule, dst) within this
# window so one connection yields one alert per rule.
ALERT_SUPPRESSION_SECONDS = 15

_MITRE = {
    "known_bad_ip_connection": "T1071",
    "known_bad_port": "T1043",
    "port_scan": "T1046",
    "restricted_protocol": "T1571",
}

# Pre-load indicators once at import time (lru_cache inside each getter).


class RuleEngine:
    """Stateful rule engine with per-container sliding window for port scans."""

    def __init__(self) -> None:
        # sliding window: container_id -> list of (dst_port, timestamp)
        self._port_scan_window: dict[str, list[tuple[int, datetime]]] = defaultdict(list)
        # last scan-alert emission per container (dedup: one alert per window)
        self._port_scan_last_alert: dict[str, datetime] = {}
        # connection-level dedup: (container_id, mitre) -> last alert timestamp,
        # collapsing the open+close duplicate per connection into one alert
        self._alert_suppression: dict[tuple[str, str], datetime] = {}

    def _suppressed(self, alert: Alert, now: datetime) -> bool:
        """True if a similar alert (same container + rule) fired recently."""
        if not alert.mitre_technique_id:
            return False
        key = (alert.container_id, alert.mitre_technique_id)
        last = self._alert_suppression.get(key)
        if last is not None and now - last <= timedelta(seconds=ALERT_SUPPRESSION_SECONDS):
            return True
        self._alert_suppression[key] = now
        return False

    def evaluate(self, event: Event) -> list[Alert]:
        """Run all rules against *event*; return zero or more alerts."""
        alerts: list[Alert] = []
        alerts.extend(self._rule_known_bad_ip(event))
        alerts.extend(self._rule_known_bad_port(event))
        alerts.extend(self._rule_port_scan(event))
        alerts.extend(self._rule_restricted_protocol(event))
        return [a for a in alerts if not self._suppressed(a, event.timestamp)]

    # ------------------------------------------------------------------
    # RULE-001: known-bad IP (T1071)
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_known_bad_ip(event: Event) -> list[Alert]:
        bad = get_known_bad_ips()
        matched_ip = None
        if event.src_ip in bad:
            matched_ip = event.src_ip
        elif event.dst_ip in bad:
            matched_ip = event.dst_ip
        if not matched_ip:
            return []
        logger.warning(
            "RULE-001 fired: event_id=%d matched known-bad IP %s",
            event.event_id,
            matched_ip,
        )
        return [
            Alert(
                event_id=event.event_id,
                container_id=event.container_id,
                timestamp=event.timestamp,
                detection_type=DetectionType.RULE,
                severity=Severity.HIGH,
                mitre_technique_id=_MITRE["known_bad_ip_connection"],
                description=f"Known-bad IP {matched_ip} in connection "
                f"{event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port}",
            )
        ]

    # ------------------------------------------------------------------
    # RULE-002: known-bad port (T1043)
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_known_bad_port(event: Event) -> list[Alert]:
        if event.dst_port not in get_known_bad_ports():
            return []
        logger.warning(
            "RULE-002 fired: event_id=%d dst_port=%d in known-bad list",
            event.event_id,
            event.dst_port,
        )
        return [
            Alert(
                event_id=event.event_id,
                container_id=event.container_id,
                timestamp=event.timestamp,
                detection_type=DetectionType.RULE,
                severity=Severity.MEDIUM,
                mitre_technique_id=_MITRE["known_bad_port"],
                description=f"Connection to known-bad port {event.dst_port} "
                f"({event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port})",
            )
        ]

    # ------------------------------------------------------------------
    # RULE-003: port scan (T1046)
    # ------------------------------------------------------------------
    def _rule_port_scan(self, event: Event) -> list[Alert]:
        threshold = get_port_scan_threshold()
        window_sec = get_port_scan_window_seconds()
        now = event.timestamp
        cutoff = now - timedelta(seconds=window_sec)

        # Skip server-side event mirrors: the destination port is the client's
        # ephemeral port, not a probed service port (mitigates responder-side
        # many-distinct-ports false positives).
        if event.dst_port >= EPHEMERAL_PORT_MIN:
            return []

        key = event.container_id
        self._port_scan_window[key].append((event.dst_port, now))

        # Prune stale entries
        entries = self._port_scan_window[key]
        self._port_scan_window[key] = [(port, ts) for port, ts in entries if ts >= cutoff]

        # Distinct destination ports (dedup for 4-event-per-connection shape)
        distinct_ports = {port for port, _ in self._port_scan_window[key]}
        if len(distinct_ports) < threshold:
            return []

        # Emit at most one alert per container per window
        last_alert = self._port_scan_last_alert.get(key)
        if last_alert is not None and now - last_alert <= timedelta(seconds=window_sec):
            return []
        self._port_scan_last_alert[key] = now

        logger.warning(
            "RULE-003 fired: container=%s scanned %d distinct ports "
            "(threshold=%d, window=%ds, e.g. dst_ip=%s)",
            event.container_id,
            len(distinct_ports),
            threshold,
            window_sec,
            event.dst_ip,
        )
        return [
            Alert(
                event_id=event.event_id,
                container_id=event.container_id,
                timestamp=event.timestamp,
                detection_type=DetectionType.RULE,
                severity=Severity.HIGH,
                mitre_technique_id=_MITRE["port_scan"],
                description=f"Port scan detected: container {event.container_id} "
                f"contacted {len(distinct_ports)} distinct destination ports "
                f"in {window_sec}s window",
            )
        ]

    # ------------------------------------------------------------------
    # RULE-004: restricted protocol / lateral movement (T1571)
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_restricted_protocol(event: Event) -> list[Alert]:
        reasons: list[str] = []

        if event.dst_port in get_restricted_ports():
            reasons.append(f"restricted port {event.dst_port} not whitelisted")

        for rule in get_restricted_connections():
            if rule.get("dst_port") != event.dst_port:
                continue
            if event.dst_ip not in rule.get("dst_ips", set()):
                continue
            allowed = set(rule.get("allowed_sources", []))
            if event.container_id not in allowed:
                reasons.append(
                    f"lateral movement to {rule.get('dst_container')}:{event.dst_port} "
                    f"from unauthorized source {event.container_id}"
                )

        if not reasons:
            return []

        logger.warning(
            "RULE-004 fired: event_id=%d container=%s dst_port=%d — %s",
            event.event_id,
            event.container_id,
            event.dst_port,
            "; ".join(reasons),
        )
        return [
            Alert(
                event_id=event.event_id,
                container_id=event.container_id,
                timestamp=event.timestamp,
                detection_type=DetectionType.RULE,
                severity=Severity.HIGH,
                mitre_technique_id=_MITRE["restricted_protocol"],
                description=f"Restricted access: container {event.container_id} "
                f"({event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port}) — "
                + "; ".join(reasons),
            )
        ]

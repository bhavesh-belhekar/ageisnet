"""Lateral movement and sensitive-port detection for graph-based attack detection.

Augments :class:`GraphDiffDetector` with heuristics for:

1. **Sensitive-port detection** — an anomalous edge to a well-known service port
   (database, SSH, RDP, Docker daemon…) is flagged as an unusual connection
   attempt.  Wording strictly distinguishes observed network behavior from
   unproven post-exploitation hypotheses; MITRE techniques requiring
   application-layer proof (e.g. T1078 Valid Accounts, T1609 Container Admin)
   are left unassigned (None) rather than falsely asserted.

2. **Temporal two-hop lateral movement** — when container A connects to
   container B (hop 1) and B subsequently connects to container C (hop 2)
   within a configurable correlation window (default 15 minutes / 900s),
   the sequence A → B → C is flagged as a potential lateral movement path.
   Connections outside the correlation window are discarded.  Known gateways
   and high fan-in proxies are filtered to avoid false positives on legitimate
   multi-tier client traffic.

3. **Connection frequency & internal reconnaissance** — tracks distinct ports
   probed between containers within the correlation window to flag suspicious
   multi-port scanning activity (T1046).

4. **TTL-based deduplication & bounded memory** — alert suppression expires
   after a configurable TTL (default 1 hour / 3600s), allowing re-alerting if
   the activity recurs.  All tracking structures enforce strict capacity limits
   and prune expired state during normal event processing to prevent unbounded
   memory growth.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger("graph_model.lateral_movement")

# ---------------------------------------------------------------------------
# Sensitive service ports
# ---------------------------------------------------------------------------

#: Mapping of port → human-readable service name.
SENSITIVE_PORTS: dict[int, str] = {
    22: "ssh",
    23: "telnet",
    3389: "rdp",
    2375: "docker-daemon",
    2376: "docker-daemon-tls",
    5432: "postgresql",
    3306: "mysql",
    1433: "mssql",
    27017: "mongodb",
    6379: "redis",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    2181: "zookeeper",
    2888: "zookeeper-peer",
    3888: "zookeeper-leader",
    5984: "couchdb",
    7474: "neo4j-http",
    7687: "neo4j-bolt",
    9042: "cassandra",
    5672: "amqp",
    15672: "rabbitmq-management",
    9092: "kafka",
    2379: "etcd",
    2380: "etcd-peer",
}

#: Cautious MITRE ATT&CK mapping:
#: Network-level observations (TCP connect) without application-layer payload
#: cannot confirm credential theft/valid account abuse (T1078) or container
#: command execution (T1609).
#: Only generic Remote Services (T1021) is applied where a remote service access
#: port is contacted. Database/cache/Docker ports leave technique unassigned (None).
SENSITIVE_PORT_MITRE: dict[int, str | None] = {
    22: "T1021",       # Remote Services (generic — connection attempt does not prove confirmed SSH session)
    3389: "T1021",     # Remote Services (generic — connection attempt does not prove confirmed RDP session)
    23: "T1021",       # Remote Services
    2375: None,        # Insufficient evidence for T1609 (port connect != container admin command)
    2376: None,        # Insufficient evidence for T1609
    5432: None,        # Insufficient evidence for T1078 (port connect != credential reuse)
    3306: None,        # Insufficient evidence for T1078
    1433: None,        # Insufficient evidence for T1078
    27017: None,       # Insufficient evidence for T1078
    6379: None,        # Insufficient evidence for T1078
    9200: None,        # Insufficient evidence for T1078
    7687: None,        # Insufficient evidence for T1078
}

RECON_PORT_THRESHOLD = 3
DEFAULT_CORRELATION_WINDOW = 900.0   # 15 minutes
DEFAULT_DEDUP_TTL = 3600.0           # 1 hour
DEFAULT_MAX_ENTRIES = 5000
DEFAULT_MAX_FANIN = 3
DEFAULT_PROXY_KEYWORDS = ("proxy", "gateway", "ingress", "router", "lb", "loadbalancer")


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class LateralMovementDetector:
    """Stateful detector for sensitive-port, recon, and two-hop lateral movement.

    Features time-based correlation, TTL-based deduplication, and bounded
    in-memory capacity to ensure reliability in long-running processes.
    """

    def __init__(
        self,
        correlation_window: float = DEFAULT_CORRELATION_WINDOW,
        dedup_ttl: float = DEFAULT_DEDUP_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_fanin: int = DEFAULT_MAX_FANIN,
        known_proxies: set[str] | None = None,
    ) -> None:
        self.correlation_window = correlation_window
        self.dedup_ttl = dedup_ttl
        self.max_entries = max_entries
        self.max_fanin = max_fanin
        self.known_proxies = set(known_proxies) if known_proxies else set()

        # State tracking:
        # newly_reached_dst → list of (hop1_src, timestamp)
        self._first_hop_sources: dict[str, list[tuple[str, float]]] = {}

        # Alert deduplication:
        # path_key (hop1_src, intermediate, dst, port) → alert_timestamp
        self._alerted_paths: dict[tuple[str, str, str, int], float] = {}

        # (src, dst) → alert_timestamp
        self._alerted_recon: dict[tuple[str, str], float] = {}

        # Frequency tracking:
        # (src, dst, port) → (count, last_seen_timestamp)
        self._edge_counts: dict[tuple[str, str, int], tuple[int, float]] = {}

        # (src, dst) → list of (port, timestamp)
        self._probed_ports: dict[tuple[str, str], list[tuple[int, float]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_new_edge(
        self,
        src: str,
        dst: str,
        port: int,
        timestamp: float | None = None,
    ) -> list[dict]:
        """Process a newly detected edge and return any additional signals.

        Args:
            src: Source container identifier (or IP proxy).
            dst: Destination container identifier (or IP proxy).
            port: Destination service port.
            timestamp: Event epoch timestamp in seconds. Defaults to time.time().

        Returns:
            A list of anomaly signal dicts (may be empty).
        """
        now = timestamp if timestamp is not None else time.time()

        # 0. Routine cleanup during event processing
        self._prune(now)

        signals: list[dict] = []
        edge_key = (src, dst, port)
        pair_key = (src, dst)

        # 1. Update edge frequency
        prev_count, _ = self._edge_counts.get(edge_key, (0, now))
        new_count = prev_count + 1
        self._edge_counts[edge_key] = (new_count, now)

        # 2. Update probed ports for pair
        ports_list = self._probed_ports.setdefault(pair_key, [])
        ports_list.append((port, now))

        # 3. Sensitive-port check
        if port in SENSITIVE_PORTS:
            signals.append(self._sensitive_port_signal(src, dst, port, new_count))

        # 4. Connection frequency & internal recon check
        # Filter distinct ports probed within correlation_window
        recent_ports = {
            p for p, ts in self._probed_ports[pair_key]
            if (now - ts) <= self.correlation_window
        }
        if len(recent_ports) >= RECON_PORT_THRESHOLD:
            last_alerted = self._alerted_recon.get(pair_key)
            if last_alerted is None or (now - last_alerted) >= self.dedup_ttl:
                self._alerted_recon[pair_key] = now
                signals.append(self._internal_recon_signal(src, dst, len(recent_ports)))
                logger.info(
                    "internal recon detected: %s → %s (%d ports)",
                    src, dst, len(recent_ports),
                )

        # 5. Two-hop lateral movement check
        # A container acting as an ingress gateway or proxy should not treat
        # its normal client traffic as an attack pivot.
        if src in self._first_hop_sources and not self._is_proxy_or_gateway(src):
            for hop1_src, hop1_ts in self._first_hop_sources[src]:
                # Temporal correlation requirement: must be within correlation window
                if (now - hop1_ts) <= self.correlation_window and hop1_src != dst:
                    path_key = (hop1_src, src, dst, port)
                    last_alerted = self._alerted_paths.get(path_key)
                    if last_alerted is None or (now - last_alerted) >= self.dedup_ttl:
                        self._alerted_paths[path_key] = now
                        signals.append(self._lateral_path_signal(hop1_src, src, dst, port))
                        logger.info(
                            "lateral path detected: %s → %s → %s:%d (elapsed: %.1fs)",
                            hop1_src, src, dst, port, (now - hop1_ts),
                        )

        # 6. Record dst as a newly-reached container with timestamp
        dst_sources = self._first_hop_sources.setdefault(dst, [])
        # Avoid duplicate (src, ...) entries; update with freshest timestamp
        filtered_sources = [(s, ts) for s, ts in dst_sources if s != src]
        filtered_sources.append((src, now))
        self._first_hop_sources[dst] = filtered_sources

        # 7. Bound memory capacity
        self._enforce_capacity()

        return signals

    def reset(self) -> None:
        """Clear all session state (for testing)."""
        self._first_hop_sources.clear()
        self._alerted_paths.clear()
        self._edge_counts.clear()
        self._probed_ports.clear()
        self._alerted_recon.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_proxy_or_gateway(self, container_id: str) -> bool:
        """Check if container is an ingress gateway, proxy, or high fan-in node."""
        cid_lower = container_id.lower()
        if container_id in self.known_proxies:
            return True
        if any(kw in cid_lower for kw in DEFAULT_PROXY_KEYWORDS):
            return True
        # Dynamic fan-in threshold check: if a node has >= max_fanin distinct clients,
        # it is functioning as a shared intermediary / gateway.
        active_sources = self._first_hop_sources.get(container_id, [])
        if len(active_sources) >= self.max_fanin:
            return True
        return False

    def _prune(self, now: float) -> None:
        """Evict expired entries across all internal tracking structures."""
        # Prune expired first_hop_sources (older than correlation_window)
        for dst in list(self._first_hop_sources.keys()):
            valid = [
                (s, ts) for s, ts in self._first_hop_sources[dst]
                if (now - ts) <= self.correlation_window
            ]
            if valid:
                self._first_hop_sources[dst] = valid
            else:
                del self._first_hop_sources[dst]

        # Prune expired probed_ports (older than correlation_window)
        for pair in list(self._probed_ports.keys()):
            valid = [
                (p, ts) for p, ts in self._probed_ports[pair]
                if (now - ts) <= self.correlation_window
            ]
            if valid:
                self._probed_ports[pair] = valid
            else:
                del self._probed_ports[pair]

        # Prune expired alerted_paths (older than dedup_ttl)
        for path, ts in list(self._alerted_paths.items()):
            if (now - ts) >= self.dedup_ttl:
                del self._alerted_paths[path]

        # Prune expired alerted_recon (older than dedup_ttl)
        for pair, ts in list(self._alerted_recon.items()):
            if (now - ts) >= self.dedup_ttl:
                del self._alerted_recon[pair]

        # Prune expired edge_counts (older than dedup_ttl)
        for edge, (_, ts) in list(self._edge_counts.items()):
            if (now - ts) >= self.dedup_ttl:
                del self._edge_counts[edge]

    def _enforce_capacity(self) -> None:
        """Ensure no collection exceeds max_entries."""
        if len(self._first_hop_sources) > self.max_entries:
            # Drop oldest keys
            excess = len(self._first_hop_sources) - self.max_entries
            for k in list(self._first_hop_sources.keys())[:excess]:
                del self._first_hop_sources[k]

        if len(self._alerted_paths) > self.max_entries:
            excess = len(self._alerted_paths) - self.max_entries
            for k in list(self._alerted_paths.keys())[:excess]:
                del self._alerted_paths[k]

        if len(self._alerted_recon) > self.max_entries:
            excess = len(self._alerted_recon) - self.max_entries
            for k in list(self._alerted_recon.keys())[:excess]:
                del self._alerted_recon[k]

        if len(self._edge_counts) > self.max_entries:
            excess = len(self._edge_counts) - self.max_entries
            for k in list(self._edge_counts.keys())[:excess]:
                del self._edge_counts[k]

        if len(self._probed_ports) > self.max_entries:
            excess = len(self._probed_ports) - self.max_entries
            for k in list(self._probed_ports.keys())[:excess]:
                del self._probed_ports[k]

    def _sensitive_port_signal(
        self,
        src: str,
        dst: str,
        port: int,
        connection_count: int,
    ) -> dict:
        service = SENSITIVE_PORTS[port]
        mitre = SENSITIVE_PORT_MITRE.get(port)
        return {
            "kind": "graph_sensitive_port",
            "score": 1.0,
            "src": src,
            "dst": dst,
            "port": port,
            "service": service,
            "connection_count": connection_count,
            "mitre": mitre,
            "reason": (
                f"Unusual connection attempt to sensitive service '{service}' observed on port {port}."
            ),
        }

    def _internal_recon_signal(self, src: str, dst: str, port_count: int) -> dict:
        return {
            "kind": "graph_internal_recon",
            "score": 1.0,
            "src": src,
            "dst": dst,
            "port_count": port_count,
            "mitre": "T1046",
            "reason": (
                f"Suspicious connection frequency observed: {src} attempted "
                f"{port_count} distinct ports on {dst}. Potential internal reconnaissance."
            ),
        }

    def _lateral_path_signal(
        self,
        hop1_src: str,
        intermediate: str,
        dst: str,
        port: int,
    ) -> dict:
        path = [hop1_src, intermediate, dst]
        return {
            "kind": "graph_lateral_path",
            "score": 1.0,
            "path": path,
            "port": port,
            "mitre": "T1021",
            "reason": (
                f"Suspicious multi-hop communication sequence observed: "
                f"{hop1_src} → {intermediate} → {dst}:{port}. Potential lateral movement."
            ),
        }

"""Port scan attack — probes distinct listening ports across the Docker network.

Detection: RULE-003 (port_scan, T1046, HIGH severity).
Mechanism: Connects to 7 distinct service ports across different containers
within the 30s sliding window, exceeding the threshold of 5 distinct
destination ports.  Every target is a confirmed-open service so the BPF
tracepoint captures both open (TCP_ESTABLISHED) and close events — refused
connections do not reliably generate events on this kernel.

Expected result: A single HIGH-severity alert tagged T1046
("Network Service Discovery") appears on the dashboard.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts import banner, log, tcp_connect

# (host, port) tuples — each is a confirmed-open service on the Docker
# network.  All ports are below EPHEMERAL_PORT_MIN (32768) so the rule
# engine counts them as service-port probes.
TARGETS = [
    ("demo-api",  5000),
    ("demo-web",    80),
    ("demo-db",   5432),
    ("redis",     6379),
    ("neo4j",     7474),
    ("neo4j",     7687),
    ("backend",   8000),
]

DELAY_BETWEEN_PROBES = 0.3  # seconds — fast enough to fit the 30s window


def main() -> None:
    banner("PORT SCAN — RULE-003 / T1046")
    log(f"Scanning {len(TARGETS)} distinct service ports (threshold: 5 in 30s)")
    log("")

    opened = 0
    closed = 0
    for host, port in TARGETS:
        result = tcp_connect(host, port, timeout=1.0)
        if result:
            opened += 1
            log(f"  {host}:{port}  OPEN")
        else:
            closed += 1
            log(f"  {host}:{port}  closed")
        time.sleep(DELAY_BETWEEN_PROBES)

    log("")
    log(f"Scan complete: {opened} open, {closed} closed out of {len(TARGETS)} probed")
    log(f"Distinct ports probed: {len(TARGETS)} (threshold: 5)")
    log("Expected detection: RULE-003 port_scan T1046 HIGH")


if __name__ == "__main__":
    main()

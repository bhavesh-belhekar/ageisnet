"""Known-bad IP attack — traffic from a threat-intel-listed source IP.

Detection: RULE-001 (known_bad_ip_connection, T1071, HIGH severity).
Mechanism: The attacker-sim container is assigned a fixed Docker IP
(172.18.0.100) that is listed in data/threat_intel/known_bad_indicators.csv.
Connections to demo-api generate eBPF events where src_ip matches the
known-bad indicator, triggering RULE-001.

Expected result: A single HIGH-severity alert tagged T1071
("Application Layer Protocol") appears on the dashboard.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

from scripts import banner, get_target_host, log, http_get

# Target a reachable service — the detection fires on src_ip matching
# the known-bad indicator (attacker-sim's fixed Docker IP).
TARGET_HOST = "demo-api"
TARGET_PORT = 5000
TARGET_PATH = "/health"

ROUNDS = 3
INTERVAL = 1.0  # seconds between rounds


def main() -> None:
    banner("KNOWN-BAD IP — RULE-001 / T1071")
    log(f"Source IP: 172.18.0.100 (listed in threat-intel CSV)")
    log(f"Target: {TARGET_HOST}:{TARGET_PORT}{TARGET_PATH}")
    log(f"Rounds: {ROUNDS}")
    log("")

    for round_num in range(1, ROUNDS + 1):
        log(f"--- Round {round_num}/{ROUNDS} ---")
        status, body = http_get(TARGET_HOST, TARGET_PORT, TARGET_PATH, timeout=3.0)
        log(f"  GET {TARGET_HOST}:{TARGET_PORT}{TARGET_PATH} → HTTP {status}")
        if round_num < ROUNDS:
            time.sleep(INTERVAL)

    log("")
    log(f"Completed {ROUNDS} requests from known-bad source IP")
    log("Expected detection: RULE-001 known_bad_ip_connection T1071 HIGH")


if __name__ == "__main__":
    main()

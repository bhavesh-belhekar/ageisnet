"""Lateral movement attack — unauthorized connection to demo-db.

Detection: RULE-004 (restricted_protocol, T1571, HIGH) + graph_model
anomaly (T1021.001).
Mechanism: Connects from attacker-sim to demo-db:5432.  The
risk_policy.yaml restricts demo-db:5432 to only demo-api as an allowed
source — attacker-sim is not whitelisted.  Additionally, the
attacker-sim → demo-db edge has never been seen in the graph baseline,
triggering the graph_model's never-seen-edge detector.

Expected results:
  1. RULE-004 alert: T1571 HIGH ("Restricted access: container ... not
     whitelisted")
  2. graph_model alert: T1021.001 ("Lateral Movement") — new unseen edge
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

from scripts import banner, get_target_host, log, tcp_connect, send_data

ROUNDS = 5  # multiple connections to ensure graph_model baseline miss


def main() -> None:
    banner("LATERAL MOVEMENT — RULE-004 / T1571 + graph_model / T1021.001")
    target = get_target_host("demo-db")
    log(f"Target: {target}:5432 (PostgreSQL)")
    log(f"Source: attacker-sim (NOT in allowed_sources for demo-db)")
    log(f"Rounds: {ROUNDS}")
    log("")

    for i in range(1, ROUNDS + 1):
        log(f"--- Round {i}/{ROUNDS} ---")

        # Attempt TCP connection to PostgreSQL port
        result = tcp_connect(target, 5432, timeout=2.0)
        if result:
            log(f"  TCP connected to {target}:5432")
            # Send a short PostgreSQL startup-like payload to generate
            # observable bytes_sent/bytes_received for flow_model
            payload = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
            sent = send_data(target, 5432, payload, timeout=2.0)
            log(f"  Sent {len(payload)} bytes, received {sent} bytes response")
        else:
            log(f"  Connection to {target}:5432 refused/failed (expected)")

        time.sleep(0.5)

    log("")
    log(f"Completed {ROUNDS} connections to demo-db:5432")
    log("Expected detections:")
    log("  1. RULE-004 restricted_protocol T1571 HIGH")
    log("  2. graph_model unseen edge T1021.001")


if __name__ == "__main__":
    main()

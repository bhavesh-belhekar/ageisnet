"""Data exfiltration attack — large outbound transfer simulating data theft.

Detection: flow_model anomaly (T1041, ML-based).
Mechanism: Sends large POST requests to demo-api, simulating data being
exfiltrated.  The flow model's feature window will see unusually high
bytes_sent compared to normal traffic patterns.  The 6-feature vector
(total_bytes_sent, total_bytes_received, connection_count,
unique_dst_ports, unique_dst_ips, window_seconds) will show a byte
volume spike that the Isolation Forest flags as anomalous.

Expected result: An ML-flagged alert with flow_model anomaly score
exceeding the 0.52 threshold, tagged T1041 ("Exfiltration Over Web
Service").
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

from scripts import banner, get_target_host, http_post, log

# Simulate exfiltrating data in chunks — each POST sends ~50KB of
# payload (realistic for credential dumps, database exports, etc.)
CHUNK_SIZE = 50_000       # bytes per POST body
CHUNK_COUNT = 20          # total chunks (= ~1MB exfiltrated)
DELAY_BETWEEN = 0.5       # seconds between chunks


def main() -> None:
    banner("DATA EXFILTRATION — flow_model / T1041")
    target = get_target_host("demo-api")
    log(f"Target: {target}:5000/api/orders (POST)")
    log(f"Payload: {CHUNK_SIZE} bytes × {CHUNK_COUNT} chunks = "
        f"{CHUNK_SIZE * CHUNK_COUNT / 1024:.0f} KB total")
    log("")

    success = 0
    failed = 0
    for i in range(1, CHUNK_COUNT + 1):
        # Generate payload that looks like order data (realistic cover)
        payload = json.dumps({
            "user_id": 1,
            "product_id": 1,
            "quantity": 1,
            "_exfil_chunk": i,
            "_padding": "A" * (CHUNK_SIZE - 200),
        }).encode()

        code, body = http_post(
            target, 5000, "/api/orders",
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
    log("Expected detection: flow_model anomaly T1041")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Manual verification script to trigger and verify real-time alerts over WebSocket.

Can:
1. POST a test alert to the backend (http://localhost:8000/api/alerts/test),
   which persists and broadcasts it to all connected WebSocket dashboard clients.
2. Listen on ws://localhost:8000/ws/alerts to demonstrate live alert reception.

Usage:
    # Trigger a High severity alert with MITRE T1071 (Application Layer Protocol):
    python scripts/trigger_test_alert.py

    # Trigger a Lateral Movement alert (T1021 / TA0008):
    python scripts/trigger_test_alert.py --technique T1021 --desc "Multi-hop lateral movement demo"

    # Trigger an Internal Reconnaissance alert (T1046 / TA0007):
    python scripts/trigger_test_alert.py --technique T1046 --desc "Port scan demo"

    # Listen to the live WebSocket feed in terminal:
    python scripts/trigger_test_alert.py --listen
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def trigger_alert(
    base_url: str,
    container_id: str,
    severity: str,
    technique_id: str,
    description: str,
) -> dict:
    url = f"{base_url.rstrip('/')}/api/alerts/test"
    payload = {
        "container_id": container_id,
        "severity": severity,
        "detection_type": "rule",
        "technique_id": technique_id,
        "description": description,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.URLError as e:
        print(f"[!] Failed to connect to {url}: {e}")
        print("    Ensure the backend server is running (e.g., uvicorn or docker compose up).")
        sys.exit(1)


def listen_websocket(ws_url: str) -> None:
    try:
        import websockets
        import asyncio
    except ImportError:
        print("[!] 'websockets' package is required for --listen mode.")
        print("    Run: pip install websockets")
        sys.exit(1)

    async def _listener():
        print(f"[*] Connecting to {ws_url} ...")
        try:
            async with websockets.connect(ws_url) as ws:
                print(f"[+] Connected! Listening for real-time alerts (Press Ctrl+C to stop)...")
                while True:
                    msg = await ws.recv()
                    data = json.loads(msg)
                    if data.get("update_type") == "shap_attachment":
                        print(f"\n[SHAP UPDATE] Alert ID: {data.get('alert_id')}")
                    else:
                        print("\n" + "=" * 60)
                        print(f"[ALERT RECEIVED] Alert #{data.get('alert_id')} - Severity: {data.get('severity', '').upper()}")
                        print(f"  Container: {data.get('container_id')}")
                        print(f"  Timestamp: {data.get('timestamp')}")
                        print(f"  MITRE Technique: {data.get('mitre_technique_id')} ({data.get('mitre_technique_name')})")
                        print(f"  MITRE Tactic:    {data.get('mitre_tactic_id')} ({data.get('mitre_tactic_name')})")
                        print(f"  Description:     {data.get('description')}")
                        print("=" * 60)
        except Exception as e:
            print(f"[!] WebSocket connection error: {e}")

    try:
        asyncio.run(_listener())
    except KeyboardInterrupt:
        print("\n[*] Disconnected.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger and inspect AegisNet real-time alerts.")
    parser.add_argument("--url", default="http://localhost:8000", help="Backend base URL")
    parser.add_argument("--container", default="demo-attacker", help="Container ID for alert")
    parser.add_argument("--severity", default="high", choices=["medium", "high"], help="Alert severity")
    parser.add_argument(
        "--technique",
        default="T1071",
        choices=["T1071", "T1071.001", "T1043", "T1046", "T1571", "T1041", "T1021"],
        help="MITRE ATT&CK technique ID",
    )
    parser.add_argument(
        "--desc",
        default="Manual verification: real-time alert delivery verified over WebSocket",
        help="Alert description",
    )
    parser.add_argument(
        "--listen",
        action="store_true",
        help="Connect to WebSocket stream and print received alerts live",
    )

    args = parser.parse_args()

    if args.listen:
        ws_url = args.url.replace("http://", "ws://").replace("https://", "wss://").rstrip("/") + "/ws/alerts"
        listen_websocket(ws_url)
    else:
        print(f"[*] Sending test alert to {args.url} ...")
        result = trigger_alert(
            args.url,
            args.container,
            args.severity,
            args.technique,
            args.desc,
        )
        print("\n" + "=" * 60)
        print("[+] Test Alert Broadcast Successfully!")
        print(f"  Alert ID:        {result.get('alert_id')}")
        print(f"  Container:       {result.get('container_id')}")
        print(f"  Severity:        {result.get('severity')}")
        print(f"  MITRE Technique: {result.get('mitre_technique_id')} ({result.get('mitre_technique_name')})")
        print(f"  MITRE Tactic:    {result.get('mitre_tactic_id')} ({result.get('mitre_tactic_name')})")
        print(f"  Description:     {result.get('description')}")
        print("=" * 60)
        print("Check your browser dashboard at http://localhost:5173 - the alert should appear live in the feed.")


if __name__ == "__main__":
    main()

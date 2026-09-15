"""Generate sustained normal traffic into the demo-app for baseline collection.

Runs from the host, hitting demo-web (localhost:8080) and demo-api
Directly (localhost:8081).  The resulting eBPF-captured events populate
the flow_model external-feature windows and graph_model edge baselines
needed for FP validation in Phase 8.

Usage (from repo root, with docker-compose up running):
    python scripts/seed_demo_data.py
    python scripts/seed_demo_data.py --duration 60 --interval 1.5

The script is non-destructive: it reads existing products/stats and
creates orders in the demo-api in-memory SQLite store.
"""

from __future__ import annotations

import argparse
import json
import random
import signal
import sys
import time
import urllib.error
import urllib.request

DEMO_WEB = "http://127.0.0.1:8080"
DEMO_API = "http://127.0.0.1:8081"

_STOP = False


def _handle_signal(signum: int, frame: object) -> None:
    global _STOP
    _STOP = True
    print("\nReceived interrupt, finishing...")


def _get(url: str, timeout: float = 5.0) -> int:
    """GET request, returns HTTP status code or 0 on failure."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _post(url: str, data: dict, timeout: float = 5.0) -> int:
    """POST request with JSON body, returns HTTP status code or 0 on failure."""
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _browse_products(base: str) -> int:
    return _get(f"{base}/api/products")


def _view_stats(base: str) -> int:
    return _get(f"{base}/api/stats")


def _create_order(base: str) -> int:
    uid = random.randint(1, 5)
    pid = random.randint(1, 5)
    qty = random.randint(1, 3)
    return _post(f"{base}/api/orders", {"user_id": uid, "product_id": pid, "quantity": qty})


def _health_check(base: str) -> int:
    return _get(f"{base}/health")


ACTIONS = [
    ("browse_products", _browse_products, 1.0),
    ("view_stats", _view_stats, 1.0),
    ("create_order", _create_order, 0.4),
    ("health_check", _health_check, 0.6),
]


def _pick_action() -> tuple[str, callable, str]:
    """Weighted random action selection. Returns (name, fn, base_url)."""
    name, fn, weight = random.choices(
        ACTIONS, weights=[a[2] for a in ACTIONS], k=1
    )[0]
    # Health checks go to demo-api directly (probes demo-db connectivity);
    # everything else goes through demo-web (generates proxy hops).
    base = DEMO_API if name == "health_check" else DEMO_WEB
    return name, fn, base


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Total run time in minutes (default: 30)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between requests (default: 2.0)",
    )
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    end_time = time.time() + args.duration * 60
    request_count = 0
    error_count = 0
    start = time.time()

    print(f"Seeding demo traffic for {args.duration}m (interval={args.interval}s)")
    print(f"  demo-web:  {DEMO_WEB}")
    print(f"  demo-api:  {DEMO_API}")
    print(f"  Press Ctrl+C to stop early.\n")

    while time.time() < end_time and not _STOP:
        name, fn, base = _pick_action()
        status = fn(base)
        request_count += 1

        if status == 0:
            error_count += 1

        if request_count % 50 == 0:
            elapsed = time.time() - start
            print(
                f"  [{elapsed / 60:.1f}m] {request_count} requests "
                f"({error_count} errors)"
            )

        time.sleep(args.interval + random.uniform(-0.3, 0.3))

    elapsed = time.time() - start
    print(f"\nDone: {request_count} requests in {elapsed / 60:.1f}m ({error_count} errors)")
    print(f"Estimated events generated: ~{request_count * 4} (4 events per connection)")
    print("\nNext steps:")
    print("  1. Wait ~5 min for events to propagate through the pipeline")
    print("  2. Run: python scripts/collect_baseline.py")
    print("  3. Run: python -m backend.app.ml_engine.flow_model.train")


if __name__ == "__main__":
    main()

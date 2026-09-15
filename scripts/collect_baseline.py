"""Collect baseline normal traffic features from Postgres for ML training.

Queries ``raw_events`` for external (north-south) events, aggregates per
(container_id, 5-minute window), extracts flow-model features, and writes
two CSVs to ``data/training_baselines/``:

    normal_baseline_train.csv  (80 %)
    normal_baseline_val.csv    (20 %)

Features per window:
    - total_bytes_sent
    - total_bytes_received
    - connection_count          (number of close events — one per connection)
    - unique_dst_ports          (port diversity — proxy for port entropy)
    - unique_dst_ips
    - window_seconds            (actual span of timestamps in the window)

Usage (from repo root, with Postgres reachable):
    python scripts/collect_baseline.py

Env vars (same as backend): POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER,
POSTGRES_PASSWORD, POSTGRES_DB — or fall back to .env / defaults.
"""

from __future__ import annotations

import csv
import math
import os
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Allow running from repo root without installing the backend package.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "backend"))

from app.config.settings import get_settings  # noqa: E402

# ---------------------------------------------------------------------------
# Feature-window config — must match risk_policy.yaml flow_model_feature_minutes
# ---------------------------------------------------------------------------
WINDOW_MINUTES = 5

OUTPUT_DIR = _REPO_ROOT / "data" / "training_baselines"
TRAIN_FILE = OUTPUT_DIR / "normal_baseline_train.csv"
VAL_FILE = OUTPUT_DIR / "normal_baseline_val.csv"

FEATURE_COLUMNS = [
    "total_bytes_sent",
    "total_bytes_received",
    "connection_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "window_seconds",
]


def _connect():
    """Return a psycopg2 connection (sync) to Postgres."""
    try:
        import psycopg2
    except ImportError:
        sys.exit(
            "ERROR: psycopg2 is required.  Install with:\n"
            "  pip install psycopg2-binary"
        )

    s = get_settings()
    return psycopg2.connect(
        host=s.postgres_host,
        port=s.postgres_port,
        user=s.postgres_user,
        password=s.postgres_password,
        dbname=s.postgres_db,
    )


def _fetch_external_events(conn) -> list[dict]:
    """Fetch all external close events from raw_events."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT container_id, event_timestamp, event_type,
               dst_ip, dst_port, bytes_sent, bytes_received
        FROM raw_events
        WHERE direction = 'external'
        ORDER BY container_id, event_timestamp
        """
    )
    rows = cur.fetchall()
    cur.close()
    return [
        {
            "container_id": r[0],
            "timestamp": r[1],
            "event_type": r[2],
            "dst_ip": r[3],
            "dst_port": r[4],
            "bytes_sent": r[5],
            "bytes_received": r[6],
        }
        for r in rows
    ]


def _bucket_key(timestamp, window_minutes: int = WINDOW_MINUTES):
    """Return a bucket key: (container_id_floor, window_start_iso)."""
    from datetime import timezone

    ts = timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    # Floor to the nearest window boundary
    epoch_s = ts.timestamp()
    bucket_start_s = epoch_s - (epoch_s % (window_minutes * 60))
    from datetime import datetime, timezone

    bucket_start = datetime.fromtimestamp(bucket_start_s, tz=timezone.utc)
    return bucket_start.isoformat()


def _aggregate(events: list[dict]) -> list[dict]:
    """Group events by (container_id, 5-min window) and extract features."""
    buckets: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "bytes_sent": 0,
            "bytes_received": 0,
            "close_count": 0,
            "dst_ports": set(),
            "dst_ips": set(),
            "timestamps": [],
        }
    )

    for ev in events:
        cid = ev["container_id"]
        key = (cid, _bucket_key(ev["timestamp"]))
        b = buckets[key]
        b["bytes_sent"] += ev["bytes_sent"]
        b["bytes_received"] += ev["bytes_received"]
        if ev["event_type"] == "close":
            b["close_count"] += 1
        b["dst_ports"].add(ev["dst_port"])
        b["dst_ips"].add(ev["dst_ip"])
        b["timestamps"].append(ev["timestamp"])

    rows = []
    for (cid, window_start), b in sorted(buckets.items()):
        ts_list = b["timestamps"]
        if len(ts_list) < 2:
            window_seconds = WINDOW_MINUTES * 60
        else:
            span = ts_list[-1] - ts_list[0]
            window_seconds = max(span.total_seconds(), 1.0)

        rows.append(
            {
                "container_id": cid,
                "window_start": window_start,
                "total_bytes_sent": b["bytes_sent"],
                "total_bytes_received": b["bytes_received"],
                "connection_count": b["close_count"],
                "unique_dst_ports": len(b["dst_ports"]),
                "unique_dst_ips": len(b["dst_ips"]),
                "window_seconds": round(window_seconds, 2),
            }
        )
    return rows


def _write_csv(rows: list[dict], path: Path) -> None:
    """Write feature rows to a CSV file."""
    fieldnames = ["container_id", "window_start"] + FEATURE_COLUMNS
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    print("Connecting to Postgres...")
    conn = _connect()

    print("Fetching external events...")
    events = _fetch_external_events(conn)
    conn.close()
    print(f"  Fetched {len(events)} external events")

    if not events:
        print(
            "\nNo external events found in raw_events.\n"
            "Run the demo environment and generate some normal external "
            "traffic first, then re-run this script.\n"
        )
        sys.exit(1)

    print(f"Aggregating into {WINDOW_MINUTES}-minute windows...")
    rows = _aggregate(events)
    print(f"  Produced {len(rows)} feature windows")

    if len(rows) < 10:
        print(
            f"\nWARNING: Only {len(rows)} windows produced.  Ideally we want "
            "50+ windows for a meaningful baseline.  Consider running the "
            "demo environment longer and re-running this script.\n"
        )

    # Shuffle before splitting (deterministic seed for reproducibility)
    import random

    random.seed(42)
    random.shuffle(rows)

    split_idx = int(len(rows) * 0.8)
    train_rows = sorted(rows[:split_idx], key=lambda r: r["window_start"])
    val_rows = sorted(rows[split_idx:], key=lambda r: r["window_start"])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    _write_csv(train_rows, TRAIN_FILE)
    _write_csv(val_rows, VAL_FILE)

    print(f"\nBaseline data written:")
    print(f"  Train: {TRAIN_FILE}  ({len(train_rows)} windows)")
    print(f"  Val:   {VAL_FILE}    ({len(val_rows)} windows)")
    print(f"\nNext step: python -m backend.app.ml_engine.flow_model.train")


if __name__ == "__main__":
    main()

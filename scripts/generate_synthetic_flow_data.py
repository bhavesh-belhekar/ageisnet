"""Generate deterministic synthetic flow windows for pipeline smoke testing.

These rows are artificial and are not a substitute for captured network
traffic. They exercise the six-feature contract, model training, alert
threshold, and SHAP evaluation end to end.

    python scripts/generate_synthetic_flow_data.py
    $env:TRAINING_DATA_SOURCE = "synthetic_smoke_test"
    python -m backend.app.ml_engine.flow_model.train
    python scripts/evaluate_flow_model.py --csv data/evaluation/synthetic_labeled.csv
"""

from __future__ import annotations

import csv
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = REPO_ROOT / "data" / "training_baselines"
EVALUATION_DIR = REPO_ROOT / "data" / "evaluation"
FEATURES = [
    "total_bytes_sent",
    "total_bytes_received",
    "connection_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "window_seconds",
]


def _normal_rows(rng: np.random.Generator, count: int) -> np.ndarray:
    """Make varied but bounded benign application traffic feature windows."""
    # Mixture of ordinary low-volume and busier application windows.
    busy = rng.random(count) < 0.22
    sent_median = np.where(busy, 42_000.0, 12_000.0)
    recv_median = np.where(busy, 36_000.0, 10_000.0)
    sent = rng.lognormal(np.log(sent_median), 0.48)
    received = rng.lognormal(np.log(recv_median), 0.5)
    connections = rng.poisson(np.where(busy, 7.0, 2.5)) + 1
    ports = np.minimum(rng.poisson(np.where(busy, 2.0, 0.8)) + 1, 10)
    ips = rng.choice([1, 2, 3, 4], size=count, p=[0.55, 0.28, 0.12, 0.05])
    seconds = rng.uniform(20.0, 300.0, count)
    return np.column_stack((sent, received, connections, ports, ips, seconds))


def _attack_rows(rng: np.random.Generator, count: int) -> np.ndarray:
    """Make held-out exfiltration, scan, and destination-spread examples."""
    rows = _normal_rows(rng, count)
    kinds = rng.integers(0, 3, count)
    exfil = kinds == 0
    scan = kinds == 1
    spread = kinds == 2

    rows[exfil, 0] = rng.uniform(2_000_000, 50_000_000, exfil.sum())
    rows[exfil, 1] = rng.uniform(500, 20_000, exfil.sum())
    rows[exfil, 2] = rng.integers(1, 5, exfil.sum())
    rows[exfil, 4] = rng.integers(1, 4, exfil.sum())

    rows[scan, 2] = rng.integers(20, 180, scan.sum())
    rows[scan, 3] = rng.integers(20, 100, scan.sum())

    rows[spread, 4] = rng.integers(10, 60, spread.sum())
    rows[spread, 2] = rng.integers(10, 50, spread.sum())
    return rows


def _write(path: Path, matrix: np.ndarray, labels: np.ndarray | None = None) -> None:
    fields = FEATURES + (["label"] if labels is not None else [])
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(fields)
        for idx, row in enumerate(matrix):
            values = [f"{value:.3f}" for value in row]
            if labels is not None:
                values.append(int(labels[idx]))
            writer.writerow(values)


def main() -> None:
    rng = np.random.default_rng(20261115)
    train = _normal_rows(rng, 1_000)
    validation = _normal_rows(rng, 250)
    benign_test = _normal_rows(rng, 250)
    attacks = _attack_rows(rng, 150)
    evaluation = np.vstack((benign_test, attacks))
    labels = np.concatenate(
        (np.zeros(len(benign_test), dtype=int), np.ones(len(attacks), dtype=int))
    )
    order = rng.permutation(len(labels))

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    _write(BASELINE_DIR / "normal_baseline_train.csv", train)
    _write(BASELINE_DIR / "normal_baseline_val.csv", validation)
    _write(EVALUATION_DIR / "synthetic_labeled.csv", evaluation[order], labels[order])
    print(f"Generated {len(train)} synthetic train windows")
    print(f"Generated {len(validation)} synthetic normal validation windows")
    print(f"Generated {len(evaluation)} labeled synthetic evaluation windows")
    print("Data are synthetic smoke-test inputs, not real network evidence.")


if __name__ == "__main__":
    main()

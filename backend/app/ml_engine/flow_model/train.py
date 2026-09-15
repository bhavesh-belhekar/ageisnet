"""Isolation Forest training for the flow model (FR-5.1).

Reads the baseline CSV produced by ``scripts/collect_baseline.py``, applies
a configurable percentile cap to feature values, trains an Isolation Forest,
and persists the model as ``data/model_artifacts/flow_model_v2.pkl``.

The saved artifact is a dict containing:

    - ``model``: fitted ``sklearn.ensemble.IsolationForest``
    - ``feature_names``: ordered list of feature column names
    - ``cap_values``: per-feature cap thresholds applied during training
      (features in ``cap_exclude`` are left uncapped; their cap_value is
      the feature's own max so the inference path stays symmetric)
    - ``training_meta``: window count, FP rate on held-out val, config used,
      changelog describing differences from prior versions

Run from the repo root::

    python -m backend.app.ml_engine.flow_model.train

Config (``config/risk_policy.yaml`` → ``flow_model``):

    - ``cap_percentile``: percentile used to cap outliers (default 0.99)
    - ``contamination``: Isolation Forest contamination param (default 0.05)
    - ``random_state``: seed for reproducibility (default 42)
    - ``cap_exclude``: list of feature names to exclude from capping
      (default: ["unique_dst_ips"] — near-binary/categorical, capping
      at the 99th percentile collapses variance to zero)

v2 changelog (vs v1):
    v1 set ``cap_percentile: 1.0`` globally to work around unique_dst_ips
    variance collapse when capping at 0.99.  v2 restores capping at 0.99
    for all features *except* unique_dst_ips, which is excluded via
    ``cap_exclude``.  This properly caps the 7.6M-byte outlier while
    preserving the variance of the near-binary feature.
"""

from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path

import numpy as np
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

_REPO_ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(_REPO_ROOT / "backend"))

from app.config.settings import get_settings  # noqa: E402
from app.ml_engine.flow_model.features import FEATURE_ORDER  # noqa: E402

logger = logging.getLogger("flow_model.train")

_CONFIG_PATH = _REPO_ROOT / "backend" / "app" / "config" / "risk_policy.yaml"
_BASELINE_DIR = _REPO_ROOT / "data" / "training_baselines"
_ARTIFACT_DIR = _REPO_ROOT / "data" / "model_artifacts"

TRAIN_CSV = _BASELINE_DIR / "normal_baseline_train.csv"
VAL_CSV = _BASELINE_DIR / "normal_baseline_val.csv"
ARTIFACT_PATH = _ARTIFACT_DIR / "flow_model_v2.pkl"


def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return yaml.safe_load(f).get("flow_model", {})


def _read_csv(path: Path) -> np.ndarray:
    """Read a baseline CSV and return the feature matrix as a numpy array."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    matrix = np.array(
        [[float(r[col]) for col in FEATURE_ORDER] for r in rows],
        dtype=np.float64,
    )
    return matrix


def _apply_cap(
    matrix: np.ndarray,
    cap_percentile: float,
    exclude_indices: set[int] | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Cap feature values at the given percentile.

    Args:
        matrix: (n_samples, n_features) feature matrix.
        cap_percentile: percentile in [0, 1] to cap at (e.g. 0.99 = 99th).
        exclude_indices: feature indices to leave uncapped.  Their cap_value
            is set to the column max so the returned array has one entry per
            feature (keeps the contract symmetric for the caller).

    Returns:
        (capped_matrix, cap_values) where cap_values has one entry per feature.
    """
    cap_values = np.percentile(matrix, cap_percentile * 100, axis=0)
    if exclude_indices:
        for idx in exclude_indices:
            cap_values[idx] = np.max(matrix[:, idx])
    capped = np.minimum(matrix, cap_values)
    return capped, cap_values


def train() -> dict:
    """Train the Isolation Forest and persist the model artifact.

    Returns the saved artifact dict for inspection.
    """
    import pickle

    config = _load_config()
    cap_pct = config.get("cap_percentile", 0.99)
    contamination = config.get("contamination", 0.05)
    random_state = config.get("random_state", 42)
    cap_exclude_names = config.get("cap_exclude", ["unique_dst_ips"])

    # Map excluded feature names to column indices
    exclude_indices = set()
    for name in cap_exclude_names:
        if name in FEATURE_ORDER:
            exclude_indices.add(FEATURE_ORDER.index(name))
        else:
            logger.warning("cap_exclude feature %r not in FEATURE_ORDER — ignored", name)

    logger.info(
        "config: cap_percentile=%.2f, contamination=%.3f, random_state=%d, "
        "cap_exclude=%s (indices=%s)",
        cap_pct,
        contamination,
        random_state,
        cap_exclude_names,
        sorted(exclude_indices) if exclude_indices else "none",
    )

    # --- Load training data ---
    if not TRAIN_CSV.exists():
        sys.exit(
            f"ERROR: training CSV not found at {TRAIN_CSV}\n"
            "Run scripts/collect_baseline.py first."
        )
    train_matrix = _read_csv(TRAIN_CSV)
    logger.info("loaded %d training windows, %d features", *train_matrix.shape)

    # --- Apply percentile cap (per-feature; excluded features left uncapped) ---
    train_capped, cap_values = _apply_cap(train_matrix, cap_pct, exclude_indices)
    logger.info(
        "cap values per feature: %s",
        {
            name: (f"{v:.2f} (uncapped)" if i in exclude_indices else f"{v:.2f}")
            for i, (name, v) in enumerate(zip(FEATURE_ORDER, cap_values))
        },
    )

    # --- Scale features ---
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_capped)

    # --- Train Isolation Forest ---
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        max_features=1.0,
    )
    model.fit(train_scaled)
    logger.info("Isolation Forest trained: %d estimators", model.n_estimators)

    # --- FP validation on held-out val set ---
    fp_rate = None
    val_count = 0
    if VAL_CSV.exists():
        val_matrix = _read_csv(VAL_CSV)
        val_capped = np.minimum(val_matrix, cap_values)
        val_scaled = scaler.transform(val_capped)
        predictions = model.predict(val_scaled)
        # Isolation Forest: -1 = anomaly, 1 = normal
        val_count = len(predictions)
        anomaly_count = int(np.sum(predictions == -1))
        fp_rate = anomaly_count / val_count if val_count > 0 else 0.0
        logger.info(
            "val FP validation: %d anomalies out of %d windows → FP rate=%.2f%%",
            anomaly_count,
            val_count,
            fp_rate * 100,
        )
    else:
        logger.warning("val CSV not found — skipping FP validation")

    # --- Persist artifact ---
    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "scaler": scaler,
        "feature_names": FEATURE_ORDER,
        "cap_values": dict(zip(FEATURE_ORDER, cap_values.tolist())),
        "training_meta": {
            "train_windows": train_capped.shape[0],
            "val_windows": val_count,
            "cap_percentile": cap_pct,
            "cap_exclude": cap_exclude_names,
            "contamination": contamination,
            "random_state": random_state,
            "fp_rate_on_val": fp_rate,
            "changelog": (
                "v2: restored cap_percentile=0.99 for continuous features; "
                "excluded unique_dst_ips from capping (near-binary, capping "
                "at 99th percentile collapsed variance to zero). v1 had "
                "cap_percentile=1.0 globally to work around this issue."
            ),
        },
    }
    with open(ARTIFACT_PATH, "wb") as f:
        pickle.dump(artifact, f)
    logger.info("model artifact saved to %s", ARTIFACT_PATH)

    return artifact


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    artifact = train()
    meta = artifact["training_meta"]
    print("\n=== Training complete ===")
    print(f"  Train windows:  {meta['train_windows']}")
    print(f"  Val windows:    {meta['val_windows']}")
    print(f"  Cap percentile: {meta['cap_percentile']}")
    print(f"  Cap exclude:    {meta['cap_exclude']}")
    print(f"  Contamination:  {meta['contamination']}")
    print(f"  Random state:   {meta['random_state']}")
    if meta["fp_rate_on_val"] is not None:
        target = 0.10
        fp = meta["fp_rate_on_val"]
        status = "PASS" if fp <= target else "FAIL"
        print(f"  FP rate (val):  {fp*100:.1f}%  (target <{target*100:.0f}%) [{status}]")
    if "changelog" in meta:
        print(f"  Changelog:      {meta['changelog']}")
    print(f"  Artifact:       {ARTIFACT_PATH}")


if __name__ == "__main__":
    main()

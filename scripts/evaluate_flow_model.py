"""Evaluate a trained flow model against labeled, captured feature windows.

Input CSV must contain the six flow features from ``FEATURE_ORDER`` and a
``label`` column (0 = normal, 1 = attack). Keep this test data separate from
the normal windows used to fit the model. The script reports classification
metrics at the configured alert threshold and verifies SHAP payloads for
every predicted anomaly.

    python scripts/evaluate_flow_model.py --csv data/evaluation/flow_labeled.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.ml_engine.flow_model.features import FEATURE_ORDER, preprocess_features  # noqa: E402
import yaml  # noqa: E402


def load_labeled_csv(path: Path) -> tuple[np.ndarray, np.ndarray]:
    with path.open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise ValueError(f"evaluation CSV is empty: {path}")
    if "label" not in rows[0]:
        raise ValueError("evaluation CSV must include label (0=normal, 1=attack)")
    labels = np.asarray([int(row["label"]) for row in rows], dtype=np.int8)
    if not set(np.unique(labels)).issubset({0, 1}) or len(np.unique(labels)) < 2:
        raise ValueError("evaluation data must contain both normal (0) and attack (1) labels")
    matrix = np.asarray(
        [[float(row[name]) for name in FEATURE_ORDER] for row in rows], dtype=np.float64
    )
    if not np.isfinite(matrix).all() or (matrix < 0).any():
        raise ValueError("evaluation features must be finite, non-negative numbers")
    return matrix, labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True, help="labeled, held-out feature CSV")
    args = parser.parse_args()

    from app.ml_engine.flow_model import infer
    from app.explainability import shap_explainer

    bundle = infer._load_model()
    if bundle is None:
        raise SystemExit(
            f"trained model unavailable: {infer.ARTIFACT_PATH}"
        )
    matrix, labels = load_labeled_csv(args.csv)
    raw, scaled = preprocess_features(
        matrix,
        scaler=bundle["scaler"],
        feature_names=bundle.get("feature_names", FEATURE_ORDER),
        cap_values=bundle.get("cap_values"),
        cap_exclude=bundle.get("training_meta", {}).get("cap_exclude", []),
        apply_caps=False,
    )
    scores = 1.0 / (1.0 + np.exp(bundle["model"].decision_function(scaled)))
    with (REPO_ROOT / "backend" / "app" / "config" / "risk_policy.yaml").open() as file:
        threshold = yaml.safe_load(file)["ml_thresholds"][
            "flow_model_anomaly_threshold"
        ]
    predicted = scores >= threshold
    actual = labels == 1
    tp = int(np.sum(predicted & actual))
    fp = int(np.sum(predicted & ~actual))
    fn = int(np.sum(~predicted & actual))
    tn = int(np.sum(~predicted & ~actual))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    explanations = 0
    # Explain every held-out sample, including missed attacks and false
    # negatives, so evaluation does not skip SHAP when the model alerts zero times.
    for idx in range(len(labels)):
        explanation = asyncio.run(
            shap_explainer.explain_flow(
                alert_id=int(idx),
                feature_names=FEATURE_ORDER,
                raw_features=dict(zip(FEATURE_ORDER, raw[idx].tolist())),
                scaled_vector=scaled[idx].tolist(),
            )
        )
        if not explanation or explanation.get("explanation_type") != "shap":
            raise RuntimeError(f"SHAP explanation failed for evaluation row {idx}")
        contributions = explanation.get("all_contributions", {})
        if set(contributions) != set(FEATURE_ORDER) or not all(
            np.isfinite(item["shap"]) for item in contributions.values()
        ):
            raise RuntimeError(f"invalid SHAP values for evaluation row {idx}")
        if explanation["additivity_error"] > 1e-4:
            raise RuntimeError(
                f"SHAP values do not reconstruct model output for evaluation row {idx}: "
                f"error={explanation['additivity_error']}"
            )
        explanations += 1

    result = {
        "rows": len(labels),
        "threshold": threshold,
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
        },
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "normal_false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "attack_recall": round(recall, 4),
        "shap_explanations_verified": explanations,
        "predicted_anomalies_explained": int(np.sum(predicted)),
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Explainability module — SHAP for flow_model, rule-based for graph_model.

Provides two explainer paths:

1. **Flow model (Isolation Forest):** Uses SHAP's exact explainer over
   the model's ``decision_function`` and a representative training sample.
   This matches the output used by inference (higher means more normal),
   so contribution direction is meaningful to the alert score.

2. **Graph model (heuristic):** Not a trained model — returns a
   deterministic ``explanation_type: "rule_based"`` dict describing
   which edge triggered the anomaly and why.  No SHAP values are
   computed because there are no learned weights to decompose.

Both return a JSON-serializable dict suitable for storage in the
``shap_explanation`` JSONB column on ``raw_alerts``.

Usage (called asynchronously after alert persist)::

    from app.explainability.shap_explainer import explain_flow, explain_graph

    explanation = await explain_flow(alert_id, event, features)
    explanation = await explain_graph(alert_id, event, detail)
"""

from __future__ import annotations

import logging
import os
import pickle
import time
import traceback
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger("shap_explainer")

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ARTIFACT_DIR = Path(
    os.environ.get("MODEL_ARTIFACT_DIR", str(_REPO_ROOT / "data" / "model_artifacts"))
)
_ARTIFACT_PATH = Path(_ARTIFACT_DIR) / "flow_model_v2.pkl"

_tree_explainer: Any = None
_model_bundle: dict | None = None


def _ensure_explainer() -> tuple[Any, dict] | None:
    """Lazily load the model and create the TreeExplainer.

    Returns (explainer, bundle) or None on failure.
    """
    global _tree_explainer, _model_bundle

    if _tree_explainer is not None and _model_bundle is not None:
        return _tree_explainer, _model_bundle

    if not _ARTIFACT_PATH.exists():
        logger.critical("model artifact not found at %s — SHAP disabled", _ARTIFACT_PATH)
        return None

    try:
        import shap
        with open(_ARTIFACT_PATH, "rb") as f:
            _model_bundle = pickle.load(f)

        model = _model_bundle["model"]
        background = _model_bundle.get("shap_background")
        if background is None or np.asarray(background).ndim != 2:
            raise ValueError("model artifact has no valid SHAP background; retrain the model")
        masker = shap.maskers.Independent(np.asarray(background, dtype=np.float64))
        _tree_explainer = shap.Explainer(model.decision_function, masker, algorithm="exact")
        logger.info("Exact SHAP explainer initialized for IsolationForest decision_function")
        return _tree_explainer, _model_bundle
    except Exception:
        logger.critical("SHAP explainer init failed\n%s", traceback.format_exc())
        return None


async def explain_flow(
    alert_id: int,
    feature_names: list[str],
    raw_features: dict[str, float],
    scaled_vector: list[float],
) -> dict | None:
    """Compute SHAP explanation for a flow_model alert.

    Args:
        alert_id: The alert's DB primary key (for logging).
        feature_names: Ordered feature names (FEATURE_ORDER).
        raw_features: Original (unscaled) feature values.
        scaled_vector: Scaled feature vector passed to the model.

    Returns:
        JSON-serializable explanation dict, or None on failure.
    """
    result = _ensure_explainer()
    if result is None:
        return None

    explainer, bundle = result
    t0 = time.time()

    try:
        expected_names = bundle.get("feature_names", feature_names)
        if list(feature_names) != list(expected_names):
            raise ValueError("feature order does not match the trained model artifact")
        arr = np.asarray([scaled_vector], dtype=np.float64)
        if arr.shape[1] != len(feature_names) or not np.isfinite(arr).all():
            raise ValueError("scaled feature vector has invalid shape or values")

        shap_result = explainer(arr)
        shap_values = np.asarray(shap_result.values[0], dtype=np.float64)
        base_value = float(np.asarray(shap_result.base_values).reshape(-1)[0])
        if shap_values.shape != (len(feature_names),) or not np.isfinite(shap_values).all():
            raise ValueError("SHAP returned invalid contribution values")
        decision_score = float(bundle["model"].decision_function(arr)[0])
        additivity_error = abs(base_value + float(shap_values.sum()) - decision_score)

        # Build per-feature explanation
        contributions = {}
        for i, name in enumerate(feature_names):
            contributions[name] = {
                "value": raw_features.get(name, 0.0),
                "shap": float(round(shap_values[i], 6)),
                "direction": "anomaly_push" if shap_values[i] < 0 else "normalizing",
            }

        # Sort by absolute SHAP value (most impactful first)
        sorted_features = sorted(
            contributions.items(),
            key=lambda kv: abs(kv[1]["shap"]),
            reverse=True,
        )

        elapsed_ms = round((time.time() - t0) * 1000, 1)
        logger.info(
            "SHAP computed for alert %d in %.1fms — top contributor: %s (%.4f)",
            alert_id,
            elapsed_ms,
            sorted_features[0][0],
            sorted_features[0][1]["shap"],
        )

        return {
            "explanation_type": "shap",
            "model": "isolation_forest",
            "output": "decision_function (higher means more normal)",
            "base_value": float(round(base_value, 6)),
            "decision_score": float(round(decision_score, 6)),
            "additivity_error": float(round(additivity_error, 8)),
            "top_features": [
                {"feature": name, **data}
                for name, data in sorted_features[:3]
            ],
            "all_contributions": contributions,
            "computation_ms": elapsed_ms,
        }
    except Exception:
        logger.error(
            "SHAP computation failed for alert %d\n%s", alert_id, traceback.format_exc()
        )
        return None


async def explain_graph(
    alert_id: int,
    detail: dict,
    baseline_size: int,
) -> dict:
    """Build a rule-based explanation for a graph_model alert.

    The graph model is a heuristic (never-seen-edge), not a trained model.
    SHAP values are not applicable.  This returns a deterministic dict
    explaining what triggered the alert.

    Args:
        alert_id: The alert's DB primary key (for logging).
        detail: The anomaly detail dict from ``GraphDiffDetector.check_edge()``
            or ``LateralMovementDetector``.
        baseline_size: Number of edges in the baseline window.

    Returns:
        JSON-serializable explanation dict.
    """
    trigger = detail.get("trigger")
    if not trigger:
        if detail.get("kind") == "graph_sensitive_port" or "service" in detail:
            trigger = "sensitive_port"
        elif detail.get("kind") == "graph_lateral_path" or "path" in detail:
            trigger = "lateral_path"
        elif detail.get("kind") == "graph_internal_recon" or "port_count" in detail:
            trigger = "internal_recon"
        else:
            trigger = "new_edge"

    explanation: dict[str, Any] = {
        "explanation_type": "rule_based",
        "trigger": trigger,
        "src_container": detail.get("src", "unknown"),
        "dst_container": detail.get("dst", "unknown"),
        "port": detail.get("port", 0),
        "reason": detail.get("reason", "edge not in baseline"),
        "baseline_edges_seen": baseline_size,
    }
    if trigger == "sensitive_port":
        explanation["service"] = detail.get("service", "unknown")
    elif trigger == "lateral_path":
        explanation["path"] = detail.get("path", [])
    elif trigger == "internal_recon":
        explanation["port_count"] = detail.get("port_count", 0)

    logger.info(
        "graph explanation built for alert %d: trigger=%s %s→%s:%d",
        alert_id,
        trigger,
        explanation["src_container"],
        explanation["dst_container"],
        explanation["port"],
    )
    return explanation

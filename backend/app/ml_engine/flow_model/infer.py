"""Flow-model inference — score a live event against the trained Isolation Forest.

Loads the model artifact from ``data/model_artifacts/flow_model_v2.pkl``
once (lazy, on first call), then scores each incoming event by extracting
features from the Redis stream via ``features.py``.

Usage (called by ``event_consumer._run_ml()``)::

    signal = await score_flow_event(redis, event)
    # signal is {"kind": "ml_flow", "score": 0.73, "features": {...}, "scaled_vector": [...]} or None

The score is a continuous anomaly score in [0, 1] where higher = more
anomalous.  Whether it triggers an alert is decided by the risk scorer's
``flow_model_anomaly_threshold`` in ``risk_policy.yaml``.
"""

from __future__ import annotations

import logging
import os
import pickle
import traceback
from pathlib import Path

import numpy as np
import redis.asyncio as aioredis

# infer.py is nested 4 levels below repo root: backend/app/ml_engine/flow_model/infer.py
_REPO_ROOT = Path(__file__).resolve().parents[4]

from app.ml_engine.flow_model.features import (
    FEATURE_ORDER,
    extract_flow_features,
    features_to_vector,
    preprocess_features,
)

logger = logging.getLogger("flow_model.infer")

_ARTIFACT_DIR = Path(
    os.environ.get("MODEL_ARTIFACT_DIR", str(_REPO_ROOT / "data" / "model_artifacts"))
)
ARTIFACT_PATH = _ARTIFACT_DIR / "flow_model_v2.pkl"

_model_bundle: dict | None = None
_model_failed = False


def _reset_model_state() -> None:
    """Reset cached model bundle (primarily used for test isolation)."""
    global _model_bundle, _model_failed
    _model_bundle = None
    _model_failed = False


def _validate_model_bundle(bundle: dict) -> bool:
    """Validate that the loaded artifact contains all required components and correct shapes."""
    if not isinstance(bundle, dict):
        logger.critical("Model artifact is not a dict (got %s) — ML scoring disabled", type(bundle).__name__)
        return False

    if "model" not in bundle or not hasattr(bundle["model"], "decision_function"):
        logger.critical("Model artifact missing valid 'model' with decision_function — ML scoring disabled")
        return False

    if "scaler" not in bundle or not hasattr(bundle["scaler"], "transform"):
        logger.critical("Model artifact missing valid 'scaler' with transform() — ML scoring disabled")
        return False

    feature_names = bundle.get("feature_names")
    if not isinstance(feature_names, list) or len(feature_names) == 0:
        logger.critical("Model artifact missing valid 'feature_names' list — ML scoring disabled")
        return False

    scaler = bundle["scaler"]
    expected_n = len(feature_names)
    scaler_n = getattr(scaler, "n_features_in_", expected_n)
    if scaler_n != expected_n:
        logger.critical(
            "Scaler feature count mismatch: scaler expects %d, feature_names has %d — ML scoring disabled",
            scaler_n,
            expected_n,
        )
        return False

    return True


def _load_model() -> dict | None:
    """Load and validate the model artifact (once).  Returns None if unavailable or invalid."""
    global _model_bundle, _model_failed

    if _model_failed:
        return None
    if _model_bundle is not None:
        return _model_bundle

    if not ARTIFACT_PATH.exists():
        logger.critical("model artifact not found at %s — ML scoring disabled", ARTIFACT_PATH)
        _model_failed = True
        return None

    try:
        with open(ARTIFACT_PATH, "rb") as f:
            loaded = pickle.load(f)

        if not _validate_model_bundle(loaded):
            _model_failed = True
            return None

        _model_bundle = loaded
        logger.info(
            "flow model loaded from %s (features: %s)",
            ARTIFACT_PATH,
            _model_bundle.get("feature_names"),
        )
        return _model_bundle
    except Exception:
        logger.critical("failed to load model artifact\n%s", traceback.format_exc())
        _model_failed = True
        return None


def _is_loaded() -> bool:
    """Check if the model is loaded without triggering a load attempt."""
    return _model_bundle is not None


def _score_vector(vector: list[float]) -> float:
    """Score a feature vector against the loaded model.

    Returns an anomaly score in [0, 1] where higher = more anomalous.
    The Isolation Forest's ``decision_function`` returns negative values
    for anomalies; we normalize to [0, 1] by sigmoid mapping.

    Note: Percentile capping is used only during training on the baseline
    to prevent rare outliers from distorting the StandardScaler.  During live
    inference, extreme values (especially total_bytes_sent in data exfiltration)
    are NOT capped so they remain extreme outliers and produce high anomaly scores.
    """
    bundle = _model_bundle
    if bundle is None:
        raise RuntimeError("Flow model artifact is not loaded")

    feature_names = bundle.get("feature_names", FEATURE_ORDER)
    _, scaled = preprocess_features(
        vector,
        scaler=bundle["scaler"],
        feature_names=feature_names,
        apply_caps=False,
    )

    model = bundle["model"]
    raw = model.decision_function(scaled)[0]
    score = 1.0 / (1.0 + np.exp(raw))
    return float(round(score, 4))


async def score_flow_event(
    redis: aioredis.Redis,
    event,  # Event model — avoid circular import
) -> dict | None:
    """Score an event using the flow model.

    Returns ``{"kind": "ml_flow", "score": <float>, "features": <dict>,
    "scaled_vector": <list>}`` if scoring succeeds, or ``None`` if the
    model is unavailable or features can't be extracted.

    The ``features`` and ``scaled_vector`` fields are included so the
    SHAP explainability module can compute per-feature contributions
    without re-extracting or re-scaling.
    """
    if event.direction.value != "external":
        return None

    bundle = _load_model()
    if bundle is None:
        return None

    try:
        features = await extract_flow_features(redis, event.container_id)
    except Exception:
        logger.error(
            "feature extraction failed for event_id=%s container=%s\n%s",
            event.event_id,
            event.container_id,
            traceback.format_exc(),
        )
        return None

    if features is None:
        logger.info(
            "insufficient features for event_id=%s container=%s — skipping ML score",
            event.event_id,
            event.container_id,
        )
        return None

    try:
        feature_names = bundle.get("feature_names", FEATURE_ORDER)
        _, scaled = preprocess_features(
            features,
            scaler=bundle["scaler"],
            feature_names=feature_names,
            apply_caps=False,
        )

        model = bundle["model"]
        raw = model.decision_function(scaled)[0]
        score = float(round(1.0 / (1.0 + np.exp(raw)), 4))
        scaled_list = scaled[0].tolist()

        logger.info(
            "flow model scored event_id=%s container=%s features=%s score=%.4f",
            event.event_id,
            event.container_id,
            features,
            score,
        )
        return {
            "kind": "ml_flow",
            "score": score,
            "features": features,
            "scaled_vector": scaled_list,
        }
    except Exception:
        logger.error(
            "ML scoring failed for event_id=%s container=%s\n%s",
            event.event_id,
            event.container_id,
            traceback.format_exc(),
        )
        return None

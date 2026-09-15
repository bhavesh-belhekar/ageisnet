"""Flow-model inference — score a live event against the trained Isolation Forest.

Loads the model artifact from ``data/model_artifacts/flow_model_v1.pkl``
once (lazy, on first call), then scores each incoming event by extracting
features from the Redis stream via ``features.py``.

Usage (called by ``event_consumer._run_ml()``)::

    signal = await score_flow_event(redis, event)
    # signal is {"kind": "ml_flow", "score": 0.73} or None

The score is a continuous anomaly score in [0, 1] where higher = more
anomalous.  Whether it triggers an alert is decided by the risk scorer's
``flow_model_anomaly_threshold`` in ``risk_policy.yaml``.
"""

from __future__ import annotations

import logging
import os
import pickle
import sys
import traceback
from pathlib import Path

import numpy as np
import redis.asyncio as aioredis

_REPO_ROOT = Path(__file__).resolve().parents[3]

from app.ml_engine.flow_model.features import (  # noqa: E402
    FEATURE_ORDER,
    extract_flow_features,
    features_to_vector,
)

logger = logging.getLogger("flow_model.infer")

_ARTIFACT_DIR = Path(os.environ.get("MODEL_ARTIFACT_DIR", str(_REPO_ROOT / "data" / "model_artifacts")))
ARTIFACT_PATH = _ARTIFACT_DIR / "flow_model_v2.pkl"

_model_bundle: dict | None = None
_model_failed = False


def _load_model() -> dict | None:
    """Load the model artifact (once).  Returns None if unavailable."""
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
            _model_bundle = pickle.load(f)
        logger.info("flow model loaded from %s", ARTIFACT_PATH)
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

    Note: the percentile cap is applied only during **training** to prevent
    outlier distortion of the decision boundary.  At inference time, raw
    feature values are scaled directly — values beyond the training
    distribution are naturally scored as more anomalous by the forest.
    """
    bundle = _model_bundle
    model = bundle["model"]
    scaler = bundle["scaler"]

    arr = np.array([vector], dtype=np.float64)
    scaled = scaler.transform(arr)

    # decision_function: higher = more normal, lower = more anomalous
    raw = model.decision_function(scaled)[0]
    # Sigmoid mapping:  raw=0 → 0.5, raw<0 → >0.5 (anomalous), raw>0 → <0.5 (normal)
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
    # Only score external events (FR-5.1)
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
        vector = features_to_vector(features)
        score = _score_vector(vector)

        # Compute scaled vector for SHAP (same transform as _score_vector)
        import numpy as np
        arr = np.array([vector], dtype=np.float64)
        scaler = bundle["scaler"]
        scaled = scaler.transform(arr)
        scaled_list = scaled[0].tolist()

        logger.info(
            "flow model scored event_id=%s container=%s features=%s score=%.4f",
            event.event_id, event.container_id, features, score,
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

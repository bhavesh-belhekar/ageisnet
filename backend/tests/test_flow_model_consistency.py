"""Tests for flow model training/inference preprocessing consistency, feature ordering,
capping behavior on extreme byte transfers (data exfiltration), and artifact error handling.
"""

from __future__ import annotations

import pickle
from unittest.mock import AsyncMock, patch

import numpy as np
import pytest
from app.ml_engine.flow_model import features, infer
from app.ml_engine.flow_model.features import (
    FEATURE_ORDER,
    UNRESTRICTED_TRANSFER_FEATURES,
    features_to_vector,
    preprocess_features,
)
from app.models.event import Direction, Event, EventType
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@pytest.fixture()
def sample_features() -> dict:
    return {
        "total_bytes_sent": 5000,
        "total_bytes_received": 3000,
        "connection_count": 2,
        "unique_dst_ports": 2,
        "unique_dst_ips": 1,
        "window_seconds": 60.0,
    }


@pytest.fixture()
def trained_bundle() -> dict:
    """Create a minimal fitted Isolation Forest bundle representing normal baseline traffic."""
    np.random.seed(42)
    # 200 windows of normal baseline traffic with realistic variances
    base_data = np.column_stack(
        [
            np.random.normal(5000, 800, 200),     # total_bytes_sent
            np.random.normal(3000, 600, 200),     # total_bytes_received
            np.random.poisson(3, 200) + 1,        # connection_count
            np.random.poisson(2, 200) + 1,        # unique_dst_ports
            np.random.choice([1, 2], 200),        # unique_dst_ips
            np.random.normal(60.0, 5.0, 200),     # window_seconds
        ]
    )
    scaler = StandardScaler().fit(base_data)
    scaled_data = scaler.transform(base_data)

    model = IsolationForest(n_estimators=100, random_state=42, contamination=0.05)
    model.fit(scaled_data)

    cap_values = dict(zip(FEATURE_ORDER, np.percentile(base_data, 99, axis=0).tolist()))

    return {
        "model": model,
        "scaler": scaler,
        "feature_names": list(FEATURE_ORDER),
        "cap_values": cap_values,
        "training_meta": {"cap_exclude": ["unique_dst_ips"]},
    }


# ---------------------------------------------------------------------------
# 1. Feature Ordering & Preprocessing Consistency
# ---------------------------------------------------------------------------


def test_feature_ordering_consistency(sample_features: dict, trained_bundle: dict) -> None:
    """Preprocessed vector must strictly match FEATURE_ORDER regardless of dict key order."""
    scrambled = {k: sample_features[k] for k in reversed(list(sample_features.keys()))}

    scaler = trained_bundle["scaler"]
    raw1, scaled1 = preprocess_features(sample_features, scaler=scaler)
    raw2, scaled2 = preprocess_features(scrambled, scaler=scaler)

    assert np.allclose(raw1, raw2)
    assert np.allclose(scaled1, scaled2)
    assert raw1[0, 0] == sample_features["total_bytes_sent"]
    assert raw1[0, 1] == sample_features["total_bytes_received"]
    assert raw1[0, 5] == sample_features["window_seconds"]


def test_preprocessing_accepts_dict_list_and_ndarray(
    sample_features: dict, trained_bundle: dict
) -> None:
    """Dict, 1D list, and 2D array inputs produce identical preprocessed outputs."""
    scaler = trained_bundle["scaler"]
    vector = features_to_vector(sample_features)
    arr_2d = np.array([vector])

    _, scaled_from_dict = preprocess_features(sample_features, scaler=scaler)
    _, scaled_from_list = preprocess_features(vector, scaler=scaler)
    _, scaled_from_arr = preprocess_features(arr_2d, scaler=scaler)

    assert np.allclose(scaled_from_dict, scaled_from_list)
    assert np.allclose(scaled_from_dict, scaled_from_arr)


def test_preprocessing_rejects_mismatched_feature_count(trained_bundle: dict) -> None:
    """Passing a vector with incorrect feature count raises ValueError."""
    scaler = trained_bundle["scaler"]
    with pytest.raises(ValueError, match="Feature count mismatch"):
        preprocess_features([1.0, 2.0, 3.0], scaler=scaler)


# ---------------------------------------------------------------------------
# 2. Extreme Outbound Byte Transfers (Data Exfiltration) vs Capping
# ---------------------------------------------------------------------------


def test_data_exfiltration_detected_when_uncapped(trained_bundle: dict) -> None:
    """Unusually large outbound byte transfer (data exfiltration) produces a higher anomaly score."""
    with patch.object(infer, "_model_bundle", trained_bundle):
        # Normal traffic vector
        normal_vec = [5000.0, 3000.0, 3.0, 2.0, 1.0, 60.0]
        normal_score = infer._score_vector(normal_vec)

        # Massive data exfiltration: 500 MB sent
        exfil_vec = [500_000_000.0, 3000.0, 3.0, 2.0, 1.0, 60.0]
        exfil_score = infer._score_vector(exfil_vec)

        # Normal score should be lower than exfiltration score
        assert normal_score < 0.50
        assert exfil_score > normal_score


def test_capping_byte_transfers_would_hide_exfiltration(trained_bundle: dict) -> None:
    """Demonstrates that blindly applying np.minimum to total_bytes_sent suppresses the anomaly score."""
    cap_val = trained_bundle["cap_values"]["total_bytes_sent"]  # ~7000 bytes
    exfil_bytes = 500_000_000.0

    # Uncapped (live inference policy):
    unclamped_vec = [exfil_bytes, 3000.0, 3.0, 2.0, 1.0, 60.0]
    with patch.object(infer, "_model_bundle", trained_bundle):
        unclamped_score = infer._score_vector(unclamped_vec)

    # If blindly capped with np.minimum:
    clamped_bytes = min(exfil_bytes, cap_val)
    clamped_vec = [clamped_bytes, 3000.0, 3.0, 2.0, 1.0, 60.0]
    with patch.object(infer, "_model_bundle", trained_bundle):
        clamped_score = infer._score_vector(clamped_vec)

    # Clamping reduces the anomaly score toward baseline normal
    assert unclamped_score >= clamped_score


def test_unrestricted_transfer_features_set() -> None:
    """UNRESTRICTED_TRANSFER_FEATURES must protect both total_bytes_sent and total_bytes_received."""
    assert "total_bytes_sent" in UNRESTRICTED_TRANSFER_FEATURES
    assert "total_bytes_received" in UNRESTRICTED_TRANSFER_FEATURES


# ---------------------------------------------------------------------------
# 3. Safe Handling of Missing and Incompatible Model Artifacts
# ---------------------------------------------------------------------------


def test_load_model_returns_none_when_artifact_file_missing(tmp_path) -> None:
    """When the artifact file does not exist, _load_model() returns None without raising."""
    infer._reset_model_state()
    missing_path = tmp_path / "non_existent_model.pkl"
    with patch.object(infer, "ARTIFACT_PATH", missing_path):
        bundle = infer._load_model()
        assert bundle is None
        assert infer._is_loaded() is False


def test_load_model_rejects_non_dict_artifact(tmp_path) -> None:
    """A corrupted artifact file that is not a dictionary is safely rejected."""
    infer._reset_model_state()
    bad_file = tmp_path / "bad_model.pkl"
    with open(bad_file, "wb") as f:
        pickle.dump(["not", "a", "dict"], f)

    with patch.object(infer, "ARTIFACT_PATH", bad_file):
        bundle = infer._load_model()
        assert bundle is None


def test_load_model_rejects_missing_model_or_scaler(tmp_path) -> None:
    """Artifacts missing required model or scaler components are safely rejected."""
    infer._reset_model_state()
    bad_file = tmp_path / "incomplete_model.pkl"
    with open(bad_file, "wb") as f:
        pickle.dump({"feature_names": FEATURE_ORDER}, f)  # missing model and scaler

    with patch.object(infer, "ARTIFACT_PATH", bad_file):
        bundle = infer._load_model()
        assert bundle is None


def test_load_model_rejects_feature_count_mismatch(tmp_path) -> None:
    """Artifacts where scaler feature dimensions mismatch feature_names are rejected."""
    infer._reset_model_state()
    scaler_3 = StandardScaler().fit(np.zeros((5, 3)))
    bad_file = tmp_path / "mismatch_model.pkl"
    with open(bad_file, "wb") as f:
        pickle.dump(
            {
                "model": IsolationForest().fit(np.zeros((5, 3))),
                "scaler": scaler_3,
                "feature_names": FEATURE_ORDER,  # length 6 vs scaler length 3
            },
            f,
        )

    with patch.object(infer, "ARTIFACT_PATH", bad_file):
        bundle = infer._load_model()
        assert bundle is None


@pytest.mark.asyncio
async def test_score_flow_event_ignores_internal_direction() -> None:
    """score_flow_event returns None for internal direction events without loading model."""
    event = Event(
        event_id=1,
        container_id="c1",
        timestamp="2026-09-06T12:00:00+00:00",
        event_type=EventType.OPEN,
        src_ip="172.18.0.1",
        dst_ip="172.18.0.2",
        src_port=40000,
        dst_port=5432,
        protocol="tcp",
        direction=Direction.INTERNAL,
    )
    redis = AsyncMock()
    result = await infer.score_flow_event(redis, event)
    assert result is None


@pytest.mark.asyncio
async def test_score_flow_event_degrades_gracefully_when_model_unavailable() -> None:
    """score_flow_event returns None when model artifact is unavailable without raising."""
    infer._reset_model_state()
    event = Event(
        event_id=2,
        container_id="c2",
        timestamp="2026-09-06T12:00:00+00:00",
        event_type=EventType.OPEN,
        src_ip="172.18.0.1",
        dst_ip="8.8.8.8",
        src_port=40000,
        dst_port=443,
        protocol="tcp",
        direction=Direction.EXTERNAL,
    )
    redis = AsyncMock()
    with patch.object(infer, "_load_model", return_value=None):
        result = await infer.score_flow_event(redis, event)
        assert result is None

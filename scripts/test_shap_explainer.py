#!/usr/bin/env python3
"""Standalone test for Phase 5 — SHAP explainability + rule-based explanations.

Demonstrates:
1. Flow model SHAP: TreeExplainer on the trained Isolation Forest
2. Graph model explanation: rule-based explanation for a new-edge alert
3. Rule engine MITRE tags: confirms all 4 rule types carry technique IDs

Run from the repo root::

    python scripts/test_shap_explainer.py
"""

from __future__ import annotations

import json
import pickle
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

import numpy as np
from app.ml_engine.flow_model.features import FEATURE_ORDER
from app.rule_engine.engine import _MITRE


def test_flow_model_shap() -> dict:
    """Load the trained Isolation Forest and compute SHAP for an anomalous sample."""
    print("=" * 68)
    print("TEST 1: Flow Model SHAP (TreeExplainer on Isolation Forest)")
    print("=" * 68)

    artifact_path = REPO_ROOT / "data" / "model_artifacts" / "flow_model_v2.pkl"
    if not artifact_path.exists():
        print("  SKIP: flow_model_v2.pkl not found")
        return {}

    with open(artifact_path, "rb") as f:
        bundle = pickle.load(f)

    model = bundle["model"]
    scaler = bundle["scaler"]

    # Construct an anomalous feature vector (high bytes, many ports, single IP)
    raw_features = {
        "total_bytes_sent": 15000,
        "total_bytes_received": 12000,
        "connection_count": 130,
        "unique_dst_ports": 66,
        "unique_dst_ips": 1,
        "window_seconds": 293.0,
    }
    vector = [float(raw_features[k]) for k in FEATURE_ORDER]
    arr = np.array([vector], dtype=np.float64)
    scaled = scaler.transform(arr)

    import shap
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(scaled)[0]

    # Build explanation dict (same format as shap_explainer.py)
    contributions = {}
    for i, name in enumerate(FEATURE_ORDER):
        contributions[name] = {
            "value": raw_features[name],
            "shap": float(round(shap_values[i], 6)),
            "direction": "anomaly_push" if shap_values[i] > 0 else "normalizing",
        }

    sorted_features = sorted(
        contributions.items(),
        key=lambda kv: abs(kv[1]["shap"]),
        reverse=True,
    )

    explanation = {
        "explanation_type": "shap",
        "model": "isolation_forest",
        "top_features": [
            {"feature": name, **data}
            for name, data in sorted_features[:3]
        ],
        "all_contributions": contributions,
    }

    print(f"\n  Input features: {raw_features}")
    print(f"  Anomaly score:  {model.decision_function(scaled)[0]:.4f} (negative = anomalous)")
    print(f"\n  SHAP values (sorted by |impact|):")
    for name, data in sorted_features:
        arrow = "↑ anomaly" if data["direction"] == "anomaly_push" else "↓ normal"
        print(f"    {name:30s}  value={data['value']:>10.1f}  shap={data['shap']:>+.4f}  {arrow}")

    print(f"\n  Top 3 contributors:")
    for item in explanation["top_features"]:
        print(f"    {item['feature']}: {item['shap']:+.4f}")

    print(f"\n  JSONB payload (stored in shap_explanation column):")
    print(f"  {json.dumps(explanation, indent=2)[:500]}...")
    return explanation


def test_graph_model_explanation() -> dict:
    """Build a rule-based explanation for a graph model alert."""
    print("\n" + "=" * 68)
    print("TEST 2: Graph Model Rule-Based Explanation")
    print("=" * 68)

    from app.explainability.shap_explainer import explain_graph

    detail = {
        "is_anomalous": True,
        "reason": "new edge — never seen in baseline window",
        "src": "evil-app",
        "dst": "demo-db",
        "port": 5432,
        "baseline_size": 42,
    }

    # explain_graph is sync, but we test it as if it were called from the async path
    import asyncio
    explanation = asyncio.get_event_loop().run_until_complete(
        explain_graph(alert_id=999, detail=detail, baseline_size=42)
    )

    print(f"\n  Edge: {detail['src']} → {detail['dst']}:{detail['port']}")
    print(f"  Reason: {detail['reason']}")
    print(f"  Baseline edges: {detail['baseline_size']}")
    print(f"\n  Explanation dict:")
    print(f"  {json.dumps(explanation, indent=2)}")
    return explanation


def test_rule_engine_mitre() -> None:
    """Confirm all 4 rule types carry MITRE technique IDs."""
    print("\n" + "=" * 68)
    print("TEST 3: Rule Engine MITRE Tags (FR-12)")
    print("=" * 68)

    from app.rule_engine.engine import _MITRE

    print(f"\n  _MITRE mapping in engine.py:")
    for rule_name, technique_id in _MITRE.items():
        print(f"    {rule_name:30s} → {technique_id}")

    # Verify all 4 rules are mapped
    expected = {
        "known_bad_ip_connection": "T1071",
        "known_bad_port": "T1043",
        "port_scan": "T1046",
        "restricted_protocol": "T1571",
    }
    all_present = all(_MITRE.get(k) == v for k, v in expected.items())
    print(f"\n  All 4 rules mapped: {'YES' if all_present else 'NO'}")
    if not all_present:
        for k, v in expected.items():
            actual = _MITRE.get(k)
            status = "OK" if actual == v else f"MISMATCH (got {actual})"
            print(f"    {k}: expected {v}, {status}")


def main() -> int:
    print("Phase 5 — SHAP Explainability & MITRE Mapping Evidence")
    print("Date: 2026-09-15\n")

    flow_explanation = test_flow_model_shap()
    graph_explanation = test_graph_model_explanation()
    test_rule_engine_mitre()

    print("\n" + "=" * 68)
    print("SUMMARY")
    print("=" * 68)
    expected_mitre = {
        "known_bad_ip_connection": "T1071",
        "known_bad_port": "T1043",
        "port_scan": "T1046",
        "restricted_protocol": "T1571",
    }
    checks = [
        ("flow_model SHAP produces per-feature contributions",
         flow_explanation.get("explanation_type") == "shap"),
        ("flow_model SHAP has top_features (sorted by |impact|)",
         len(flow_explanation.get("top_features", [])) == 3),
        ("graph_model explanation is rule_based",
         graph_explanation.get("explanation_type") == "rule_based"),
        ("graph_model explanation has trigger + edge details",
         graph_explanation.get("trigger") == "new_edge"),
        ("rule engine maps all 4 rules to MITRE technique IDs",
         all(_MITRE.get(k) == v for k, v in expected_mitre.items())),
    ]

    all_pass = True
    for desc, ok in checks:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {desc}")
        if not ok:
            all_pass = False

    print()
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())

"""Risk/severity scoring (FR-6) — combines per-event detections into one label.

Every detection (rule hit, ML anomaly score) is a *signal* on the same event.
The scorer converts each signal into a numeric contribution using the
config-driven policy in ``config/risk_policy.yaml`` and maps the aggregate
onto a single Low/Medium/High severity label per event:

* a rule hit contributes ``severity_levels[severity] * rule_hit``
* an ML flow signal contributes ``ml_flow_anomaly`` (2) when its anomaly score
  crosses ``flow_model_anomaly_threshold`` — a confident ML-only detection
  surfaces as Medium and reaches the real-time dashboard
* an ML graph signal contributes ``ml_graph_anomaly`` (1) when its score
  crosses ``graph_new_edge_threshold`` — still LOW until graph FP validation
  (Phase 8 follow-up) is complete
* ``hard_height_override: true`` forces High when any single rule signal is
  High, so a lone high-severity rule hit can never be downgraded by summation
* otherwise the total is tiered: ``high_min`` -> High, ``medium_min`` -> Medium,
  below that Low
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from app.models.alert import Severity

_CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"


@lru_cache
def _load_policy() -> dict:
    with open(_CONFIG_DIR / "risk_policy.yaml") as f:
        return yaml.safe_load(f)


def get_push_min_severity() -> Severity:
    """Minimum severity that is pushed live to WebSocket subscribers (FR-7.2)."""
    value = _load_policy().get("delivery", {}).get("push_min_severity", "medium")
    return Severity(value)


class RiskScorer:
    """Config-driven aggregator turning per-event signals into one severity."""

    def __init__(self) -> None:
        policy = _load_policy()
        self._levels = policy["risk_scoring"]["severity_levels"]
        self._weights = policy["risk_scoring"]["component_weights"]
        self._tiers = policy["risk_scoring"]["severity_tiers"]
        self._override = policy["risk_scoring"]["hard_height_override"]
        self._ml_thresholds = policy.get("ml_thresholds", {})

    def score(self, signals: list[dict]) -> Severity:
        """Combine *signals* for one event into a single severity label.

        Each signal is a dict:

        * ``{"kind": "rule", "severity": "medium"}``
        * ``{"kind": "ml_flow", "score": 0.71}`` (Phase 4)
        * ``{"kind": "ml_graph", "score": 1.0}`` (Phase 4)
        """
        total = 0
        any_high = False

        for signal in signals:
            kind = signal.get("kind")
            if kind == "rule":
                severity = Severity(signal["severity"])
                if severity is Severity.HIGH:
                    any_high = True
                total += self._levels[severity.value] * self._weights["rule_hit"]
            elif kind == "ml_flow":
                threshold = self._ml_thresholds.get("flow_model_anomaly_threshold", 0.6)
                if signal["score"] >= threshold:
                    total += self._weights["ml_flow_anomaly"]
            elif kind == "ml_graph":
                threshold = self._ml_thresholds.get("graph_new_edge_threshold", 1.0)
                if signal["score"] >= threshold:
                    total += self._weights["ml_graph_anomaly"]

        if self._override and any_high:
            return Severity.HIGH
        if total >= self._tiers["high_min"]:
            return Severity.HIGH
        if total >= self._tiers["medium_min"]:
            return Severity.MEDIUM
        return Severity.LOW

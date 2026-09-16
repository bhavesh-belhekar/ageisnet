"""Risk-scoring tests (FR-6): config-driven aggregation to one severity/event."""

import pytest
from app.models.alert import Severity
from app.risk_scoring import scorer as scorer_module
from app.risk_scoring.scorer import RiskScorer, get_push_min_severity


@pytest.fixture()
def scorer() -> RiskScorer:
    return RiskScorer()


rule = lambda sev: {"kind": "rule", "severity": sev}  # noqa: E731


def test_no_signals_scores_low(scorer: RiskScorer) -> None:
    assert scorer.score([]) is Severity.LOW


def test_single_medium_rule_hit_scores_medium(scorer: RiskScorer) -> None:
    assert scorer.score([rule("medium")]) is Severity.MEDIUM


def test_single_high_rule_hit_is_overridden_to_high(scorer: RiskScorer) -> None:
    assert scorer.score([rule("high")]) is Severity.HIGH


def test_low_rule_hit_scores_low(scorer: RiskScorer) -> None:
    assert scorer.score([rule("low")]) is Severity.LOW


def test_two_medium_rule_hits_escalate_to_high(scorer: RiskScorer) -> None:
    assert scorer.score([rule("medium"), rule("medium")]) is Severity.HIGH


def test_medium_plus_low_stays_medium(scorer: RiskScorer) -> None:
    assert scorer.score([rule("medium"), rule("low")]) is Severity.MEDIUM


def test_high_override_survives_with_lower_signal(scorer: RiskScorer) -> None:
    assert scorer.score([rule("high"), rule("medium")]) is Severity.HIGH


def test_ml_flow_below_threshold_contributes_nothing(scorer: RiskScorer) -> None:
    assert scorer.score([{"kind": "ml_flow", "score": 0.1}]) is Severity.LOW


def test_ml_flow_above_threshold_scores_medium(scorer: RiskScorer) -> None:
    # ml_flow_anomaly weight=2 matches medium_min=2, so a confident ML-only
    # detection surfaces as Medium and reaches the real-time dashboard.
    assert scorer.score([{"kind": "ml_flow", "score": 0.9}]) is Severity.MEDIUM


def test_ml_flow_plus_medium_rule_escalates_to_high(scorer: RiskScorer) -> None:
    # Combined ML + rule confirmation: ml(2) + rule_medium(2) = 4 >= high_min(4).
    assert scorer.score([rule("medium"), {"kind": "ml_flow", "score": 0.9}]) is Severity.HIGH


def test_ml_graph_above_threshold_combines_with_rule(scorer: RiskScorer) -> None:
    assert scorer.score([rule("medium"), {"kind": "ml_graph", "score": 1.5}]) is Severity.MEDIUM


def test_push_min_severity_reads_policy() -> None:
    assert get_push_min_severity() is Severity.MEDIUM


def test_tiers_are_config_driven(monkeypatch) -> None:
    policy = scorer_module._load_policy()
    policy = dict(policy)
    policy["risk_scoring"] = dict(policy["risk_scoring"])
    policy["risk_scoring"]["severity_tiers"] = {"low_min": 0, "medium_min": 10, "high_min": 20}
    monkeypatch.setattr(scorer_module, "_load_policy", lambda: policy)
    cfg_scorer = RiskScorer()
    assert cfg_scorer.score([rule("medium")]) is Severity.LOW
    assert cfg_scorer.score([rule("high")]) is Severity.HIGH  # override still applies

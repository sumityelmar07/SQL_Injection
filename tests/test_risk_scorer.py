"""Tests for detection/risk_scorer.py"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.risk_scorer import compute_risk, DECISION_SAFE, DECISION_SUSP, DECISION_LIKELY, DECISION_DEFINITE


def test_safe_all_zeros():
    score, decision = compute_risk(0, 0, 0.0)
    assert decision == DECISION_SAFE
    assert score == 0


def test_low_signals_suspicious():
    score, decision = compute_risk(40, 30, 0.20)
    assert decision in (DECISION_SUSP, DECISION_LIKELY)


def test_high_signals_blocked():
    score, decision = compute_risk(95, 90, 0.95)
    assert decision == DECISION_DEFINITE
    assert score >= 80


def test_score_capped_at_100():
    score, _ = compute_risk(100, 100, 1.0)
    assert score <= 100


def test_score_floor_zero():
    score, _ = compute_risk(0, 0, 0.0)
    assert score >= 0


def test_custom_config_thresholds():
    cfg = {
        "WEIGHT_SIGNATURE": 0.4,
        "WEIGHT_ANOMALY": 0.25,
        "WEIGHT_ML": 0.35,
        "RISK_SUSPICIOUS": 30,
        "RISK_BLOCK": 60,
        "RISK_DEFINITE": 80,
    }
    score, decision = compute_risk(90, 80, 0.9, config=cfg)
    assert decision == DECISION_DEFINITE

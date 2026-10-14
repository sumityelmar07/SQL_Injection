"""End-to-end tests for detection/pipeline.py (no Flask app context needed)."""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.pipeline import inspect


ATTACKS = [
    "' OR '1'='1",
    "' UNION SELECT null,null --",
    "'; DROP TABLE users; --",
    "' AND SLEEP(5) --",
    "admin'--",
    "1 WAITFOR DELAY '0:0:5'",
    "' UNION SELECT table_name FROM information_schema.tables --",
]

NORMALS = [
    "alice",
    "user@example.com",
    "laptop keyboard",
    "42",
    "alice_smith99",
]


def test_attacks_are_not_safe():
    for payload in ATTACKS:
        result = inspect(payload)
        assert result["decision"] != "SAFE", (
            f"Expected non-SAFE for payload: {payload!r}, got {result}"
        )


def test_normals_are_safe():
    for normal in NORMALS:
        result = inspect(normal)
        assert result["decision"] == "SAFE", (
            f"Expected SAFE for normal input: {normal!r}, got {result}"
        )


def test_result_has_required_keys():
    result = inspect("hello")
    for key in ("normalized", "signature_hit", "signature_score",
                 "anomaly_score", "ml_score", "risk_score", "decision"):
        assert key in result, f"Missing key: {key}"


def test_risk_score_range():
    for payload in ATTACKS + NORMALS:
        result = inspect(payload)
        assert 0 <= result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# New tests — gaps identified in the audit
# ---------------------------------------------------------------------------

def test_apostrophe_names_are_safe():
    """
    Names that contain a single apostrophe (O'Brien, O'Reilly) trigger the
    anomaly quote-imbalance check (score 70), but the final weighted risk
    score must stay below 30 (SAFE) because no signature fires and ML is low.

    This test documents the expected margin so that if config weights change
    and the margin shrinks, the failure is caught here rather than in
    production with a real user complaint.
    """
    legitimate_names = ["O'Brien", "O'Reilly", "it's fine", "don't"]
    for name in legitimate_names:
        result = inspect(name)
        assert result["decision"] == "SAFE", (
            f"False positive: {name!r} should be SAFE, got decision="
            f"{result['decision']} risk={result['risk_score']}"
        )
        # Also assert the margin is comfortable — score must stay below 25
        # so there is headroom before the SUSPICIOUS threshold of 30.
        assert result["risk_score"] <= 25, (
            f"Risk score for {name!r} is {result['risk_score']} — "
            f"too close to the SUSPICIOUS threshold of 30"
        )


def test_natural_language_keywords_are_safe():
    """
    English phrases that happen to contain SQL keyword tokens must not be
    blocked. Verified safe by live probe (see audit notes).
    """
    phrases = [
        "order online",        # "order" is a SQL keyword
        "not available",       # "not" is a SQL keyword
        "group of friends",    # "group" is a SQL keyword
    ]
    for phrase in phrases:
        result = inspect(phrase)
        assert result["decision"] == "SAFE", (
            f"False positive: {phrase!r} classified as {result['decision']} "
            f"(risk={result['risk_score']})"
        )


def test_previously_false_positive_now_safe():
    """
    Regression test: 'in and out' was a known ML false positive (risk ~55,
    SUSPICIOUS) in the pre-Phase-A model.

    Fixed by:
      1. Adding natural-language phrases to normal training data so the ML model
         learns that 'in', 'and', 'out' appear in innocent contexts.
      2. Capping keyword-density anomaly score for short phrases (< 5 tokens)
         so 3-word phrases like 'in and out' no longer score 85.

    After fix: risk ~13, decision SAFE.  This test locks in the improvement.
    """
    result = inspect("in and out")
    assert result["decision"] == "SAFE", (
        f"Regression: 'in and out' should be SAFE after Phase A fix, "
        f"got {result['decision']} (risk={result['risk_score']})"
    )
    assert result["risk_score"] < 20, (
        f"Risk score {result['risk_score']} is too high for a benign phrase"
    )


def test_suspicious_decision_is_between_thresholds():
    """
    Verify that a score of 30-59 maps to SUSPICIOUS (not SAFE, not LIKELY_ATTACK).
    This is a unit test of the risk scorer's threshold logic.
    """
    from detection.risk_scorer import compute_risk, DECISION_SUSP
    # Craft inputs that land in the 30-59 band:
    # sig=0, anomaly=70 (quote imbalance), ml=0.10 → 0 + 17.5 + 3.5 = 21... too low
    # sig=50, anomaly=30, ml=0.20 → 20 + 7.5 + 7 = 34.5 → 35 → SUSPICIOUS
    score, decision = compute_risk(50, 30, 0.20)
    assert decision == DECISION_SUSP, (
        f"Expected SUSPICIOUS for score {score}, got {decision}"
    )
    assert 30 <= score <= 59


def test_classifier_missing_model_returns_zero():
    """
    When model.pkl does not exist, predict() must return 0.0 (graceful
    degradation) so that signatures and anomaly checks still work.
    We test this without deleting the real model by patching the path.
    """
    import detection.classifier as clf_module
    from unittest.mock import patch

    # Temporarily reset the cached model state
    original_model = clf_module._model
    original_loaded = clf_module._model_loaded

    try:
        clf_module._model = None
        clf_module._model_loaded = False

        with patch("os.path.exists", return_value=False):
            result = clf_module.predict("anything")

        assert result == 0.0, f"Expected 0.0 when model is missing, got {result}"
    finally:
        # Always restore — never permanently affect the real cached model
        clf_module._model = original_model
        clf_module._model_loaded = original_loaded

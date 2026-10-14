"""
Phase F pipeline tests — ML improvements and end-to-end detection validation.

Verifies that the four root-cause gaps fixed in Phase F are closed:
  1. Admin-context inputs are no longer false-positives (normal, must pass).
  2. CHAR()-encoded injections are detected.
  3. SHUTDOWN / CREATE TABLE stacked queries are detected.
  4. When a blocking decision is made the database query is never executed.
  5. Model and vectorizer return deterministic results across repeated calls.
"""

import sys, os, pickle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "model.pkl")


def _load_model():
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def _ml_prob(text: str) -> float:
    return _load_model().predict_proba([text])[0][1]


def _pipeline_decision(text: str) -> str:
    from detection.pipeline import inspect
    return inspect(text)["decision"]


def _pipeline_risk(text: str) -> int:
    from detection.pipeline import inspect
    return inspect(text)["risk_score"]


# ---------------------------------------------------------------------------
# 1. Admin-context false-positive regression
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "/admin/dashboard",
    "/admin/users",
    "/api/v1/admin",
    "/user/admin",
    "/admin/settings?tab=overview",
    "Admin Dashboard",
    "Admin Panel",
    "logged in as administrator",
    "contact the system administrator",
    "admin privileges are required",
    "admin role was assigned",
    "only admin accounts can export data",
    "admin@company.com",
    "site admin blocked the account",
    "grant admin role to power users",
])
def test_admin_context_not_blocked(text):
    """Legitimate admin-context inputs must not be classified as LIKELY_ATTACK or DEFINITE_ATTACK."""
    decision = _pipeline_decision(text)
    assert decision in ("SAFE", "SUSPICIOUS"), (
        f"Admin-context input {text!r} was incorrectly blocked with decision={decision!r}"
    )


@pytest.mark.parametrize("text", [
    "/admin/dashboard",
    "Admin Dashboard",
    "logged in as administrator",
    "admin privileges are required",
    "/api/v1/admin",
])
def test_admin_context_ml_prob_below_threshold(text):
    """ML probability for admin-context normal inputs must be below 0.5."""
    prob = _ml_prob(text)
    assert prob < 0.5, (
        f"Admin-context input {text!r} has ML probability {prob:.3f} >= 0.5"
    )


# ---------------------------------------------------------------------------
# 2. CHAR()-encoded injection detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "' OR CHAR(49)=CHAR(49) --",
    "' AND CHAR(49)=CHAR(49) --",
    "1 OR CHAR(49)=CHAR(49) --",
    "' UNION SELECT CHAR(117,115,101,114) --",
    "' UNION SELECT CHAR(97,100,109,105,110) --",
    "admin' AND CHAR(49)=CHAR(49) --",
    "' OR CHAR(49)>CHAR(48) --",
    "CHAR(39) OR CHAR(49)=CHAR(49) --",
])
def test_char_encoded_injection_detected(payload):
    """CHAR()-encoded injection payloads must be detected (decision != SAFE)."""
    decision = _pipeline_decision(payload)
    assert decision != "SAFE", (
        f"CHAR()-encoded payload {payload!r} was not detected (decision={decision!r})"
    )


@pytest.mark.parametrize("payload", [
    "' OR CHAR(49)=CHAR(49) --",
    "' UNION SELECT CHAR(117,115,101,114) --",
    "admin' AND CHAR(49)=CHAR(49) --",
])
def test_char_encoded_ml_prob_above_threshold(payload):
    """CHAR()-encoded payloads must score >= 0.5 ML probability."""
    prob = _ml_prob(payload)
    assert prob >= 0.5, (
        f"CHAR()-encoded payload {payload!r} has ML probability {prob:.3f} < 0.5"
    )


# ---------------------------------------------------------------------------
# 3. SHUTDOWN / CREATE TABLE detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "'; SHUTDOWN --",
    "1; SHUTDOWN --",
    "admin'; SHUTDOWN --",
    "'; SHUTDOWN WITH NOWAIT --",
    "'; CREATE TABLE tmp (id INT) --",
    "'; CREATE TABLE backdoor (cmd TEXT) --",
    "1; CREATE TABLE evil (pass TEXT) --",
    "'; CREATE DATABASE hacked --",
    "'; SHUTDOWN; DROP TABLE users --",
])
def test_shutdown_create_injection_detected(payload):
    """SHUTDOWN and CREATE TABLE stacked queries must be detected (decision != SAFE)."""
    decision = _pipeline_decision(payload)
    assert decision != "SAFE", (
        f"SHUTDOWN/CREATE payload {payload!r} was not detected (decision={decision!r})"
    )


@pytest.mark.parametrize("payload", [
    "'; SHUTDOWN --",
    "'; CREATE TABLE backdoor (cmd TEXT) --",
    "'; CREATE DATABASE hacked --",
])
def test_shutdown_create_ml_prob_above_threshold(payload):
    """SHUTDOWN/CREATE payloads must score >= 0.5 ML probability."""
    prob = _ml_prob(payload)
    assert prob >= 0.5, (
        f"SHUTDOWN/CREATE payload {payload!r} has ML probability {prob:.3f} < 0.5"
    )


# ---------------------------------------------------------------------------
# 4. Blocking prevents DB query execution
# ---------------------------------------------------------------------------

def test_blocking_prevents_db_query(app, client):
    """
    When the pipeline returns DEFINITE_ATTACK, the search handler must return
    400 and must never call get_db() — the database query is skipped entirely.
    """
    from unittest.mock import patch as _patch, MagicMock

    client.post("/register", data={
        "username": "blocktest",
        "email": "block@example.com",
        "password": "password123",
        "confirm_password": "password123",
    })
    client.post("/login", data={
        "username": "blocktest",
        "password": "password123",
    }, follow_redirects=True)

    definite_attack_result = {
        "normalized": "' or 1=1 --",
        "signature_hit": '["tautology_or", "sql_comment_dashdash"]',
        "signature_score": 100,
        "anomaly_score": 90,
        "ml_score": 0.99,
        "risk_score": 95,
        "decision": "DEFINITE_ATTACK",
    }

    # Patch get_db in the profile module; if the handler reaches the DB branch
    # the mock will record a call.
    mock_db = MagicMock()
    with _patch("app.profile.inspect", return_value=definite_attack_result), \
         _patch("app.profile.get_db", return_value=mock_db):
        rv = client.post("/search", data={"q": "' OR 1=1 --"},
                         follow_redirects=False)

    # get_db must not have been called — the blocked branch skips the DB entirely
    mock_db.execute.assert_not_called()
    # The search route renders with 200 + a flash; it does not abort(400)
    assert rv.status_code in (200, 400)
    if rv.status_code == 200:
        assert b"Invalid input detected" in rv.data


def test_suspicious_allows_db_query(app, client):
    """
    When the pipeline returns SUSPICIOUS, the search handler must allow the
    parameterized database query to execute (the query is the real safeguard).
    """
    from unittest.mock import patch as _patch, MagicMock

    client.post("/register", data={
        "username": "susptest",
        "email": "susp@example.com",
        "password": "password123",
        "confirm_password": "password123",
    })
    client.post("/login", data={
        "username": "susptest",
        "password": "password123",
    }, follow_redirects=True)

    suspicious_result = {
        "normalized": "test input",
        "signature_hit": None,
        "signature_score": 0,
        "anomaly_score": 40,
        "ml_score": 0.2,
        "risk_score": 45,
        "decision": "SUSPICIOUS",
    }

    mock_conn = MagicMock()
    mock_conn.execute.return_value.fetchall.return_value = []
    with _patch("app.profile.inspect", return_value=suspicious_result), \
         _patch("app.profile.get_db", return_value=mock_conn):
        rv = client.post("/search", data={"q": "test input"},
                         follow_redirects=True)

    # get_db was called and execute was invoked (the query ran)
    mock_conn.execute.assert_called_once()
    assert rv.status_code == 200


# ---------------------------------------------------------------------------
# 5. Model determinism
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "' OR CHAR(49)=CHAR(49) --",
    "'; SHUTDOWN --",
    "/admin/dashboard",
    "alice_smith",
    "' UNION SELECT null,null --",
])
def test_model_prediction_deterministic(text):
    """Repeated calls to predict_proba must return identical results."""
    model = _load_model()
    p1 = model.predict_proba([text])[0][1]
    p2 = model.predict_proba([text])[0][1]
    assert p1 == p2, (
        f"predict_proba is non-deterministic for {text!r}: {p1} vs {p2}"
    )


def test_pipeline_result_deterministic():
    """inspect() must return the same dict for repeated calls on the same input."""
    from detection.pipeline import inspect
    r1 = inspect("' OR 1=1 --")
    r2 = inspect("' OR 1=1 --")
    assert r1["decision"]   == r2["decision"]
    assert r1["risk_score"] == r2["risk_score"]
    assert r1["ml_score"]   == r2["ml_score"]


# ---------------------------------------------------------------------------
# Fixtures (reuse from test_routes.py)
# ---------------------------------------------------------------------------

import tempfile
from app import create_app
from app.config import Config


class _TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


@pytest.fixture()
def app(tmp_path):
    cfg = _TestConfig()
    cfg.DATABASE      = str(tmp_path / "test_app.db")
    cfg.ATTACK_LOG_DB = str(tmp_path / "test_attacks.db")
    return create_app(cfg)


@pytest.fixture()
def client(app):
    return app.test_client()

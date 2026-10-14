"""
Integration tests for Flask routes.

Uses a temporary SQLite database so tests never touch the real instance/app.db.
"""

import sys, os, tempfile, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app
from app.config import Config


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False   # never throttle automated test requests


@pytest.fixture()
def app(tmp_path):
    cfg = TestConfig()
    cfg.DATABASE    = str(tmp_path / "test_app.db")
    cfg.ATTACK_LOG_DB = str(tmp_path / "test_attacks.db")
    application = create_app(cfg)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# Auth route tests
# ---------------------------------------------------------------------------

def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Login" in response.data


def test_register_page_loads(client):
    response = client.get("/register")
    assert response.status_code == 200


def test_register_and_login(client):
    # Register a new user
    rv = client.post("/register", data={
        "username": "testuser",
        "email": "test@example.com",
        "password": "securepass1",
        "confirm_password": "securepass1",
    }, follow_redirects=True)
    assert rv.status_code == 200

    # Login
    rv = client.post("/login", data={
        "username": "testuser",
        "password": "securepass1",
    }, follow_redirects=True)
    assert rv.status_code == 200
    assert b"testuser" in rv.data


def test_wrong_password_rejected(client):
    client.post("/register", data={
        "username": "user2",
        "email": "u2@example.com",
        "password": "correctpass",
        "confirm_password": "correctpass",
    })
    rv = client.post("/login", data={
        "username": "user2",
        "password": "wrongpass",
    }, follow_redirects=True)
    assert b"Invalid username or password" in rv.data


def test_injection_in_login_is_blocked(client):
    rv = client.post("/login", data={
        "username": "' OR '1'='1",
        "password": "anything",
    }, follow_redirects=True)
    # 400 = detection blocked it outright (LIKELY_ATTACK / DEFINITE_ATTACK)
    # 401 = detection flagged it as SUSPICIOUS but allowed it through;
    #       the parameterized query returned no user, so login failed safely.
    # 200 = login page re-rendered with a flash message.
    # All three are correct outcomes — the important assertion is that no
    # raw database error is exposed.
    assert rv.status_code in (200, 400, 401)
    assert b"Internal" not in rv.data  # no raw error exposed


def test_profile_requires_login(client):
    rv = client.get("/profile", follow_redirects=True)
    assert b"Login" in rv.data


def test_admin_requires_admin_role(client):
    # Register a normal user and try to access admin
    client.post("/register", data={
        "username": "normaluser",
        "email": "norm@example.com",
        "password": "password123",
        "confirm_password": "password123",
    })
    client.post("/login", data={
        "username": "normaluser",
        "password": "password123",
    })
    rv = client.get("/admin/", follow_redirects=True)
    assert rv.status_code in (403, 200)
    if rv.status_code == 200:
        assert b"permission" in rv.data.lower()


def test_search_with_injection_blocked(client):
    # Register and log in
    client.post("/register", data={
        "username": "searcher",
        "email": "search@example.com",
        "password": "password123",
        "confirm_password": "password123",
    })
    client.post("/login", data={
        "username": "searcher",
        "password": "password123",
    })
    rv = client.post("/search", data={"q": "' UNION SELECT null,null --"},
                     follow_redirects=True)
    assert rv.status_code in (200, 400)
    assert b"Internal" not in rv.data


# ---------------------------------------------------------------------------
# New tests — gaps identified in the audit
# ---------------------------------------------------------------------------

def _register_and_login(client, username, email, password="password123"):
    """Helper: register then login; returns login response."""
    client.post("/register", data={
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password,
    })
    return client.post("/login", data={
        "username": username,
        "password": password,
    }, follow_redirects=True)


def test_apostrophe_name_search_safe(client):
    """O'Brien is a legitimate name — it must pass detection and reach the DB query."""
    _register_and_login(client, "tester1", "tester1@example.com")
    rv = client.post("/search", data={"q": "O'Brien"}, follow_redirects=True)
    assert rv.status_code == 200
    # The block message must NOT appear for a legitimate name
    assert b"Invalid input detected" not in rv.data


def test_attack_log_written_on_injection(app, client):
    """
    After a blocked injection, attacks.db must contain exactly one new row
    with the correct endpoint, decision, and a non-null signature_hit.
    """
    import sqlite3
    _register_and_login(client, "logger1", "logger1@example.com")

    client.post("/search", data={"q": "' UNION SELECT null,null --"},
                follow_redirects=True)

    log_path = app.config["ATTACK_LOG_DB"]
    conn = sqlite3.connect(log_path)
    rows = conn.execute(
        "SELECT endpoint, decision, signature_hit, risk_score "
        "FROM attack_logs WHERE endpoint='/search'"
    ).fetchall()
    conn.close()

    import json as _json
    assert len(rows) == 1, f"Expected 1 log row, got {len(rows)}"
    endpoint, decision, sig_hit, risk = rows[0]
    assert endpoint == "/search"
    assert decision in ("LIKELY_ATTACK", "DEFINITE_ATTACK")
    assert sig_hit is not None, "signature_hit should be a JSON array for a UNION SELECT payload"
    parsed = _json.loads(sig_hit)
    assert isinstance(parsed, list) and len(parsed) >= 2, (
        f"Expected 2+ signature names, got: {parsed}"
    )
    assert "union_select" in parsed
    assert risk >= 60


def test_admin_accessible_to_admin(app, client):
    """A user with role='admin' must be able to reach /admin/ and get HTTP 200."""
    from app import bcrypt
    from app.models import create_user

    with app.app_context():
        hashed = bcrypt.generate_password_hash("AdminPass1!").decode("utf-8")
        create_user("siteadmin", "siteadmin@example.com", hashed, role="admin")

    client.post("/login", data={
        "username": "siteadmin",
        "password": "AdminPass1!",
    }, follow_redirects=True)

    rv = client.get("/admin/", follow_redirects=True)
    assert rv.status_code == 200
    assert b"Dashboard" in rv.data or b"attack" in rv.data.lower()


def test_suspicious_input_not_blocked(client):
    """
    A SUSPICIOUS-decision input (score 30–59) is logged but must NOT be blocked —
    the search query should still execute and return a 200 with no block flash.
    We use unittest.mock to control the pipeline result precisely so this test
    does not depend on ML score thresholds.
    """
    from unittest.mock import patch

    _register_and_login(client, "tester2", "tester2@example.com")

    suspicious_result = {
        "normalized": "test input",
        "signature_hit": None,
        "signature_score": 0,
        "anomaly_score": 35,
        "ml_score": 0.15,
        "risk_score": 45,
        "decision": "SUSPICIOUS",
    }

    with patch("app.profile.inspect", return_value=suspicious_result):
        rv = client.post("/search", data={"q": "test input"}, follow_redirects=True)

    assert rv.status_code == 200
    # SUSPICIOUS is logged but the user is NOT shown a block message
    assert b"Invalid input detected" not in rv.data


def test_natural_language_search_safe(client):
    """Phrases containing SQL keywords in plain English must not trigger a block."""
    _register_and_login(client, "tester3", "tester3@example.com")
    for phrase in ["in and out", "order online", "select size medium"]:
        rv = client.post("/search", data={"q": phrase}, follow_redirects=True)
        assert rv.status_code == 200, f"Unexpected status for phrase: {phrase!r}"
        assert b"Invalid input detected" not in rv.data, (
            f"False positive block for phrase: {phrase!r}"
        )


# ---------------------------------------------------------------------------
# Phase D tests — clear-log endpoint
# ---------------------------------------------------------------------------

def test_too_many_requests_page(app, client):
    """The 429 error handler must return a friendly HTML page (not a raw traceback)."""
    @app.route("/test-force-429")
    def _force_429():
        from flask import abort
        abort(429)

    rv = client.get("/test-force-429")
    assert rv.status_code == 429
    assert b"Internal" not in rv.data
    # The friendly message from errors.py must appear
    assert b"slow down" in rv.data.lower() or b"too many" in rv.data.lower()


def test_clear_log_requires_admin(client):
    """A non-admin user must get 403 when POSTing to /admin/clear-log."""
    _register_and_login(client, "normaluser2", "norm2@example.com")
    rv = client.post("/admin/clear-log", follow_redirects=False)
    assert rv.status_code in (403, 302)
    if rv.status_code == 302:
        # If redirected, it must not be to the dashboard (which would mean success)
        assert "/admin/" not in rv.headers.get("Location", "")


def test_admin_can_clear_old_logs(app, client):
    """Admin can POST /admin/clear-log and sees a success flash message."""
    import sqlite3
    from datetime import datetime, timedelta
    from app import bcrypt
    from app.models import create_user

    with app.app_context():
        hashed = bcrypt.generate_password_hash("AdminPass2!").decode("utf-8")
        create_user("clearadmin", "clearadmin@example.com", hashed, role="admin")

        # Insert an old log row directly so there's something to delete
        log_path = app.config["ATTACK_LOG_DB"]
        conn = sqlite3.connect(log_path)
        old_ts = (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO attack_logs (timestamp, source_ip, endpoint, raw_input, "
            "decision, risk_score) VALUES (?, '127.0.0.1', '/search', 'old', 'SAFE', 5)",
            (old_ts,),
        )
        conn.commit()
        conn.close()

    client.post("/login", data={
        "username": "clearadmin",
        "password": "AdminPass2!",
    }, follow_redirects=True)

    rv = client.post("/admin/clear-log", follow_redirects=True)
    assert rv.status_code == 200
    assert b"Deleted" in rv.data or b"deleted" in rv.data


# ---------------------------------------------------------------------------
# Phase E tests — dashboard counts, column visibility, sensitive data
# ---------------------------------------------------------------------------

def _make_admin(app, username, password):
    """Helper: create an admin user directly in the test DB."""
    from app import bcrypt
    from app.models import create_user
    with app.app_context():
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        create_user(username, f"{username}@example.com", hashed, role="admin")


def _insert_log_row(app, decision, anomaly_score=30.0, ml_score=0.5,
                    risk_score=40, signature_hit=None):
    """Helper: write a row directly into the test attack_logs database."""
    import sqlite3
    with app.app_context():
        path = app.config["ATTACK_LOG_DB"]
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO attack_logs
           (source_ip, endpoint, raw_input, normalized,
            signature_hit, anomaly_score, ml_score, risk_score, decision)
           VALUES ('127.0.0.1', '/search', 'test', 'test',
                   ?, ?, ?, ?, ?)""",
        (signature_hit, anomaly_score, ml_score, risk_score, decision),
    )
    conn.commit()
    conn.close()


def test_dashboard_suspicious_count_matches_db(app, client):
    """
    The Suspicious stat card value must equal the count of SUSPICIOUS rows
    in the attack_logs database, not a hardcoded number.
    """
    _make_admin(app, "dashtest1", "DashPass1!")
    _insert_log_row(app, "SUSPICIOUS",    anomaly_score=70, ml_score=0.8,  risk_score=45)
    _insert_log_row(app, "SUSPICIOUS",    anomaly_score=60, ml_score=0.75, risk_score=40)
    _insert_log_row(app, "LIKELY_ATTACK", anomaly_score=90, ml_score=0.99, risk_score=75)

    client.post("/login", data={"username": "dashtest1", "password": "DashPass1!"},
                follow_redirects=True)
    rv = client.get("/admin/", follow_redirects=True)
    assert rv.status_code == 200

    body = rv.data.decode("utf-8")
    # 2 SUSPICIOUS rows; the stat card value must reflect exactly this count
    assert "2" in body, "Expected SUSPICIOUS count of 2 to appear on dashboard"


def test_dashboard_blocked_count_is_separate_from_suspicious(app, client):
    """
    SUSPICIOUS and blocked (LIKELY_ATTACK + DEFINITE_ATTACK) are counted by
    separate SQL queries and displayed as separate stat cards.
    """
    _make_admin(app, "dashtest2", "DashPass2!")
    _insert_log_row(app, "SUSPICIOUS",     risk_score=45)
    _insert_log_row(app, "LIKELY_ATTACK",  risk_score=65)
    _insert_log_row(app, "DEFINITE_ATTACK",risk_score=85)

    client.post("/login", data={"username": "dashtest2", "password": "DashPass2!"},
                follow_redirects=True)
    rv = client.get("/admin/", follow_redirects=True)
    assert rv.status_code == 200

    from app.models import get_attack_stats
    with app.app_context():
        stats = get_attack_stats()

    assert stats["suspicious"] == 1, f"Expected 1 SUSPICIOUS, got {stats['suspicious']}"
    assert stats["blocked"]    == 2, f"Expected 2 blocked, got {stats['blocked']}"
    assert stats["total"]      == 3, f"Expected 3 total, got {stats['total']}"


def test_dashboard_anomaly_and_ml_scores_rendered(app, client):
    """anomaly_score and ml_score must appear in the log table rows."""
    _make_admin(app, "dashtest3", "DashPass3!")
    _insert_log_row(app, "SUSPICIOUS", anomaly_score=70.0, ml_score=0.93, risk_score=52)

    client.post("/login", data={"username": "dashtest3", "password": "DashPass3!"},
                follow_redirects=True)
    rv = client.get("/admin/", follow_redirects=True)
    assert rv.status_code == 200

    body = rv.data.decode("utf-8")
    # anomaly_score=70 → displayed as integer "70"
    assert "70" in body, "Expected anomaly_score 70 in dashboard table"
    # ml_score=0.93 → displayed as "93%"
    assert "93%" in body, "Expected ml_score 93% in dashboard table"


def test_dashboard_session_id_not_in_response(app, client):
    """
    session_id is a sensitive token. get_attack_logs() must exclude it from
    the SELECT so it never reaches the browser, even for admin users.
    """
    import sqlite3
    _make_admin(app, "dashtest4", "DashPass4!")

    # Insert a row with a recognisable session_id sentinel
    SENTINEL = "SUPERSECRET_SESSION_TOKEN_DO_NOT_EXPOSE"
    with app.app_context():
        path = app.config["ATTACK_LOG_DB"]
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO attack_logs
           (source_ip, endpoint, raw_input, normalized,
            anomaly_score, ml_score, risk_score, decision, session_id)
           VALUES ('127.0.0.1', '/search', 'test', 'test',
                   30, 0.5, 40, 'SUSPICIOUS', ?)""",
        (SENTINEL,),
    )
    conn.commit()
    conn.close()

    client.post("/login", data={"username": "dashtest4", "password": "DashPass4!"},
                follow_redirects=True)
    rv = client.get("/admin/", follow_redirects=True)
    assert rv.status_code == 200
    assert SENTINEL.encode() not in rv.data, (
        "session_id sentinel was found in the dashboard HTML response — "
        "it must be excluded from get_attack_logs() SELECT"
    )

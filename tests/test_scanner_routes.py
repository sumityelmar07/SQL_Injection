"""
Integration tests for Code Scanner routes (/scanner and /api/scan).
"""

import io
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app
from app.config import Config


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


@pytest.fixture()
def app(tmp_path):
    cfg = TestConfig()
    cfg.DATABASE = str(tmp_path / "test_app.db")
    cfg.ATTACK_LOG_DB = str(tmp_path / "test_attacks.db")
    application = create_app(cfg)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def _login(client, username="scanner_tester"):
    client.post("/register", data={
        "username": username,
        "email": f"{username}@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
    })
    return client.post("/login", data={
        "username": username,
        "password": "Password123!",
    }, follow_redirects=True)


def test_scanner_requires_login(client):
    rv = client.get("/scanner")
    assert rv.status_code == 302
    assert "/login" in rv.headers["Location"]


def test_scanner_page_loads_for_user(client):
    _login(client, "user_scanner_1")
    rv = client.get("/scanner")
    assert rv.status_code == 200
    assert b"Source Code SQL Injection Scanner" in rv.data


def test_scanner_pasted_vulnerable_code(client):
    _login(client, "user_scanner_2")
    vuln_code = "cursor.execute(f'SELECT * FROM users WHERE username = \"{user_input}\"')"
    rv = client.post("/scanner", data={
        "code_text": vuln_code,
        "filename": "vuln_test.py",
    })
    assert rv.status_code == 200
    assert b"CRITICAL" in rv.data
    assert b"f-string SQL Interpolation" in rv.data
    assert b"How to Fix" in rv.data


def test_scanner_pasted_safe_code(client):
    _login(client, "user_scanner_3")
    safe_code = "cursor.execute('SELECT * FROM users WHERE username = ?', (user_input,))"
    rv = client.post("/scanner", data={
        "code_text": safe_code,
        "filename": "safe_test.py",
    })
    assert rv.status_code == 200
    assert b"SAFE" in rv.data
    assert b"Verified Secure Practices" in rv.data


def test_scanner_file_upload(client):
    _login(client, "user_scanner_4")
    file_content = b"query = 'SELECT * FROM items WHERE id = ' + item_id\n"
    rv = client.post("/scanner", data={
        "code_file": (io.BytesIO(file_content), "items.py"),
    })
    assert rv.status_code == 200
    assert b"CRITICAL" in rv.data
    assert b"items.py" in rv.data


def test_scanner_api_json(client):
    _login(client, "user_scanner_5")
    rv = client.post("/api/scan", json={
        "code": "const sql = `SELECT * FROM accounts WHERE id = ${accId}`;",
        "filename": "service.js",
    })
    assert rv.status_code == 200
    json_data = rv.get_json()
    assert json_data["overall_risk"] == "CRITICAL"
    assert json_data["language"] == "JAVASCRIPT"
    assert len(json_data["findings"]) >= 1

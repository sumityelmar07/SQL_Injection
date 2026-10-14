"""
Database helpers using Python's built-in sqlite3 module.

Two separate databases are used:
  - app.db    : users (login credentials, roles)
  - attacks.db: attack event log (never mixed with user data)

Every query in this file uses parameterized placeholders (?) so that
user-supplied values are always treated as data, never as SQL code.
"""

import os
import sqlite3
from datetime import datetime
from flask import current_app, g


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a cached connection to app.db for the current request."""
    if "db" not in g:
        db_path = current_app.config["DATABASE"]
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row  # rows behave like dicts
    return g.db


def get_log_db():
    """Return a cached connection to attacks.db for the current request."""
    if "log_db" not in g:
        log_path = current_app.config["ATTACK_LOG_DB"]
        parent = os.path.dirname(log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        g.log_db = sqlite3.connect(
            log_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.log_db.row_factory = sqlite3.Row
    return g.log_db


def close_db(e=None):
    """Close both connections at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

    log_db = g.pop("log_db", None)
    if log_db is not None:
        log_db.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db(app):
    """Create tables if they do not exist yet. Called once at startup."""
    with app.app_context():
        db_path = app.config.get("DATABASE")
        if db_path and os.path.dirname(db_path):
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

        log_path = app.config.get("ATTACK_LOG_DB")
        if log_path and os.path.dirname(log_path):
            os.makedirs(os.path.dirname(log_path), exist_ok=True)

        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    UNIQUE NOT NULL,
                email      TEXT    UNIQUE NOT NULL,
                password   TEXT    NOT NULL,
                role       TEXT    NOT NULL DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        db.commit()

        # Ensure default admin account exists if not present
        if not app.config.get("TESTING"):
            admin_row = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
            if not admin_row:
                from . import bcrypt
                hashed = bcrypt.generate_password_hash("Admin@1234").decode("utf-8")
                db.execute(
                    "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                    ("admin", "admin@localhost.local", hashed, "admin"),
                )
                db.commit()

        log_db = get_log_db()
        log_db.executescript("""
            CREATE TABLE IF NOT EXISTS attack_logs (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip      TEXT,
                endpoint       TEXT,
                raw_input      TEXT,
                normalized     TEXT,
                signature_hit  TEXT,
                anomaly_score  REAL,
                ml_score       REAL,
                risk_score     INTEGER,
                decision       TEXT,
                session_id     TEXT
            );
        """)
        log_db.commit()


# ---------------------------------------------------------------------------
# User queries — all use ? placeholders
# ---------------------------------------------------------------------------

def create_user(username, email, hashed_password, role="user"):
    db = get_db()
    db.execute(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        (username, email, hashed_password, role),
    )
    db.commit()


def get_user_by_username(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(user_id):
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def get_user_by_email(email):
    return get_db().execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()


# ---------------------------------------------------------------------------
# Attack log queries — all use ? placeholders
# ---------------------------------------------------------------------------

def log_attack(source_ip, endpoint, raw_input, normalized,
               signature_hit, anomaly_score, ml_score, risk_score,
               decision, session_id=None):
    log_db = get_log_db()
    log_db.execute(
        """INSERT INTO attack_logs
           (source_ip, endpoint, raw_input, normalized, signature_hit,
            anomaly_score, ml_score, risk_score, decision, session_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (source_ip, endpoint, raw_input, normalized, signature_hit,
         anomaly_score, ml_score, risk_score, decision, session_id),
    )
    log_db.commit()


def get_attack_logs(limit=200):
    # Explicit column list: excludes session_id (sensitive, not needed for
    # display) and normalized (internal pipeline detail, not shown to admin).
    return get_log_db().execute(
        """SELECT id, timestamp, source_ip, endpoint, raw_input,
                  signature_hit, anomaly_score, ml_score, risk_score, decision
           FROM attack_logs ORDER BY timestamp DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def clear_old_logs(days: int = 7) -> int:
    """Delete attack_logs rows older than *days* days. Returns the row count deleted."""
    log_db = get_log_db()
    cur = log_db.execute(
        "DELETE FROM attack_logs WHERE timestamp < datetime('now', ?)",
        (f"-{days} days",),
    )
    log_db.commit()
    return cur.rowcount


def get_attack_stats():
    """Return summary counts used by the admin dashboard."""
    log_db = get_log_db()
    total = log_db.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]
    suspicious = log_db.execute(
        "SELECT COUNT(*) FROM attack_logs WHERE decision='SUSPICIOUS'"
    ).fetchone()[0]
    blocked = log_db.execute(
        "SELECT COUNT(*) FROM attack_logs WHERE decision IN ('LIKELY_ATTACK','DEFINITE_ATTACK')"
    ).fetchone()[0]
    by_endpoint = log_db.execute(
        "SELECT endpoint, COUNT(*) as cnt FROM attack_logs GROUP BY endpoint ORDER BY cnt DESC"
    ).fetchall()
    by_decision = log_db.execute(
        "SELECT decision, COUNT(*) as cnt FROM attack_logs GROUP BY decision"
    ).fetchall()
    return {
        "total":      total,
        "suspicious": suspicious,
        "blocked":    blocked,
        "by_endpoint": [dict(r) for r in by_endpoint],
        "by_decision": [dict(r) for r in by_decision],
    }

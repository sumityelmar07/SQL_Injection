"""
Protected profile route — only reachable after login.
Demonstrates a safe parameterized search query.
"""

from flask import Blueprint, render_template, request, flash, session
from flask_login import login_required, current_user
from .models import get_db, log_attack
from . import limiter
from detection.pipeline import inspect

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@profile_bp.route("/search", methods=["GET", "POST"])
@login_required
@limiter.limit("60 per minute")
def search():
    """
    A deliberately simple user-search feature.
    It exists so you can demonstrate injection attempts in a realistic context.
    The query uses a parameterized LIKE pattern — injection has no effect.
    """
    results = []
    query_term = ""

    if request.method == "POST":
        query_term = request.form.get("q", "").strip()

        result = inspect(query_term)

        if result["decision"] in ("SUSPICIOUS", "LIKELY_ATTACK", "DEFINITE_ATTACK"):
            log_attack(
                source_ip=request.remote_addr,
                endpoint="/search",
                raw_input=query_term,
                normalized=result["normalized"],
                signature_hit=result.get("signature_hit"),
                anomaly_score=result["anomaly_score"],
                ml_score=result["ml_score"],
                risk_score=result["risk_score"],
                decision=result["decision"],
                session_id=session.get("_id"),
            )

        if result["decision"] in ("LIKELY_ATTACK", "DEFINITE_ATTACK"):
            flash("Invalid input detected.", "danger")
        else:
            # Parameterized LIKE query — the % wildcards are added in Python,
            # not concatenated into the SQL string.
            db = get_db()
            rows = db.execute(
                "SELECT username, email FROM users WHERE username LIKE ?",
                (f"%{query_term}%",),
            ).fetchall()
            results = [dict(r) for r in rows]

    return render_template("search.html", results=results, query=query_term)

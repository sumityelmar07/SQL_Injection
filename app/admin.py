"""
Admin dashboard — accessible only to users with role='admin'.
"""

from flask import Blueprint, render_template, abort, redirect, url_for, flash, request
from flask_login import login_required, current_user
from .models import get_attack_logs, get_attack_stats, clear_old_logs
import os, json

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin():
    if not current_user.is_authenticated or current_user.role != "admin":
        abort(403)


@admin_bp.route("/")
@login_required
def dashboard():
    _require_admin()
    logs = get_attack_logs(limit=200)
    stats = get_attack_stats()
    return render_template("admin/dashboard.html",
                           logs=logs, stats=stats,
                           stats_json=json.dumps(stats))


@admin_bp.route("/clear-log", methods=["POST"])
@login_required
def clear_log():
    _require_admin()
    deleted = clear_old_logs(days=7)
    flash(f"Deleted {deleted} log entries older than 7 days.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/metrics")
@login_required
def metrics():
    _require_admin()
    # Read pre-computed metrics written by ml/evaluate.py
    metrics_path = os.path.join(
        os.path.dirname(__file__), "..", "ml", "metrics.json"
    )
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            data = json.load(f)
    else:
        data = None
    return render_template("admin/metrics.html", metrics=data)

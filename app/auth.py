"""
Authentication routes: /register, /login, /logout.

Every user-supplied value is inspected by the detection pipeline before
the database is touched. The database queries themselves use parameterized
placeholders (?) regardless — detection is the alarm, parameterized queries
are the actual lock.
"""

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session)
from flask_login import login_user, logout_user, login_required, UserMixin, current_user

from . import bcrypt, login_manager, limiter
from .models import create_user, get_user_by_username, get_user_by_email, log_attack

# Lazy import so detection module is only loaded after the app is set up.
from detection.pipeline import inspect

auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# flask-login user loader
# ---------------------------------------------------------------------------

class User(UserMixin):
    """Thin wrapper so flask-login can work with sqlite3.Row objects."""

    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.role = row["role"]
        # The hashed password is NOT stored on this object — never needed after login.

    def get_id(self):
        return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    from .models import get_user_by_id
    row = get_user_by_id(int(user_id))
    return User(row) if row else None


# ---------------------------------------------------------------------------
# Helper: run detection on a dict of field values
# ---------------------------------------------------------------------------

def _check_inputs(fields: dict, endpoint: str) -> tuple[bool, dict]:
    """
    Inspect each field through the detection pipeline.

    Returns (blocked: bool, worst_result: dict).
    Logs any non-safe result to attacks.db.
    """
    worst = None
    blocked = False

    for field_name, value in fields.items():
        if not isinstance(value, str):
            continue
        result = inspect(value)

        if result["decision"] in ("SUSPICIOUS", "LIKELY_ATTACK", "DEFINITE_ATTACK"):
            log_attack(
                source_ip=request.remote_addr,
                endpoint=endpoint,
                raw_input=value,
                normalized=result["normalized"],
                signature_hit=result.get("signature_hit"),
                anomaly_score=result["anomaly_score"],
                ml_score=result["ml_score"],
                risk_score=result["risk_score"],
                decision=result["decision"],
                session_id=session.get("_id"),
            )

        if result["decision"] in ("LIKELY_ATTACK", "DEFINITE_ATTACK"):
            blocked = True

        if worst is None or result["risk_score"] > worst["risk_score"]:
            worst = result

    return blocked, worst or {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("profile.profile"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("profile.profile"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        blocked, _ = _check_inputs({"username": username}, "/login")
        if blocked:
            flash("Invalid input detected.", "danger")
            return render_template("login.html"), 400

        row = get_user_by_username(username)

        # Deliberately vague message — do not reveal whether username or password was wrong.
        if row is None or not bcrypt.check_password_hash(row["password"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        user = User(row)
        login_user(user)
        return redirect(url_for("profile.profile"))

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("profile.profile"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Basic validation
        if not username or not email or not password:
            flash("All fields are required.", "warning")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "warning")
            return render_template("register.html")

        # Detection check on user-supplied text fields
        blocked, _ = _check_inputs({"username": username, "email": email}, "/register")
        if blocked:
            flash("Invalid input detected.", "danger")
            return render_template("register.html"), 400

        if get_user_by_username(username):
            flash("Username already taken.", "warning")
            return render_template("register.html")

        if get_user_by_email(email):
            flash("Email already registered.", "warning")
            return render_template("register.html")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        create_user(username, email, hashed)
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))

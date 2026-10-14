"""
App factory.

Calling create_app() builds and returns a configured Flask application.
Using a factory function (instead of a global `app`) makes testing easier
because each test can create its own isolated app instance.
"""

import json as _json

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .config import Config
from .models import close_db, init_db

bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

login_manager.login_view = "auth.login"          # redirect here if not logged in
login_manager.login_message_category = "info"


def _parse_sig_hits(value):
    """Jinja2 filter: convert signature_hit JSON string to a Python list."""
    if not value:
        return []
    try:
        result = _json.loads(value)
        return result if isinstance(result, list) else [result]
    except (_json.JSONDecodeError, TypeError):
        return [str(value)]


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_class)

    # Initialise extensions
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)      # validates csrf_token on every POST/PUT/PATCH/DELETE
    limiter.init_app(app)   # rate-limits configured per-route via @limiter.limit()

    # Jinja2 filter: parse JSON signature_hit list for dashboard display
    app.jinja_env.filters["parse_sig_hits"] = _parse_sig_hits

    # Close DB connections after every request
    app.teardown_appcontext(close_db)

    # Create tables on first run
    init_db(app)

    # Register blueprints (route groups)
    from .auth import auth_bp
    from .profile import profile_bp
    from .admin import admin_bp
    from .scanner import scanner_bp
    from .errors import register_error_handlers

    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(scanner_bp)
    register_error_handlers(app)

    return app

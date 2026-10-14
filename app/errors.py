"""
Safe error handlers.

Flask calls these functions when an HTTP error occurs. They return a
friendly HTML page — never a raw exception, stack trace, or SQL message.
The full error is printed to the server console (stdout) for the developer.
"""

import traceback
from flask import render_template


def register_error_handlers(app):

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400,
                               message="Bad request. Please check your input."), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message="You do not have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="Page not found."), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("error.html", code=429,
                               message="Too many requests. Please slow down and try again in a moment."), 429

    @app.errorhandler(500)
    def server_error(e):
        # Log the full traceback server-side only — never expose it to the browser.
        traceback.print_exc()
        return render_template("error.html", code=500,
                               message="An internal error occurred. Please try again later."), 500

"""
Source code scanner route blueprint.

Allows users to upload or paste source code files (Python, PHP, JavaScript,
Java, C#, SQL) to detect dynamic SQL construction, string formatting vulnerabilities,
and SQL injection risks via static analysis (SAST).
"""

from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required
from werkzeug.utils import secure_filename

from . import csrf
from detection.code_scanner import scan_source_code

scanner_bp = Blueprint("scanner", __name__)

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB limit


@scanner_bp.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():
    report = None
    code_text = ""
    filename = "snippet.py"

    if request.method == "POST":
        uploaded_file = request.files.get("code_file")
        pasted_text = request.form.get("code_text", "").strip()

        if uploaded_file and uploaded_file.filename:
            raw_filename = secure_filename(uploaded_file.filename) or "uploaded_code.txt"
            filename = raw_filename
            file_bytes = uploaded_file.read()

            if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                flash("File exceeds maximum allowed size (2 MB).", "warning")
                return render_template("scanner.html", report=None, raw_code="")

            try:
                code_text = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    code_text = file_bytes.decode("latin-1")
                except Exception:
                    flash("Unable to decode file content as text.", "danger")
                    return render_template("scanner.html", report=None, raw_code="")

        elif pasted_text:
            code_text = pasted_text
            input_filename = request.form.get("filename", "").strip()
            if input_filename:
                filename = secure_filename(input_filename)
            else:
                filename = "pasted_code.py"
        else:
            flash("Please upload a file or paste source code to scan.", "warning")
            return render_template("scanner.html", report=None, raw_code="")

        report = scan_source_code(code_text, filename=filename)

    return render_template(
        "scanner.html",
        report=report,
        raw_code=code_text,
        filename=filename,
    )


@scanner_bp.route("/api/scan", methods=["POST"])
@csrf.exempt
@login_required
def api_scan():
    """Programmatic JSON endpoint for scanning code files."""
    code_text = ""
    filename = "snippet.py"

    if request.is_json:
        data = request.get_json() or {}
        code_text = data.get("code", "")
        filename = data.get("filename", "snippet.py")
    else:
        uploaded_file = request.files.get("code_file")
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            code_text = uploaded_file.read().decode("utf-8", errors="replace")
        else:
            code_text = request.form.get("code", "")
            filename = request.form.get("filename", "snippet.py")

    if not code_text.strip():
        return jsonify({"error": "No code provided"}), 400

    report = scan_source_code(code_text, filename=filename)
    return jsonify(report.to_dict())

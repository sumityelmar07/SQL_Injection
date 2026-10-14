"""
Entry point.  Run with:  python run.py

The app starts on http://0.0.0.0:5000 (reachable from the local browser).

Debug mode is OFF by default.  Enable it only during development:
    FLASK_DEBUG=1 python run.py

Never run with FLASK_DEBUG=1 on a machine accessible to other people —
the Werkzeug interactive debugger allows arbitrary code execution.
"""

import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)

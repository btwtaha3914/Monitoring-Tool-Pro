"""
Vercel entry point for the full Monitor Suite app.

Vercel's Python runtime executes this file directly and looks for a
WSGI-callable named `app` at module scope. It runs with the working
directory set to this file's own folder (`api/`), NOT the project
root -- so without help, `app.py`'s own `from modules.web_monitor import
...` etc. would fail to resolve.

This file's only job is to make the project root importable first,
then import the real Flask app unchanged from app.py so every route,
blueprint, and piece of logic behaves exactly as it does when you run
`python app.py` locally.
"""

import os
import sys

# --- Make the project root importable ------------------------------------
# api/index.py lives at   <project_root>/api/index.py
# app.py lives at         <project_root>/app.py
_API_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_API_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# --- Import the existing Flask app (routes, blueprints, everything) ------
from app import app  # noqa: E402

# Vercel's @vercel/python runtime looks for a WSGI-callable named `app`
# at module scope in this file -- that's the import above, nothing else
# to wire up.

if __name__ == "__main__":
    # Local testing only: `python api/index.py`
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

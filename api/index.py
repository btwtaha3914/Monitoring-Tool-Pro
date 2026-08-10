"""
Vercel serverless entry point.
Vercel looks for a WSGI-compatible `app` object in files under /api.
This just imports your existing Flask app unchanged.
"""
import os
import sys

# Make the project root importable (so `import auth`, `import modules...` work)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app  # noqa: E402

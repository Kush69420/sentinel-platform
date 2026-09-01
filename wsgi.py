"""Production WSGI entrypoint. Run via: gunicorn wsgi:app

Do not run this file directly, and never run app.py directly in production —
app.py's `if __name__ == "__main__"` block starts Werkzeug's dev server with
debug=True, which must not be reachable outside local development.
"""
from app import app  # noqa: F401  — gunicorn imports the `app` object from this module

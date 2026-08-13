import os

# app.py fails fast on missing SECRET_KEY/ENCRYPTION_KEY unless FLASK_ENV=development
# (see the "Fail-fast secrets" fix in app.py, ~module top). The test suite never sets
# real secrets, so it must opt into the dev fallback the same way local `flask run`
# would. This runs before any test module imports `app`, since unittest discover
# imports the `tests` package first.
os.environ.setdefault("FLASK_ENV", "development")

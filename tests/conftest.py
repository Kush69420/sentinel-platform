"""Test-suite environment isolation.

app.py calls load_dotenv() at import, so a developer's local .env leaks into
every test run. That is mostly harmless, but Google sign-in is not: configuring
it switches the admin password door OFF (see admin_password_login_enabled() in
app.py), which silently breaks every pre-existing test that logs in with a
username and password — on that developer's machine only, while CI stays green.
A test suite whose results depend on whether the person running it happens to
have Google OAuth configured is not a test suite.

So the default world for tests is "Google sign-in not configured", set here
before app.py is imported (pytest loads conftest first, and these are read into
module-level constants at import time). Tests that exercise Google sign-in opt
back in explicitly by patching those constants — see
tests/test_admin_google_oauth.py, which does exactly that.
"""
import os

for _var in (
    "GOOGLE_OAUTH_CLIENT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
    "GOOGLE_OAUTH_REDIRECT_URI",
    "ADMIN_PASSWORD_LOGIN",
):
    os.environ.pop(_var, None)

# load_dotenv() does not override variables that already exist in the
# environment, so an empty-string placeholder survives it and keeps Google
# sign-in disabled regardless of what the local .env says.
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = ""
os.environ["GOOGLE_OAUTH_CLIENT_SECRET"] = ""
os.environ["GOOGLE_OAUTH_REDIRECT_URI"] = ""

"""INACTIVITY_EXEMPT_ENDPOINTS — the idle-timeout hook must not intercept
session-establishing routes.

`_enforce_inactivity_timeout()` (app.py) had no exemption list at all: it
gates purely on `session.get("is_user")`/`is_admin`, with no notion of "this
route doesn't need an existing session" the way `_enforce_csrf()` already has
via `CSRF_EXEMPT_ENDPOINTS`. Confirmed consequence: a browser holding a stale,
idle-expired session cookie got a raw 401 `{"error": "Session expired due to
inactivity"}` on the *next* request to ANY route, before that route's own
logic ever ran — including a login POST with the *correct* password (never
even inspected), the Google admin login redirect (401 JSON instead of a 302
to Google), and the plain `/login` page (401 JSON instead of the login page).

The fix adds `INACTIVITY_EXEMPT_ENDPOINTS` (app.py, next to
`_enforce_inactivity_timeout()`) and checks it first in the hook. It is
deliberately NOT the same object as `CSRF_EXEMPT_ENDPOINTS` — it's a superset
of it, unioned in app.py — because this hook runs on every method (GET
included) and has to cover routes CSRF never had to: the Google OAuth GET
round-trip, the login/admin pages themselves, and Flask's own "static"
endpoint.

Seams under test here:
  - a stale-but-not-yet-cleared session no longer blocks POST /api/user/login
    from reaching real credential verification (and correct credentials win).
  - the Google admin login route still redirects (302) rather than 401ing.
  - GET /login still renders the login page rather than 401ing.
  - the remaining content-only pages (/, /register, /pricing,
    /reset-password, /analysis, /cdr-analysis) also render rather than
    401ing on a stale session — closing the open observation the earlier
    pass on this hook left behind.
  - regression: an idle-expired session is STILL rejected on a genuinely
    @admin_required route and on /api/events (@session_required) — the
    exemption list must not have swallowed real enforcement.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_user_auth import FakeConn, make_db  # reuse the bot_users login fixture

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
CLIENT_SECRET = "test-client-secret"
REDIRECT_URI = "https://sentinel.example/api/admin/auth/google/callback"


def _iso(dt):
    return dt.isoformat()


class _InactivityExemptionTestBase(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.fake_conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        self.addCleanup(self.get_db_patch.stop)
        app_module._rate_limiter._windows.clear()  # per-IP login rate limit is a module-level singleton
        # Fixed 15-minute window, independent of app_settings/env — same
        # approach as tests/test_inactivity_timeout.py.
        self.timeout_patch = mock.patch.object(app_module, "_inactivity_timeout_seconds", return_value=900)
        self.timeout_patch.start()
        self.addCleanup(self.timeout_patch.stop)
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def _seed_stale_user_session(self, idle_minutes=20):
        """A session that still says is_user=True but whose last_activity_at
        marker is well past the (patched) 15-minute window — exactly the
        "browser had a tab open overnight" scenario the bug report reproduces."""
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 999
            sess["last_activity_at"] = _iso(datetime.utcnow() - timedelta(minutes=idle_minutes))

    def _seed_stale_admin_session(self, idle_minutes=20):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["admin_name"] = "Ops Admin"
            sess["last_activity_at"] = _iso(datetime.utcnow() - timedelta(minutes=idle_minutes))


class StaleSessionLoginTests(_InactivityExemptionTestBase):
    def test_stale_session_does_not_block_correct_credentials(self):
        """The headline reproduction: a stale is_user=True cookie must not
        turn a correct-password POST /api/user/login into a 401 before the
        credentials are even looked at."""
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["user"]["phone"], "9999999999")

    def test_a_still_fresh_session_hitting_login_is_unchanged(self):
        """Explicitly NOT a side effect of this fix: a logged-in, non-idle
        session hitting the login endpoint keeps whatever behaviour it had
        before — it is not specially blocked or specially treated, it just
        runs user_login() normally, same as a stale-exempted one does."""
        self._seed_stale_user_session(idle_minutes=1)  # within the 15-min window
        resp = self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["success"])


class StaleSessionGoogleLoginTests(_InactivityExemptionTestBase):
    def _with_google(self):
        patchers = [
            mock.patch.object(self.app_module, "GOOGLE_OAUTH_CLIENT_ID", CLIENT_ID),
            mock.patch.object(self.app_module, "GOOGLE_OAUTH_CLIENT_SECRET", CLIENT_SECRET),
            mock.patch.object(self.app_module, "GOOGLE_OAUTH_REDIRECT_URI", REDIRECT_URI),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_stale_admin_session_still_gets_redirected_to_google(self):
        """A stale is_admin=True cookie must not turn "click Sign in with
        Google" into a raw 401 JSON body — it must still 302 to Google's
        consent screen, exactly as it would for a fully anonymous visitor."""
        self._with_google()
        self._seed_stale_admin_session(idle_minutes=30)
        resp = self.client.get("/api/admin/auth/google/login")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].startswith(self.app_module.GOOGLE_AUTH_ENDPOINT))


class StaleSessionLoginPageTests(_InactivityExemptionTestBase):
    def test_stale_session_still_renders_the_login_page(self):
        """GET /login must render login.html, not a 401 JSON body, even when
        the browser is carrying a stale is_user cookie."""
        self._seed_stale_user_session(idle_minutes=45)
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")

    def test_stale_admin_session_still_renders_the_admin_page(self):
        """Same property for /admin: it hosts both the Google button and the
        break-glass password form, so it must stay reachable precisely when
        the admin's existing session has gone stale — that's the whole
        reason to be there."""
        self._seed_stale_admin_session(idle_minutes=45)
        resp = self.client.get("/admin")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")


class StaleSessionContentOnlyPageTests(_InactivityExemptionTestBase):
    """The remaining content-only pages that share the same pre-existing
    quirk (401 instead of rendering) when a session is stale — closing the
    open observation the previous pass on this hook left behind. Each of
    these was individually verified (see the INACTIVITY_EXEMPT_ENDPOINTS
    comment in app.py) to have no inline session gate and no server-side
    Jinja branching on session state, so there is nothing for a stale
    session to protect here either."""

    def test_stale_session_still_renders_the_home_page(self):
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")

    def test_stale_session_still_renders_the_register_page(self):
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.get("/register")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")

    def test_stale_session_still_renders_the_pricing_page(self):
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.get("/pricing")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")

    def test_stale_session_still_renders_the_reset_password_page(self):
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.get("/reset-password")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")

    def test_stale_session_still_renders_the_analysis_page(self):
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.get("/analysis")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")

    def test_stale_session_still_renders_the_cdr_analysis_page(self):
        """/cdr-analysis is a second route on the same cdr_analysis_page
        endpoint as /analysis — confirming both paths are covered by
        exempting the one endpoint name."""
        self._seed_stale_admin_session(idle_minutes=20)
        resp = self.client.get("/cdr-analysis")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type.split(";")[0], "text/html")


class StillEnforcedOnAuthenticatedRoutesTests(_InactivityExemptionTestBase):
    """Regression guard: the exemption list must not have accidentally
    swallowed real enforcement. An idle-expired session must still be
    rejected on a genuinely @admin_required route and on /api/events."""

    def test_idle_expired_session_is_still_rejected_on_an_admin_route(self):
        self._seed_stale_admin_session(idle_minutes=20)
        resp = self.client.get("/api/admin/session-info")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("inactivity", resp.get_json()["error"].lower())

    def test_idle_expired_session_is_still_rejected_on_the_sse_stream(self):
        self._seed_stale_admin_session(idle_minutes=20)
        resp = self.client.get("/api/events")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("inactivity", resp.get_json()["error"].lower())

    def test_idle_expired_user_session_is_still_rejected_on_a_user_route(self):
        self._seed_stale_user_session(idle_minutes=20)
        resp = self.client.get("/api/me")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("inactivity", resp.get_json()["error"].lower())


if __name__ == "__main__":
    unittest.main()

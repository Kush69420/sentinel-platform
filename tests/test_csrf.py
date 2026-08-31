"""Day 2 (c) — CSRF protection.

Before this fix there were no CSRF tokens anywhere, no SameSite cookie config:
every session-authenticated state-changing endpoint was forgeable by a page the
victim's browser merely had open while logged in (the browser attaches session
cookies to cross-site requests automatically).

The fix is a lightweight, dependency-free double-submit token: a random token is
minted into the server-side session at login (user_login/admin_login/user_signup,
`app.py`) and `_enforce_csrf()` (a `before_request` hook) requires it to be echoed
back in the `X-CSRF-Token` header on every POST/PUT/DELETE once a session is
authenticated. `GET /api/csrf-token` hands the token to the frontend.

Seams under test:
  - `_enforce_csrf()` before_request hook: blocks authenticated state-changing
    requests with a missing/wrong token, allows GET regardless, and does not
    apply to unauthenticated requests (nothing to protect yet).
  - `GET /api/csrf-token`: 401 unauthenticated; returns (and persists) a token
    once authenticated.
  - Login mints a fresh token into the session and returns it in the response.
"""
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_user_auth import FakeConn, make_db  # reuse the bot_users login fixture


class _ActivityOnlyCursor:
    """Accepts the one query log_activity() issues; ignores everything else.

    Enough to exercise /api/user/logout and /api/admin/logout without pulling in
    a full bot_users/admin_users fixture just to prove the CSRF gate works.
    """

    def execute(self, query, params=()):
        return None

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    @property
    def rowcount(self):
        return 0


class _ActivityOnlyConn:
    def cursor(self, dictionary=False):
        return _ActivityOnlyCursor()

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class CsrfEnforcementTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=_ActivityOnlyConn())
        self.get_db_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def _authenticated_user_session(self, token="right-token"):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
            sess["csrf_token"] = token

    def _authenticated_admin_session(self, token="right-token"):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["csrf_token"] = token

    def test_authenticated_post_without_header_is_rejected(self):
        self._authenticated_user_session()
        resp = self.client.post("/api/user/logout")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("CSRF", resp.get_json()["error"])

    def test_authenticated_post_with_wrong_header_is_rejected(self):
        self._authenticated_user_session(token="right-token")
        resp = self.client.post("/api/user/logout", headers={"X-CSRF-Token": "wrong-token"})
        self.assertEqual(resp.status_code, 403)

    def test_authenticated_post_with_correct_header_succeeds(self):
        self._authenticated_user_session(token="right-token")
        resp = self.client.post("/api/user/logout", headers={"X-CSRF-Token": "right-token"})
        self.assertEqual(resp.status_code, 200)

    def test_admin_post_without_header_is_rejected(self):
        self._authenticated_admin_session()
        resp = self.client.post("/api/admin/logout")
        self.assertEqual(resp.status_code, 403)

    def test_admin_post_with_correct_header_succeeds(self):
        self._authenticated_admin_session(token="admin-token")
        resp = self.client.post("/api/admin/logout", headers={"X-CSRF-Token": "admin-token"})
        self.assertEqual(resp.status_code, 200)

    def test_get_requests_are_never_blocked(self):
        self._authenticated_user_session()
        resp = self.client.get("/api/user/session")
        self.assertNotEqual(resp.status_code, 403)

    def test_unauthenticated_post_is_not_csrf_blocked(self):
        """No session yet means nothing to forge — CSRF does not apply here.

        (It may still fail for ordinary business-logic reasons — missing body,
        rate limit, etc. — just never with the CSRF error.)
        """
        resp = self.client.post("/api/user/password-reset/request", json={})
        # Exact code, not just "not a CSRF 403": an empty body is missing the
        # required `identifier` field, which fails business-logic validation
        # with 400 — a 500 here would satisfy assertNotEqual(..., 403) too.
        self.assertEqual(resp.status_code, 400)

    def test_session_without_a_token_yet_is_not_silently_allowed(self):
        """A pre-existing authenticated session with no csrf_token (e.g. one from
        before this feature shipped) must fail closed, not be waved through.

        It used to fail closed with a 403 that no amount of retrying could clear.
        It now fails closed by dropping the unusable session: the request runs
        as an anonymous caller, so @user_required answers 401 and the frontend
        can send the user to a login that actually works.
        """
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
            # deliberately no csrf_token
        resp = self.client.post("/api/user/logout", headers={"X-CSRF-Token": "anything"})
        self.assertEqual(resp.status_code, 401)
        with self.client.session_transaction() as sess:
            self.assertNotIn("is_user", sess, "the unusable session was left in place")


class CsrfLoginLockoutTests(unittest.TestCase):
    """Regression: a stale session cookie must never block logging back in.

    A browser holding a session cookie minted before CSRF enforcement shipped
    (is_user set, no csrf_token) got `CSRF token missing or invalid` from
    POST /api/user/login itself — the one request that would have handed it a
    fresh token. The only way out was clearing cookies by hand. The login,
    signup and password-reset entry points are now exempt from the check.
    """

    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=FakeConn(self.db))
        self.get_db_patch.start()
        app_module._rate_limiter._windows.clear()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def _stale_session(self):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
            # no csrf_token — the shape of every session issued before Day 2

    def test_login_succeeds_with_a_stale_tokenless_session_cookie(self):
        self._stale_session()
        resp = self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertTrue(resp.get_json().get("csrf_token"))

    def test_login_is_exempt_even_with_a_fully_valid_session(self):
        """Logging in again from an already-authenticated tab must not 403 either."""
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
            sess["csrf_token"] = "some-token"
        resp = self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        self.assertEqual(resp.status_code, 200, resp.get_json())

    def test_password_reset_confirm_is_exempt_with_a_stale_session(self):
        self._stale_session()
        resp = self.client.post("/api/user/password-reset/confirm", json={})
        # An empty body is missing the required `token`, which 400s before
        # anything else runs — the exact code, not merely "not 403".
        self.assertEqual(resp.status_code, 400)

    def test_signup_is_exempt_with_a_stale_session(self):
        self._stale_session()
        resp = self.client.post("/api/user/signup", json={})
        # An empty body is missing the required `name`, which 400s before any
        # DB access — the exact code, not merely "not 403".
        self.assertEqual(resp.status_code, 400)

    def test_admin_login_is_exempt_with_a_stale_session(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
        # admin_login hits admin_users, which the bot_users fixture does not carry.
        with mock.patch.object(self.app_module, "get_db", return_value=_ActivityOnlyConn()):
            resp = self.client.post("/api/admin/login", json={"username": "nobody", "password": "x"})
        # _ActivityOnlyCursor's fetchone() always returns None, so admin_login
        # takes its "unknown username" branch: exact 401, not merely "not 403".
        self.assertEqual(resp.status_code, 401)


class CsrfTokenEndpointTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=_ActivityOnlyConn())
        self.get_db_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def test_requires_authentication(self):
        resp = self.client.get("/api/csrf-token")
        self.assertEqual(resp.status_code, 401)

    def test_returns_the_sessions_token(self):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
            sess["csrf_token"] = "existing-token"
        resp = self.client.get("/api/csrf-token")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["csrf_token"], "existing-token")

    def test_mints_a_token_if_the_session_has_none_yet(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
        resp = self.client.get("/api/csrf-token")
        self.assertEqual(resp.status_code, 200)
        token = resp.get_json()["csrf_token"]
        self.assertTrue(token)
        # And it's now usable for a subsequent state-changing request.
        resp2 = self.client.post("/api/admin/logout", headers={"X-CSRF-Token": token})
        self.assertEqual(resp2.status_code, 200)


class LoginMintsCsrfTokenTests(unittest.TestCase):
    """The real login path (not a hand-crafted session) must set the token too."""

    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.fake_conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        app_module._rate_limiter._windows.clear()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def test_login_response_includes_a_csrf_token(self):
        resp = self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        self.assertEqual(resp.status_code, 200)
        token = resp.get_json().get("csrf_token")
        self.assertTrue(token, "login response does not include a csrf_token")

    def test_the_returned_token_is_the_one_the_server_checks(self):
        resp = self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        token = resp.get_json()["csrf_token"]
        logout_resp = self.client.post("/api/user/logout", headers={"X-CSRF-Token": token})
        self.assertEqual(logout_resp.status_code, 200)

    def test_logout_without_the_token_is_rejected_even_after_a_real_login(self):
        self.client.post(
            "/api/user/login",
            json={"identifier": "9999999999", "password": "CorrectHorse123!"},
        )
        logout_resp = self.client.post("/api/user/logout")
        self.assertEqual(logout_resp.status_code, 403)


BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _template(name):
    with open(os.path.join(BASE, "templates", name), encoding="utf-8") as fh:
        return fh.read()


class FrontendCsrfSweepTest(unittest.TestCase):
    """The 3 templates that issue an authenticated state-changing fetch() must
    install the wrapper that attaches X-CSRF-Token — otherwise every one of
    their POST/PUT/DELETE calls gets a 403 from _enforce_csrf() with no way
    for the page to have known to send the header.

    Of the 8 templates with any fetch() call at all, only admin.html,
    dashboard.html and pricing.html have calls reachable from an authenticated
    session (54 total state-changing calls counted in the Day 2 brief split as
    admin.html 40, dashboard.html 9, pricing.html 1, plus 4 pre-login calls in
    login.html/register.html/reset_password.html that are deliberately exempt
    — nothing is authenticated yet at signup/login/password-reset time).
    index.html and workspace.html have fetch() calls but none of them are
    POST/PUT/DELETE.
    """

    WRAPPED_TEMPLATES = ("admin.html", "dashboard.html", "pricing.html")
    EXEMPT_TEMPLATES = ("index.html", "login.html", "register.html", "reset_password.html", "workspace.html")

    def test_wrapped_templates_install_the_csrf_fetch_wrapper(self):
        for name in self.WRAPPED_TEMPLATES:
            with self.subTest(template=name):
                body = _template(name)
                self.assertIn("X-CSRF-Token", body, f"{name} has an authenticated POST/PUT/DELETE but never sets X-CSRF-Token")
                self.assertIn("window.fetch=async function", body, f"{name} does not wrap window.fetch")
                self.assertIn("/api/csrf-token", body, f"{name} never fetches a CSRF token")

    def test_wrapper_is_installed_before_any_other_script_code(self):
        """The override must run before any fetch() call site further down the
        file, or an early call (e.g. one fired from a top-level script tag,
        not just an event handler) would use the native unwrapped fetch."""
        for name in self.WRAPPED_TEMPLATES:
            with self.subTest(template=name):
                body = _template(name)
                script_start = body.index("<script>")
                wrapper_at = body.index("window.fetch=async function", script_start)
                first_call_site = body.index("fetch(", wrapper_at + len("window.fetch=async function"))
                self.assertLess(wrapper_at, first_call_site)

    def test_exempt_templates_have_no_authenticated_state_changing_calls(self):
        """Every fetch() in these templates must be either GET (default/explicit)
        or an unauthenticated POST — routes with no session to protect yet."""
        unauthenticated_post_routes = {
            "/api/user/signup", "/api/user/login", "/api/user/password-reset/request",
            "/api/user/password-reset/confirm",
        }
        state_changing = re.compile(r"method\s*:\s*['\"](POST|PUT|DELETE|PATCH)['\"]")
        fetch_call = re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]")
        for name in self.EXEMPT_TEMPLATES:
            body = _template(name)
            for match in state_changing.finditer(body):
                # Find the nearest preceding fetch( call to identify the route.
                preceding = body.rfind("fetch(", 0, match.start())
                self.assertNotEqual(preceding, -1, f"{name}: found a state-changing fetch options object with no fetch() call")
                route_match = fetch_call.match(body, preceding)
                route = route_match.group(1) if route_match else None
                self.assertIn(route, unauthenticated_post_routes,
                              f"{name} calls {route!r} with a state-changing method but has no CSRF wrapper installed")


if __name__ == "__main__":
    unittest.main()

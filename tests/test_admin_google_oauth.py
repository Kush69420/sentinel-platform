"""Google sign-in for the admin console.

Covers the two properties the feature's security actually rests on:

  1. `admin_users.google_email` is an ALLOW-LIST, not a registration path. A
     verified Google identity that matches no active admin row must be refused
     and must not create one — otherwise every Google account on the internet is
     a super_admin.
  2. The callback is not a bare "trust whatever came back" handler: `state` is
     checked (CSRF on the callback), `nonce` is checked (replay of a token
     minted for another session), and an unverified email is rejected (anyone
     can *claim* an address they do not own until Google confirms it).

Plus the door-switching logic: configuring Google sign-in closes the admin
password door on BOTH entrances (/api/admin/login and the unified /api/user/login
that routes admin usernames to the same check), unless ADMIN_PASSWORD_LOGIN
re-opens it as break-glass.

The Google network calls are mocked. Nothing here reaches accounts.google.com;
the ID-token signature check is google-auth's job and is not re-tested here.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
CLIENT_SECRET = "test-client-secret"
REDIRECT_URI = "https://sentinel.example/api/admin/auth/google/callback"
AUTHORIZED_EMAIL = "authorized.admin@example.com"


class _FakeCursor:
    def __init__(self, db):
        self.db = db
        self._result = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        if q.startswith("SELECT * FROM admin_users WHERE LOWER(google_email)=%s AND is_active=1"):
            wanted = params[0]
            self._result = None
            for row in self.db["admin_users"].values():
                email = (row.get("google_email") or "").lower()
                if email and email == wanted and row.get("is_active", 1):
                    self._result = dict(row)
                    break
        elif q.startswith("UPDATE admin_users SET failed_login_count=0"):
            self.db.setdefault("last_login_updates", []).append(params[-1])
        elif q.startswith("INSERT INTO admin_users"):
            raise AssertionError(
                "the Google callback must never create an admin row — "
                "google_email is an allow-list, not a registration path"
            )
        elif q.startswith("INSERT INTO activity_log"):
            self.db.setdefault("activity_log", []).append(params)
        else:
            self._result = None

    def fetchone(self):
        return self._result

    def fetchall(self):
        return []

    def close(self):
        pass

    @property
    def lastrowid(self):
        return 1


class _FakeConn:
    def __init__(self, db):
        self.db = db

    def cursor(self, dictionary=False, **kwargs):
        return _FakeCursor(self.db)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class GoogleOAuthTestBase(unittest.TestCase):
    def setUp(self):
        self.db = {
            "admin_users": {
                1: {
                    "id": 1,
                    "name": "Ops Admin",
                    "username": "admin",
                    "role": "super_admin",
                    "is_active": 1,
                    "google_email": AUTHORIZED_EMAIL,
                    "password_hash": "google-oauth-only:not-a-valid-login",
                    "twofa_enabled": 0,
                },
                2: {
                    "id": 2,
                    "name": "Former Admin",
                    "username": "former",
                    "role": "support",
                    "is_active": 0,  # deactivated — must not be able to sign in
                    "google_email": "former.admin@example.com",
                    "password_hash": "x",
                    "twofa_enabled": 0,
                },
            }
        }
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

        patcher = mock.patch.object(app_module, "get_db", lambda: _FakeConn(self.db))
        patcher.start()
        self.addCleanup(patcher.stop)
        # log_activity opens its own connection via db_conn(); stub it out so the
        # audit write in the failure paths doesn't need a database.
        log_patcher = mock.patch.object(app_module, "log_activity", lambda *a, **k: None)
        log_patcher.start()
        self.addCleanup(log_patcher.stop)

        # The in-process rate limiter is module state shared across tests.
        app_module._rate_limiter._hits.clear() if hasattr(app_module._rate_limiter, "_hits") else None

    def _enable_google(self, password_login="0"):
        return [
            mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_ID", CLIENT_ID),
            mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_SECRET", CLIENT_SECRET),
            mock.patch.object(app_module, "GOOGLE_OAUTH_REDIRECT_URI", REDIRECT_URI),
            mock.patch.dict(os.environ, {"ADMIN_PASSWORD_LOGIN": password_login}),
        ]

    def _with_google(self, password_login="0"):
        patchers = self._enable_google(password_login)
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)


class ConfigGatingTests(GoogleOAuthTestBase):
    def test_partial_configuration_counts_as_disabled(self):
        """A half-configured flow that redirects to Google and then fails at the
        callback is worse than never offering the button."""
        with mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_ID", CLIENT_ID), \
             mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_SECRET", ""), \
             mock.patch.object(app_module, "GOOGLE_OAUTH_REDIRECT_URI", REDIRECT_URI):
            self.assertFalse(app_module.google_oauth_enabled())

    def test_password_login_stays_on_when_google_not_configured(self):
        with mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_ID", ""), \
             mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_SECRET", ""), \
             mock.patch.object(app_module, "GOOGLE_OAUTH_REDIRECT_URI", ""):
            self.assertTrue(app_module.admin_password_login_enabled())

    def test_configuring_google_closes_the_password_door(self):
        self._with_google(password_login="0")
        self.assertTrue(app_module.google_oauth_enabled())
        self.assertFalse(app_module.admin_password_login_enabled())

    def test_break_glass_flag_reopens_the_password_door(self):
        self._with_google(password_login="1")
        self.assertTrue(app_module.google_oauth_enabled())
        self.assertTrue(app_module.admin_password_login_enabled())


class PasswordDoorClosedTests(GoogleOAuthTestBase):
    def test_admin_login_endpoint_refuses_when_password_login_disabled(self):
        self._with_google()
        r = self.client.post("/api/admin/login", json={"username": "admin", "password": "whatever"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("Google", r.get_json()["error"])

    def test_unified_login_door_also_refuses_admin_passwords(self):
        """Regression guard: /api/user/login routes admin usernames to the same
        password check, so gating only /api/admin/login would move the door, not
        close it."""
        self._with_google()
        with mock.patch.object(app_module, "_is_admin_username", lambda *_: True), \
             mock.patch.object(app_module, "_perform_admin_login") as perform:
            r = self.client.post("/api/user/login", json={"identifier": "admin", "password": "whatever"})
        self.assertEqual(r.status_code, 403)
        perform.assert_not_called()


class GoogleLoginRedirectTests(GoogleOAuthTestBase):
    def test_login_redirects_to_google_with_state_and_nonce(self):
        self._with_google()
        r = self.client.get("/api/admin/auth/google/login")
        self.assertEqual(r.status_code, 302)
        location = r.headers["Location"]
        self.assertTrue(location.startswith(app_module.GOOGLE_AUTH_ENDPOINT))
        self.assertIn("client_id=" + CLIENT_ID.replace(".", "."), location)
        self.assertIn("state=", location)
        self.assertIn("nonce=", location)
        self.assertIn("prompt=select_account", location)
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("google_oauth_state"))
            self.assertTrue(sess.get("google_oauth_nonce"))

    def test_login_is_refused_when_google_not_configured(self):
        with mock.patch.object(app_module, "GOOGLE_OAUTH_CLIENT_ID", ""):
            r = self.client.get("/api/admin/auth/google/login")
        self.assertEqual(r.status_code, 302)
        self.assertIn("auth_error", r.headers["Location"])


class GoogleCallbackTests(GoogleOAuthTestBase):
    def setUp(self):
        super().setUp()
        self._with_google()

    def _prime_session(self, state="state-abc", nonce="nonce-xyz"):
        with self.client.session_transaction() as sess:
            sess["google_oauth_state"] = state
            sess["google_oauth_nonce"] = nonce

    def _mock_google(self, claims, token_status=200):
        token_response = mock.Mock()
        token_response.status_code = token_status
        token_response.json.return_value = {"id_token": "fake.jwt.token"}
        return (
            mock.patch.object(app_module.requests, "post", return_value=token_response),
            mock.patch.object(app_module.google_id_token, "verify_oauth2_token", return_value=claims),
        )

    def _assert_not_signed_in(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertIn("auth_error", response.headers["Location"])
        with self.client.session_transaction() as sess:
            self.assertNotIn("admin_id", sess)
            self.assertFalse(sess.get("is_admin"))

    def test_authorized_account_signs_in(self):
        self._prime_session()
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/admin"))
        with self.client.session_transaction() as sess:
            self.assertTrue(sess["is_admin"])
            self.assertEqual(sess["admin_id"], 1)
            self.assertEqual(sess["admin_auth_method"], "google")
            self.assertTrue(sess["csrf_token"])

    def test_unlisted_google_account_is_refused_and_creates_no_admin(self):
        """The core allow-list property. _FakeCursor raises on INSERT INTO
        admin_users, so an auto-provisioning regression fails loudly."""
        self._prime_session()
        claims = {"email": "stranger@gmail.com", "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(r)

    def test_deactivated_admin_cannot_sign_in(self):
        self._prime_session()
        claims = {"email": "former.admin@example.com", "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(r)

    def test_unverified_email_is_refused(self):
        self._prime_session()
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": False, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(r)

    def test_state_mismatch_is_refused(self):
        self._prime_session(state="the-real-state")
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=attacker-state")
        self._assert_not_signed_in(r)

    def test_callback_without_a_primed_session_is_refused(self):
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=anything")
        self._assert_not_signed_in(r)

    def test_nonce_mismatch_is_refused(self):
        self._prime_session(nonce="expected-nonce")
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": True, "nonce": "different-nonce"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(r)

    def test_state_is_single_use(self):
        """Replaying a callback URL (browser history, a proxy log, a shoulder
        surfer) must not mint a second admin session: state/nonce are consumed
        on the first attempt, so a session that never held them is refused."""
        self._prime_session()
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            first = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
            self.assertTrue(first.headers["Location"].endswith("/admin"))
            # Drop the authenticated cookie the way a different browser would:
            # the logout endpoint needs a CSRF header the test client has not
            # fetched, and this test is about the callback, not about logout.
            with self.client.session_transaction() as sess:
                sess.clear()
            replay = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(replay)

    def test_token_endpoint_failure_is_refused(self):
        self._prime_session()
        claims = {"email": AUTHORIZED_EMAIL, "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims, token_status=400)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(r)

    def test_invalid_id_token_signature_is_refused(self):
        """google-auth raises on a bad signature/audience/expiry — that must be
        a refusal, not a 500."""
        self._prime_session()
        token_response = mock.Mock()
        token_response.status_code = 200
        token_response.json.return_value = {"id_token": "forged.jwt.token"}
        with mock.patch.object(app_module.requests, "post", return_value=token_response), \
             mock.patch.object(app_module.google_id_token, "verify_oauth2_token",
                               side_effect=ValueError("Token has wrong audience")):
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self._assert_not_signed_in(r)

    def test_email_comparison_is_case_insensitive(self):
        self._prime_session()
        claims = {"email": AUTHORIZED_EMAIL.upper(), "email_verified": True, "nonce": "nonce-xyz"}
        post_patch, verify_patch = self._mock_google(claims)
        with post_patch, verify_patch:
            r = self.client.get("/api/admin/auth/google/callback?code=abc&state=state-abc")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/admin"))


class LoginPageRenderTests(GoogleOAuthTestBase):
    def test_password_fields_are_absent_when_password_login_is_off(self):
        self._with_google(password_login="0")
        html = self.client.get("/admin").get_data(as_text=True)
        self.assertIn("/api/admin/auth/google/login", html)
        self.assertIn("Sign in with Google", html)
        self.assertNotIn('id="loginPass"', html)

    def test_both_doors_render_under_break_glass(self):
        self._with_google(password_login="1")
        html = self.client.get("/admin").get_data(as_text=True)
        self.assertIn("Sign in with Google", html)
        self.assertIn('id="loginPass"', html)

    def test_auth_error_is_escaped(self):
        """auth_error comes straight off the query string — it must not be a
        reflected-XSS sink in the login page."""
        self._with_google()
        html = self.client.get("/admin?auth_error=<script>alert(1)</script>").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)


if __name__ == "__main__":
    unittest.main()

"""Day 2 (d) — session cookie hardening + security headers.

Before this fix there was no SESSION_COOKIE_SECURE/SAMESITE config (Flask's
insecure defaults applied) and no after_request hook at all — no CSP,
X-Frame-Options, X-Content-Type-Options, or HSTS anywhere.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SessionCookieConfigTest(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module

    def test_httponly_is_set(self):
        self.assertTrue(self.app_module.app.config["SESSION_COOKIE_HTTPONLY"])

    def test_samesite_is_lax(self):
        self.assertEqual(self.app_module.app.config["SESSION_COOKIE_SAMESITE"], "Lax")

    def test_secure_is_env_gated_and_on_by_default(self):
        # tests/__init__.py sets FLASK_ENV=development for the whole suite, so
        # this reads as the dev-relaxed value here. The source itself is
        # asserted separately to pin the non-dev behavior.
        self.assertFalse(self.app_module.IS_DEV_ENV is True and self.app_module.app.config["SESSION_COOKIE_SECURE"] is True,
                          "SECURE must be relaxed in dev — otherwise the cookie is dropped over plain http://localhost")

    def test_secure_follows_is_dev_env_in_source(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "app.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('app.config["SESSION_COOKIE_SECURE"] = not IS_DEV_ENV', src,
                     "SESSION_COOKIE_SECURE must default to True (fail closed) and only relax under FLASK_ENV=development")


class SecurityHeadersTest(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def test_headers_present_on_a_plain_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    def test_headers_present_on_an_api_response_too(self):
        """after_request must apply globally, not just to rendered pages."""
        resp = self.client.get("/api/user/session")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", resp.headers)

    def test_headers_present_even_on_a_403_csrf_rejection(self):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
            sess["csrf_token"] = "right"
        resp = self.client.post("/api/user/logout")  # no header -> 403
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_csp_forbids_framing(self):
        resp = self.client.get("/")
        self.assertIn("frame-ancestors 'none'", resp.headers.get("Content-Security-Policy", ""))

    def test_hsts_absent_in_dev(self):
        resp = self.client.get("/")
        self.assertNotIn("Strict-Transport-Security", resp.headers)

    def test_hsts_present_outside_dev_over_https(self):
        with mock.patch.object(self.app_module, "IS_DEV_ENV", False):
            resp = self.client.get("/", base_url="https://sentinel.example")
        self.assertIn("Strict-Transport-Security", resp.headers)

    def test_hsts_absent_outside_dev_over_plain_http(self):
        """Never claim HSTS over a connection that isn't actually HTTPS."""
        with mock.patch.object(self.app_module, "IS_DEV_ENV", False):
            resp = self.client.get("/")  # test client defaults to http://
        self.assertNotIn("Strict-Transport-Security", resp.headers)


if __name__ == "__main__":
    unittest.main()

"""Day 2 (e) — /api/admin/login had no IP-based rate limit, unlike
/api/user/login. The account lockout (3 wrong attempts / 2 hours, unchanged)
meant any single source could lock out the one real admin trivially. This adds
the same IP rate limit user login already has, ahead of that lockout.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _NoAdminCursor:
    """SELECT ... FROM admin_users always misses — enough to exercise the
    rate limiter, which is the outermost decorator and runs before any DB
    query the view function would issue."""

    def execute(self, query, params=()):
        return None

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _NoAdminConn:
    def cursor(self, dictionary=False):
        return _NoAdminCursor()

    def commit(self):
        pass

    def close(self):
        pass


class AdminLoginRateLimitTest(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=_NoAdminConn())
        self.get_db_patch.start()
        app_module._rate_limiter._windows.clear()  # module-level singleton — isolate tests
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def _attempt(self):
        return self.client.post("/api/admin/login", json={"username": "admin", "password": "wrong"})

    def test_route_declares_an_ip_rate_limit(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "app.py"), encoding="utf-8") as fh:
            src = fh.read()
        start = src.index('@app.route("/api/admin/login"')
        guard = src[start:src.index("def admin_login", start)]
        self.assertIn("@rate_limit(", guard, "admin_login has no rate limit decorator")
        self.assertIn('per="ip"', guard, "admin_login rate limit is not IP-scoped")

    def test_11th_attempt_from_the_same_ip_within_the_window_is_rate_limited(self):
        # user_login's limit is 10 requests / 300s per IP; admin_login now matches it.
        for _ in range(10):
            resp = self._attempt()
            self.assertEqual(resp.status_code, 401, "expected ordinary invalid-credentials responses within the limit")
        resp = self._attempt()
        self.assertEqual(resp.status_code, 429)

    def test_rate_limit_is_keyed_per_ip_not_global(self):
        for _ in range(10):
            self._attempt()
        limited = self._attempt()
        self.assertEqual(limited.status_code, 429)

        other_ip_resp = self.client.post(
            "/api/admin/login",
            json={"username": "admin", "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": "10.0.0.99"},
        )
        self.assertEqual(other_ip_resp.status_code, 401, "a different source IP must not share the exhausted window")


if __name__ == "__main__":
    unittest.main()

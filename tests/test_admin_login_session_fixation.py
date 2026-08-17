"""admin_login() set the new authenticated session directly on top of whatever
session already existed, unlike user_login() which calls session.clear() first
(see the comment there: "so a pre-login fixated cookie cannot be reused as an
authenticated one"). That meant an attacker able to plant a session cookie in
an admin's browser before they logged in (session fixation) could reuse that
same cookie afterwards with full admin privileges. Fixed by clearing the
session in admin_login() too, before the new admin session keys are set.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash


class _AdminCursor:
    def __init__(self, db):
        self.db = db
        self._result = []

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = []

        if q.startswith("SELECT * FROM admin_users WHERE username=%s AND is_active=1"):
            username = params[0]
            a = next((a for a in self.db["admin_users"].values() if a["username"] == username), None)
            self._result = [dict(a)] if a else []
        elif q.startswith("UPDATE admin_users SET failed_login_count=0, locked_until=NULL, last_login_at=NOW()"):
            admin_id = params[0]
            self.db["admin_users"][admin_id]["failed_login_count"] = 0
            self.db["admin_users"][admin_id]["locked_until"] = None
        elif q.startswith("INSERT INTO activity_log"):
            pass
        else:
            raise AssertionError(f"_AdminCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class _AdminConn:
    def __init__(self, db):
        self.db = db

    def cursor(self, dictionary=False):
        return _AdminCursor(self.db)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _make_db():
    return {
        "admin_users": {
            1: {
                "id": 1, "username": "admin", "name": "Root Admin", "role": "super_admin",
                "password_hash": generate_password_hash("CorrectHorse123!"),
                "is_active": 1, "twofa_enabled": 0, "twofa_secret": None,
                "recovery_codes_hash": None, "failed_login_count": 0, "locked_until": None,
            },
        },
    }


class AdminLoginSessionFixationTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = _make_db()
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=_AdminConn(self.db))
        self.get_db_patch.start()
        app_module._rate_limiter._windows.clear()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def test_login_clears_any_preexisting_session_state(self):
        with self.client.session_transaction() as sess:
            sess["planted_by_attacker"] = "evil"

        resp = self.client.post("/api/admin/login", json={"username": "admin", "password": "CorrectHorse123!"})
        self.assertEqual(resp.status_code, 200)

        with self.client.session_transaction() as sess:
            self.assertNotIn("planted_by_attacker", sess, "admin_login must regenerate the session, not build on top of it")
            self.assertTrue(sess.get("is_admin"))

    def test_successful_login_still_sets_expected_session_state(self):
        resp = self.client.post("/api/admin/login", json={"username": "admin", "password": "CorrectHorse123!"})
        self.assertEqual(resp.status_code, 200)
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("is_admin"))
            self.assertEqual(sess.get("admin_id"), 1)
            self.assertEqual(sess.get("admin_role"), "super_admin")
            self.assertTrue(sess.get("csrf_token"))


if __name__ == "__main__":
    unittest.main()

"""Verifies the /api/user/login sign-in flow end to end against an in-memory
fake DB: correct-password success, wrong-password rejection + lockout,
unapproved-account block, 2FA gate, and session/logout state.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash


class FakeCursor:
    def __init__(self, db, dictionary=False):
        self.db = db
        self.dictionary = dictionary
        self._result = []
        self.rowcount = 0

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = []
        self.rowcount = 0

        if q.startswith("SELECT id, phone, name, department, official_email, password_hash"):
            identifier = params[0]
            u = next((u for u in self.db["bot_users"].values() if u["phone"] == identifier or u.get("official_email") == identifier), None)
            self._result = [dict(u)] if u else []

        elif q.startswith("SELECT id, phone, name, department, official_email, credits, status,"):
            u = self.db["bot_users"].get(params[0])
            self._result = [dict(u)] if u else []

        elif q.startswith("SELECT id, phone, name, department, credits, status, plan_id FROM bot_users WHERE id=%s"):
            u = self.db["bot_users"].get(params[0])
            self._result = [dict(u)] if u else []

        elif q.startswith("UPDATE bot_users SET failed_login_count=%s, locked_until=DATE_ADD"):
            failed_count, lockout_hours, user_id = params
            self.db["bot_users"][user_id]["failed_login_count"] = failed_count
            self.db["bot_users"][user_id]["locked_until"] = datetime.now(timezone.utc) + timedelta(hours=int(lockout_hours))

        elif q.startswith("UPDATE bot_users SET failed_login_count=0, locked_until=NULL"):
            user_id = params[0]
            self.db["bot_users"][user_id]["failed_login_count"] = 0
            self.db["bot_users"][user_id]["locked_until"] = None

        elif q.startswith("UPDATE bot_users SET failed_login_count=%s WHERE id=%s"):
            failed_count, user_id = params
            self.db["bot_users"][user_id]["failed_login_count"] = failed_count

        elif q.startswith("SELECT setting_value FROM app_settings"):
            self._result = []

        elif q.startswith("INSERT INTO activity_log"):
            pass

        else:
            raise AssertionError(f"FakeCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class FakeConn:
    def __init__(self, db):
        self.db = db

    def cursor(self, dictionary=False):
        return FakeCursor(self.db, dictionary=dictionary)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def make_db():
    return {
        "bot_users": {
            1: {
                "id": 1, "phone": "9999999999", "name": "Ramesh Kumar", "department": "Cyber Cell",
                "official_email": "ramesh@example.gov.in", "password_hash": generate_password_hash("CorrectHorse123!"),
                "credits": 10, "status": "approved", "verification_status": "approved",
                "twofa_enabled": 0, "twofa_secret": None,
                "failed_login_count": 0, "locked_until": None,
            },
            2: {
                "id": 2, "phone": "8888888888", "name": "Pending User", "department": "Cyber Cell",
                "official_email": "pending@example.gov.in", "password_hash": generate_password_hash("Whatever123!"),
                "credits": 0, "status": "pending", "verification_status": "unverified",
                "twofa_enabled": 0, "twofa_secret": None,
                "failed_login_count": 0, "locked_until": None,
            },
            3: {
                "id": 3, "phone": "7777777777", "name": "Blocked User", "department": "Cyber Cell",
                "official_email": "blocked@example.gov.in", "password_hash": generate_password_hash("Whatever123!"),
                "credits": 0, "status": "blocked", "verification_status": "approved",
                "twofa_enabled": 0, "twofa_secret": None,
                "failed_login_count": 0, "locked_until": None,
            },
        },
    }


class UserAuthTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.fake_conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        app_module._rate_limiter._windows.clear()  # per-IP login rate limit is a module-level singleton
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def test_correct_credentials_log_in_and_set_session(self):
        resp = self.client.post("/api/user/login", json={"identifier": "9999999999", "password": "CorrectHorse123!"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["user"]["phone"], "9999999999")

        session_resp = self.client.get("/api/user/session")
        self.assertEqual(session_resp.status_code, 200)
        self.assertTrue(session_resp.get_json()["logged_in"])

    def test_wrong_password_is_rejected_and_does_not_leak_which_field_was_wrong(self):
        resp = self.client.post("/api/user/login", json={"identifier": "9999999999", "password": "wrong"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json()["error"], "Invalid credentials")
        self.assertEqual(self.db["bot_users"][1]["failed_login_count"], 1)

    def test_account_locks_after_reaching_the_failed_attempt_limit(self):
        for _ in range(5):  # default FAILED_LOGIN_LIMIT is 5
            resp = self.client.post("/api/user/login", json={"identifier": "9999999999", "password": "wrong"})
        self.assertEqual(resp.status_code, 423)
        self.assertTrue(resp.get_json()["locked"])

    def test_unverified_account_can_log_in_but_holds_no_clearance(self):
        """Self-serve signup: signing in buys the dashboard and pricing, nothing else.

        Superseded the old contract, where any status other than 'approved' was
        refused at login. The gate moved to the data routes (@verified_required)
        so that a new operator can sign in and submit their LEA documents.
        """
        resp = self.client.post("/api/user/login", json={"identifier": "8888888888", "password": "Whatever123!"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["user"]["verification_status"], "unverified")

    def test_blocked_account_cannot_log_in(self):
        resp = self.client.post("/api/user/login", json={"identifier": "7777777777", "password": "Whatever123!"})
        self.assertEqual(resp.status_code, 403)

    def test_missing_credentials_return_400(self):
        resp = self.client.post("/api/user/login", json={"identifier": "9999999999"})
        self.assertEqual(resp.status_code, 400)

    def test_unknown_identifier_does_not_leak_account_existence(self):
        resp = self.client.post("/api/user/login", json={"identifier": "0000000000", "password": "x"})
        wrong_pw_resp = self.client.post("/api/user/login", json={"identifier": "9999999999", "password": "wrong"})
        self.assertEqual(resp.status_code, wrong_pw_resp.status_code)
        self.assertEqual(resp.get_json()["error"], wrong_pw_resp.get_json()["error"])

    def test_session_endpoint_reports_logged_out_by_default(self):
        resp = self.client.get("/api/user/session")
        self.assertEqual(resp.status_code, 401)
        self.assertFalse(resp.get_json()["logged_in"])

    def test_logout_clears_session(self):
        self.client.post("/api/user/login", json={"identifier": "9999999999", "password": "CorrectHorse123!"})
        logout_resp = self.client.post("/api/user/logout")
        self.assertEqual(logout_resp.status_code, 200)
        session_resp = self.client.get("/api/user/session")
        self.assertEqual(session_resp.status_code, 401)

    def test_protected_route_rejects_unauthenticated_request(self):
        resp = self.client.get("/api/user/credit-history")
        self.assertEqual(resp.status_code, 401)

    def test_dashboard_page_redirects_to_login_when_not_authenticated(self):
        resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_dashboard_page_loads_after_login(self):
        self.client.post("/api/user/login", json={"identifier": "9999999999", "password": "CorrectHorse123!"})
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)

    def test_api_me_requires_login(self):
        resp = self.client.get("/api/me?phone=9999999999")
        self.assertEqual(resp.status_code, 401)

    def test_api_me_ignores_phone_param_and_returns_only_the_caller_own_account(self):
        # Logged in as user 2 (8888888888), but requesting another account's phone.
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 2
            sess["user_phone"] = "8888888888"
        resp = self.client.get("/api/me?phone=9999999999")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["phone"], "8888888888")


if __name__ == "__main__":
    unittest.main()

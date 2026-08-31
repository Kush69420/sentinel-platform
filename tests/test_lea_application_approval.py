"""REMEDIATION-PLAN.md §2.2 — real test_client() coverage for the LEA
verification queue's approve/reject endpoints.

tests/test_access_control.py never calls these routes at all — it only greps
app.py's source text. This file drives
/api/admin/lea/applications/<id>/{approve,reject} through a real Flask
test_client() against an in-memory fake DB and asserts:

  - an unauthenticated caller is rejected (401),
  - an authenticated caller who is *not* an admin is rejected (401) —
    admin_required only, since RBAC role-scoping is a separate, deferred item
    (Phase 1.2 — not touched here),
  - a genuine admin session actually flips lea_applications.status and the
    linked bot_users row (approved: status/verification_status/credits;
    rejected: verification_status + the account survives),
  - an application that isn't 'pending' any more can't be approved twice.
"""
import os
import sys
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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

        if q.startswith("SELECT * FROM lea_applications WHERE id=%s"):
            app_ = self.db["lea_applications"].get(params[0])
            self._result = [dict(app_)] if app_ else []

        elif q.startswith("SELECT id FROM bot_users WHERE id=%s"):
            u = self.db["bot_users"].get(params[0])
            self._result = [{"id": u["id"]}] if u else []

        elif q.startswith("SELECT id FROM bot_users WHERE phone=%s"):
            u = next((u for u in self.db["bot_users"].values() if u["phone"] == params[0]), None)
            self._result = [{"id": u["id"]}] if u else []

        elif q.startswith(
            "UPDATE bot_users SET status='approved', verification_status='approved', "
            "verified_at=NOW(), credits=credits+%s, department=%s, lea_application_id=%s WHERE id=%s"
        ):
            credits, department, app_id, user_id = params
            u = self.db["bot_users"][user_id]
            u["status"] = "approved"
            u["verification_status"] = "approved"
            u["credits"] += credits
            u["department"] = department
            u["lea_application_id"] = app_id
            self.rowcount = 1

        elif q.startswith("UPDATE lea_applications SET status='approved', reviewed_by=%s, reviewed_at=NOW() WHERE id=%s"):
            reviewed_by, app_id = params
            a = self.db["lea_applications"][app_id]
            a["status"] = "approved"
            a["reviewed_by"] = reviewed_by
            self.rowcount = 1

        elif q.startswith("INSERT INTO credit_transactions (phone, type, amount, reason) VALUES (%s,'credit',%s,'lea_approval_bonus')"):
            phone, amount = params
            self.db["credit_transactions"].append({"phone": phone, "amount": amount, "reason": "lea_approval_bonus"})

        elif q.startswith(
            "UPDATE lea_applications SET status='rejected', reviewed_by=%s, reviewed_at=NOW(), rejection_reason=%s WHERE id=%s"
        ):
            reviewed_by, reason, app_id = params
            a = self.db["lea_applications"][app_id]
            a["status"] = "rejected"
            a["reviewed_by"] = reviewed_by
            a["rejection_reason"] = reason
            self.rowcount = 1

        elif q.startswith("UPDATE bot_users SET verification_status='rejected', verification_note=%s WHERE id=%s"):
            reason, user_id = params
            u = self.db["bot_users"][user_id]
            u["verification_status"] = "rejected"
            u["verification_note"] = reason
            self.rowcount = 1

        elif q.startswith("UPDATE bot_users SET verification_status='rejected', verification_note=%s WHERE phone=%s"):
            reason, phone = params
            u = next((u for u in self.db["bot_users"].values() if u["phone"] == phone), None)
            u["verification_status"] = "rejected"
            u["verification_note"] = reason
            self.rowcount = 1

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
            9: {
                "id": 9, "phone": "9123456780", "credits": 0, "department": "",
                "status": "pending", "verification_status": "unverified",
            },
        },
        "lea_applications": {
            42: {
                "id": 42, "full_name": "Insp. Test Officer", "phone": "9123456780",
                "department": "Cyber Cell", "status": "pending", "user_id": 9,
                "created_at": datetime(2026, 3, 1, 10, 0, 0),
                "reviewed_by": None, "reviewed_at": None, "rejection_reason": None,
            },
        },
        "credit_transactions": [],
    }


class LeaApplicationApprovalTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=FakeConn(self.db))
        self.get_db_patch.start()
        self.log_patch = mock.patch.object(app_module, "log_activity")
        self.log_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.log_patch.stop()
        self.get_db_patch.stop()

    CSRF_TOKEN = "lea-test-csrf-token"
    CSRF_HEADERS = {"X-CSRF-Token": CSRF_TOKEN}

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["admin_name"] = "Root Admin"
            sess["admin_role"] = "super_admin"
            sess["csrf_token"] = self.CSRF_TOKEN

    def _login_user(self):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 9
            sess["user_phone"] = "9123456780"
            sess["csrf_token"] = self.CSRF_TOKEN

    # ── auth gating ──

    def test_approve_rejects_unauthenticated_request(self):
        resp = self.client.post("/api/admin/lea/applications/42/approve", json={})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["lea_applications"][42]["status"], "pending")

    def test_approve_rejects_an_authenticated_non_admin_user(self):
        self._login_user()
        resp = self.client.post("/api/admin/lea/applications/42/approve", json={}, headers=self.CSRF_HEADERS)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["lea_applications"][42]["status"], "pending")

    def test_reject_rejects_unauthenticated_request(self):
        resp = self.client.post("/api/admin/lea/applications/42/reject", json={"reason": "forged ID"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["lea_applications"][42]["status"], "pending")

    def test_reject_rejects_an_authenticated_non_admin_user(self):
        self._login_user()
        resp = self.client.post(
            "/api/admin/lea/applications/42/reject", json={"reason": "forged ID"}, headers=self.CSRF_HEADERS
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["lea_applications"][42]["status"], "pending")

    # ── approve: real state transition ──

    def test_admin_approve_transitions_application_and_grants_credits(self):
        self._login_admin()
        resp = self.client.post(
            "/api/admin/lea/applications/42/approve", json={"free_credits": 25}, headers=self.CSRF_HEADERS
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["phone"], "9123456780")

        self.assertEqual(self.db["lea_applications"][42]["status"], "approved")
        self.assertEqual(self.db["lea_applications"][42]["reviewed_by"], "Root Admin")

        user = self.db["bot_users"][9]
        self.assertEqual(user["status"], "approved")
        self.assertEqual(user["verification_status"], "approved")
        self.assertEqual(user["credits"], 25)
        self.assertEqual(user["department"], "Cyber Cell")

        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["credit_transactions"][0]["amount"], 25)

    def test_admin_approve_of_an_already_decided_application_is_rejected(self):
        self.db["lea_applications"][42]["status"] = "approved"
        self._login_admin()
        resp = self.client.post(
            "/api/admin/lea/applications/42/approve", json={"free_credits": 25}, headers=self.CSRF_HEADERS
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("already", resp.get_json()["error"])
        # No second credit grant on the double-approve attempt.
        self.assertEqual(self.db["bot_users"][9]["credits"], 0)

    def test_admin_approve_of_unknown_application_returns_404(self):
        self._login_admin()
        resp = self.client.post(
            "/api/admin/lea/applications/9999/approve", json={}, headers=self.CSRF_HEADERS
        )
        self.assertEqual(resp.status_code, 404)

    # ── reject: real state transition ──

    def test_admin_reject_transitions_application_and_user_verification_status(self):
        self._login_admin()
        resp = self.client.post(
            "/api/admin/lea/applications/42/reject",
            json={"reason": "ID proof illegible"},
            headers=self.CSRF_HEADERS,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["success"])

        app_row = self.db["lea_applications"][42]
        self.assertEqual(app_row["status"], "rejected")
        self.assertEqual(app_row["rejection_reason"], "ID proof illegible")

        user = self.db["bot_users"][9]
        self.assertEqual(user["verification_status"], "rejected")
        self.assertEqual(user["verification_note"], "ID proof illegible")
        # The account itself survives a rejection — only clearance is withheld.
        self.assertNotEqual(user["status"], "deleted")
        self.assertIn(9, self.db["bot_users"])


if __name__ == "__main__":
    unittest.main()

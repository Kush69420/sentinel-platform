"""QUERYING_PLAN.md §3.1 — credit deduction + audit logging for mobile_lookup.

Uses an in-memory fake DB layer (no live MySQL on this box) that understands just
enough of the SQL app.py issues against bot_users/services/subscriber_records/
credit_transactions/search_logs to exercise the real business logic, including the
atomic "don't overspend under a race" UPDATE ... WHERE credits >= %s guard.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeCursor:
    def __init__(self, db, dictionary=False):
        self.db = db
        self.dictionary = dictionary
        self._result = []
        self.rowcount = 0
        self.lastrowid = None

    def execute(self, query, params=()):
        q = " ".join(query.split())  # normalize whitespace
        self._result = []
        self.rowcount = 0

        if q.startswith("SELECT * FROM services WHERE code=%s"):
            svc = self.db["services"].get(params[0])
            self._result = [dict(svc)] if svc else []

        elif q.startswith("SELECT id, phone, name, department, official_email, credits, status,"):
            # load_current_user(): authorization state is read live, never from session.
            u = self.db["bot_users"].get(params[0])
            self._result = [dict(u)] if u else []

        elif q.startswith("SELECT credits FROM bot_users WHERE id=%s"):
            u = self.db["bot_users"].get(params[0])
            self._result = [{"credits": u["credits"]}] if u else []

        elif q.startswith("UPDATE bot_users SET credits = credits - %s WHERE id=%s AND credits >= %s"):
            amount, user_id, required = params
            u = self.db["bot_users"].get(user_id)
            if u and u["credits"] >= required:
                u["credits"] -= amount
                self.rowcount = 1
            else:
                self.rowcount = 0

        elif q.startswith("INSERT INTO credit_transactions"):
            phone, amount, reason = params
            self.db["credit_transactions"].append(
                {"id": len(self.db["credit_transactions"]) + 1, "phone": phone, "type": "debit", "amount": amount, "reason": reason, "status": "success", "created_at": None}
            )

        elif q.startswith("INSERT INTO search_logs"):
            user_id, phone, search_type, query_value, case_reference, credits_used, source = params
            self.db["search_logs"].append(
                {"user_id": user_id, "phone": phone, "search_type": search_type, "query_value": query_value,
                 "case_reference": case_reference, "credits_used": credits_used, "sources_queried": source}
            )
            self.lastrowid = len(self.db["search_logs"])

        elif q.startswith("SELECT * FROM subscriber_records WHERE mobile_number=%s"):
            row = self.db["subscriber_records"].get(params[0])
            self._result = [dict(row)] if row else []

        elif q.startswith("SELECT * FROM master_data_records"):
            self._result = []

        elif q.startswith("SELECT id, type, amount, reason, status, created_at FROM credit_transactions WHERE phone=%s"):
            phone = params[0]
            rows = [t for t in self.db["credit_transactions"] if t["phone"] == phone]
            self._result = list(reversed(rows))

        elif q.startswith("SELECT * FROM integrations WHERE is_enabled=1"):
            self._result = []  # no integrations configured in these tests

        else:
            raise AssertionError(f"FakeCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class FakeConn:
    def __init__(self, db):
        self.db = db
        self.committed = False
        self.rolled_back = False

    def cursor(self, dictionary=False):
        return FakeCursor(self.db, dictionary=dictionary)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


def make_db():
    return {
        "bot_users": {
            1: {"id": 1, "phone": "9999999999", "name": "Officer One", "department": "Cyber",
                "official_email": "one@police.gov.in", "credits": 5, "status": "approved",
                "verification_status": "approved", "twofa_enabled": 0},
            2: {"id": 2, "phone": "8888888888", "name": "Officer Two", "department": "Cyber",
                "official_email": "two@police.gov.in", "credits": 1, "status": "approved",
                "verification_status": "approved", "twofa_enabled": 0},
        },
        "services": {
            "mobile_lookup": {"code": "mobile_lookup", "credits_per_use": 2, "is_free": 0, "is_enabled": 1, "maintenance_mode": 0, "status": "active"},
        },
        "subscriber_records": {
            "9876543210": {"mobile_number": "9876543210", "subscriber_name": "Ramesh Kumar"},
        },
        "credit_transactions": [],
        "search_logs": [],
    }


class MobileLookupCreditTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.fake_conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def _login(self, user_id=1, phone="9999999999"):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = user_id
            sess["user_phone"] = phone

    def test_successful_lookup_deducts_credit_and_logs_audit_row(self):
        self._login(user_id=1, phone="9999999999")
        resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9876543210", "case_reference": "FIR-2026-1182"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["credits_charged"], 2)
        self.assertEqual(body["search_log_id"], 1)
        self.assertEqual(self.db["bot_users"][1]["credits"], 3)  # 5 - 2
        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["credit_transactions"][0]["amount"], 2)
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["case_reference"], "FIR-2026-1182")
        self.assertEqual(log["credits_used"], 2)
        self.assertEqual(log["query_value"], "9876543210")

    def test_insufficient_credits_blocks_before_running_query(self):
        self._login(user_id=2, phone="8888888888")  # only 1 credit, needs 2
        resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9876543210"})
        self.assertEqual(resp.status_code, 402)
        self.assertEqual(self.db["bot_users"][2]["credits"], 1)  # untouched
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(self.db["search_logs"], [])

    def test_no_match_is_logged_but_not_charged(self):
        self._login(user_id=1, phone="9999999999")
        resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "0000000000"})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.db["bot_users"][1]["credits"], 5)  # untouched
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(len(self.db["search_logs"]), 1)
        self.assertEqual(self.db["search_logs"][0]["credits_used"], 0)
        self.assertEqual(self.db["search_logs"][0]["sources_queried"], "No match")

    def test_race_lost_between_check_and_deduct_returns_402_and_does_not_overspend(self):
        self._login(user_id=1, phone="9999999999")
        real_execute = FakeCursor.execute

        def draining_execute(cursor_self, query, params=()):
            q = " ".join(query.split())
            # Drain after the pre-flight balance read but before the atomic debit,
            # which is exactly the window the `WHERE credits >= %s` guard exists to
            # cover. The subscriber lookup is the query that sits in that window.
            if q.startswith("SELECT * FROM subscriber_records WHERE mobile_number=%s"):
                self.db["bot_users"][1]["credits"] = 0  # a concurrent request drains it first
            return real_execute(cursor_self, query, params)

        with mock.patch.object(FakeCursor, "execute", draining_execute):
            resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9876543210"})
        self.assertEqual(resp.status_code, 402)
        self.assertEqual(self.db["bot_users"][1]["credits"], 0)
        self.assertEqual(self.db["credit_transactions"], [])

    def test_credit_history_endpoint_requires_login(self):
        resp = self.client.get("/api/user/credit-history")
        self.assertEqual(resp.status_code, 401)

    def test_credit_history_endpoint_returns_only_own_transactions(self):
        self.db["credit_transactions"] = [
            {"id": 1, "phone": "9999999999", "type": "debit", "amount": 2, "reason": "service:mobile_lookup", "status": "success", "created_at": None},
            {"id": 2, "phone": "8888888888", "type": "debit", "amount": 5, "reason": "service:other", "status": "success", "created_at": None},
        ]
        self._login(user_id=1, phone="9999999999")
        resp = self.client.get("/api/user/credit-history")
        self.assertEqual(resp.status_code, 200)
        txns = resp.get_json()["transactions"]
        self.assertEqual(len(txns), 1)
        self.assertEqual(txns[0]["reason"], "service:mobile_lookup")


if __name__ == "__main__":
    unittest.main()

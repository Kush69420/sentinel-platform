"""log_service_usage_internal() (CDR/IPDR post-hoc billing) must use the same
atomic UPDATE ... WHERE credits >= %s guard as run_tool_generic(), so two
concurrent requests can't both pass a stale balance check and drive a user's
credits negative.
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

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = []
        self.rowcount = 0

        if q.startswith("SELECT * FROM services WHERE code=%s"):
            svc = self.db["services"].get(params[0])
            self._result = [dict(svc)] if svc else []

        elif q.startswith("SELECT * FROM bot_users WHERE phone=%s"):
            u = next((u for u in self.db["bot_users"].values() if u["phone"] == params[0]), None)
            self._result = [dict(u)] if u else []

        elif q.startswith("UPDATE bot_users SET credits = credits - %s WHERE id = %s AND credits >= %s"):
            amount, user_id, required = params
            u = self.db["bot_users"].get(user_id)
            if u and u["credits"] >= required:
                u["credits"] -= amount
                self.rowcount = 1
            else:
                self.rowcount = 0

        elif q.startswith("INSERT INTO credit_transactions"):
            phone, amount, reason = params
            self.db["credit_transactions"].append({"phone": phone, "amount": amount, "reason": reason})

        elif q.startswith("INSERT INTO service_usage_log"):
            user_id, service_id, case_reference, input_summary, credits_charged = params
            self.db["service_usage_log"].append(
                {"user_id": user_id, "service_id": service_id, "case_reference": case_reference,
                 "input_summary": input_summary, "credits_charged": credits_charged}
            )

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
        "bot_users": {1: {"id": 1, "phone": "9999999999", "credits": 5}},
        "services": {
            "cdr_processor": {"id": 10, "code": "cdr_processor", "credits_per_use": 3, "is_free": 0},
        },
        "credit_transactions": [],
        "service_usage_log": [],
    }


class ServiceUsageRaceTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=FakeConn(self.db))
        self.get_db_patch.start()

    def tearDown(self):
        self.get_db_patch.stop()

    def test_normal_usage_deducts_credit_and_logs(self):
        self.app_module.log_service_usage_internal("9999999999", "cdr_processor", "FIR-1", "CDR file: 10 rows analyzed")
        self.assertEqual(self.db["bot_users"][1]["credits"], 2)  # 5 - 3
        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["service_usage_log"][0]["credits_charged"], 3)

    def test_lost_race_does_not_overspend_or_record_a_debit(self):
        real_execute = FakeCursor.execute

        def draining_execute(cursor_self, query, params=()):
            q = " ".join(query.split())
            if q.startswith("SELECT * FROM bot_users WHERE phone=%s"):
                self.db["bot_users"][1]["credits"] = 0  # a concurrent request drains it first
            return real_execute(cursor_self, query, params)

        with mock.patch.object(FakeCursor, "execute", draining_execute):
            self.app_module.log_service_usage_internal("9999999999", "cdr_processor", "FIR-1", "CDR file: 10 rows analyzed")

        self.assertEqual(self.db["bot_users"][1]["credits"], 0)  # untouched by the lost race
        self.assertEqual(self.db["credit_transactions"], [])  # no debit recorded
        self.assertEqual(self.db["service_usage_log"][0]["credits_charged"], 0)  # audit row still written


if __name__ == "__main__":
    unittest.main()

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

        elif q.startswith("SELECT * FROM subscriber_records WHERE mobile_number IN ("):
            # mobile_lookup normalises the query and probes every stored format
            # variant of the same number, so match on any of the candidates.
            row = next((self.db["subscriber_records"][k] for k in params
                        if k in self.db["subscriber_records"]), None)
            self._result = [dict(row)] if row else []

        elif q.startswith("SELECT * FROM master_data_records"):
            self._result = []

        elif q.startswith("SELECT id, type, amount, reason, status, created_at FROM credit_transactions WHERE phone=%s"):
            phone = params[0]
            rows = [t for t in self.db["credit_transactions"] if t["phone"] == phone]
            self._result = list(reversed(rows))

        elif q.startswith("SELECT * FROM integrations WHERE is_enabled=1 AND (name=%s OR category=%s)"):
            # api_dependency-scoped lookup: match by integration name OR category.
            name_or_cat = params[0]
            matches = [i for i in self.db.get("integrations", [])
                       if i.get("is_enabled") and (i.get("name") == name_or_cat or i.get("category") == name_or_cat)]
            self._result = [dict(matches[0])] if matches else []

        elif q.startswith("SELECT * FROM integrations WHERE is_enabled=1 AND category=%s"):
            # category-only lookup (no api_dependency configured on the service).
            cat = params[0]
            matches = [i for i in self.db.get("integrations", [])
                       if i.get("is_enabled") and i.get("category") == cat]
            self._result = [dict(matches[0])] if matches else []

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
        "integrations": [],  # no integrations configured by default
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

    CSRF_TOKEN = "test-csrf-token"
    CSRF_HEADERS = {"X-CSRF-Token": CSRF_TOKEN}

    def _login(self, user_id=1, phone="9999999999"):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = user_id
            sess["user_phone"] = phone
            # CSRF enforcement (Day 2) checks a session-stored token against the
            # X-CSRF-Token header on every state-changing request once a session
            # is authenticated. This helper bypasses the real login flow (which
            # is what mints that token), so it must set one directly.
            sess["csrf_token"] = self.CSRF_TOKEN

    def test_successful_lookup_deducts_credit_and_logs_audit_row(self):
        # Case (d): a subscriber_records hit (the pre-existing, unmodified path)
        # still charges exactly once — regression guard for the fallthrough fix.
        self._login(user_id=1, phone="9999999999")
        resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9876543210", "case_reference": "FIR-2026-1182"}, headers=self.CSRF_HEADERS)
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
        resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9876543210"}, headers=self.CSRF_HEADERS)
        self.assertEqual(resp.status_code, 402)
        self.assertEqual(self.db["bot_users"][2]["credits"], 1)  # untouched
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(self.db["search_logs"], [])

    def test_no_match_is_logged_but_not_charged(self):
        # Case (b): local miss + no integration configured at all. Behavior must
        # be byte-for-byte unchanged from before the fallthrough fix.
        self._login(user_id=1, phone="9999999999")
        resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9999999999"}, headers=self.CSRF_HEADERS)
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.db["bot_users"][1]["credits"], 5)  # untouched
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(len(self.db["search_logs"]), 1)
        self.assertEqual(self.db["search_logs"][0]["credits_used"], 0)
        self.assertEqual(self.db["search_logs"][0]["sources_queried"], "No match")

    def _add_enabled_twilio_integration(self):
        # Matches on category ("phone", via TOOL_CATEGORY_MAP["mobile_lookup"])
        # since the test services row has no api_dependency set.
        self.db["integrations"].append({
            "id": 1, "name": "Twilio Lookup Service", "category": "phone",
            "is_enabled": 1, "base_url": "", "api_key": "test-key", "api_secret": "test-secret",
        })

    def test_local_miss_with_working_integration_charges_once_with_real_source(self):
        # Case (a): local miss on both subscriber_records and master_data_records,
        # but an enabled Twilio integration is configured and returns real data.
        # This is exactly the fallthrough this bug fix closes: the fake DB used by
        # the rest of this file hardcodes the integrations query to `[]`, so without
        # `_add_enabled_twilio_integration()` this path is never exercised and the
        # bug is invisible to the test suite.
        self._add_enabled_twilio_integration()
        self._login(user_id=1, phone="9999999999")
        fake_twilio_response = {"phone_number": "+910000000000", "carrier": {"name": "Test Telecom"}}
        with mock.patch.object(self.app_module, "_http_json", return_value=fake_twilio_response) as mocked_http:
            resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9999999999", "case_reference": "FIR-2026-9001"}, headers=self.CSRF_HEADERS)
            self.assertEqual(mocked_http.call_count, 1)

        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["credits_charged"], 2)
        self.assertEqual(body["credits_remaining"], 3)  # 5 - 2
        # No search_log_id: an API-sourced hit has no subscriber_records row, and
        # mobile_lookup_report_pdf reads only subscriber_records — offering a PDF
        # download here would 404. See app.py comment at the same spot.
        self.assertNotIn("search_log_id", body)

        # Charged exactly once.
        self.assertEqual(self.db["bot_users"][1]["credits"], 3)
        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["credit_transactions"][0]["amount"], 2)

        # The audit row must be truthful: real source, real credits_used, not "No match".
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["credits_used"], 2)
        self.assertEqual(log["sources_queried"], "Twilio Lookup Service")
        self.assertEqual(log["case_reference"], "FIR-2026-9001")

    def test_local_miss_with_failing_integration_is_uncharged_and_distinguishable(self):
        # Case (c): an integration is configured but the outbound call fails. This
        # must NOT be recorded the same way as a true "no data anywhere" miss.
        self._add_enabled_twilio_integration()
        self._login(user_id=1, phone="9999999999")
        with mock.patch.object(self.app_module, "_http_json", side_effect=Exception("provider timeout")):
            resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9999999999"}, headers=self.CSRF_HEADERS)

        # Same HTTP status as today's true-miss case — don't break the frontend.
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.db["bot_users"][1]["credits"], 5)  # untouched, not charged
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["credits_used"], 0)
        self.assertEqual(log["sources_queried"], "Lookup failed")
        self.assertNotEqual(log["sources_queried"], "No match")

    def test_race_lost_between_check_and_deduct_returns_402_and_does_not_overspend(self):
        self._login(user_id=1, phone="9999999999")
        real_execute = FakeCursor.execute

        def draining_execute(cursor_self, query, params=()):
            q = " ".join(query.split())
            # Drain after the pre-flight balance read but before the atomic debit,
            # which is exactly the window the `WHERE credits >= %s` guard exists to
            # cover. The subscriber lookup is the query that sits in that window.
            if q.startswith("SELECT * FROM subscriber_records WHERE mobile_number IN ("):
                self.db["bot_users"][1]["credits"] = 0  # a concurrent request drains it first
            return real_execute(cursor_self, query, params)

        with mock.patch.object(FakeCursor, "execute", draining_execute):
            resp = self.client.post("/api/tools/run", json={"code": "mobile_lookup", "query": "9876543210"}, headers=self.CSRF_HEADERS)
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


class MobileNumberNormalizationTests(MobileLookupCreditTests):
    """A format mismatch between what the officer types and what was imported
    must not read as "not in the database", and a typo must not read as a miss.

    Both used to return the same 404, which is the part that matters: the tool
    produces evidence, and an investigator has to be able to tell "this number
    has no subscriber record" from "I mistyped it". These tests pin the two
    apart and pin the canonical form that lands in the audit ledger."""

    def test_prefixed_and_spaced_forms_find_the_same_record(self):
        for typed in ("+91 98765 43210", "+919876543210", "09876543210",
                      "91-9876-543-210", "98765 43210"):
            with self.subTest(typed=typed):
                self.setUp()
                self._login(user_id=1, phone="9999999999")
                resp = self.client.post(
                    "/api/tools/run",
                    json={"code": "mobile_lookup", "query": typed},
                    headers=self.CSRF_HEADERS)
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(resp.get_json()["success"])

    def test_audit_row_records_the_canonical_form_not_what_was_typed(self):
        # The ledger has to hold one stable representation of the number, or
        # "every search for 9876543210" misses the ones typed as +91....
        self._login(user_id=1, phone="9999999999")
        resp = self.client.post(
            "/api/tools/run",
            json={"code": "mobile_lookup", "query": "+91 98765 43210",
                  "case_reference": "FIR-2026-2001"},
            headers=self.CSRF_HEADERS)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["query"], "9876543210")
        self.assertEqual(self.db["search_logs"][0]["query_value"], "9876543210")

    def test_malformed_number_is_400_not_404_and_costs_nothing(self):
        # An empty query is deliberately absent from this list: it is caught
        # earlier by the generic "query required" guard, which is also a 400 but
        # carries no reason code.
        for typed in ("1234567890", "98765", "abcdefghij",
                      "+1 202 555 0143", "98765432100"):
            with self.subTest(typed=typed):
                self.setUp()
                self._login(user_id=1, phone="9999999999")
                resp = self.client.post(
                    "/api/tools/run",
                    json={"code": "mobile_lookup", "query": typed},
                    headers=self.CSRF_HEADERS)
                # 400 with its own reason code — distinguishable by the client
                # from the 404 a genuinely absent number returns.
                self.assertIn(resp.status_code, (400,))
                self.assertEqual(resp.get_json().get("reason"), "invalid_query")
                # Nothing searched means nothing billed and nothing logged.
                self.assertEqual(self.db["bot_users"][1]["credits"], 5)
                self.assertEqual(self.db["credit_transactions"], [])
                self.assertEqual(self.db["search_logs"], [])

    def test_wellformed_absent_number_is_still_404(self):
        # The other half of the pair: valid shape, simply not on file.
        self._login(user_id=1, phone="9999999999")
        resp = self.client.post(
            "/api/tools/run",
            json={"code": "mobile_lookup", "query": "9999999999"},
            headers=self.CSRF_HEADERS)
        self.assertEqual(resp.status_code, 404)
        self.assertNotEqual(resp.get_json().get("reason"), "invalid_query")


if __name__ == "__main__":
    unittest.main()

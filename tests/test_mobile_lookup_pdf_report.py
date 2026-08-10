"""QUERYING_PLAN.md §3.2 — PDF report for an already-paid-for mobile_lookup search.

GET /api/tools/run/report/pdf/<search_log_id> re-formats an existing search_logs row
(no new credit charge, no new audit row). Covers the IDOR guard (scoped to the caller's
own user_id, same pattern as /api/me and /api/user/credit-history), rejection of
non-match rows, and the happy path.
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

        if q.startswith("SELECT * FROM search_logs WHERE id=%s AND user_id=%s"):
            log_id, user_id = params
            row = self.db["search_logs"].get(log_id)
            self._result = [dict(row)] if row and row["user_id"] == user_id else []

        elif q.startswith("SELECT * FROM subscriber_records WHERE mobile_number=%s"):
            row = self.db["subscriber_records"].get(params[0])
            self._result = [dict(row)] if row else []

        elif q.startswith("SELECT * FROM master_data_records"):
            self._result = []

        elif q.startswith("SELECT setting_value FROM app_settings WHERE setting_key=%s"):
            val = self.db["app_settings"].get(params[0])
            self._result = [{"setting_value": val}] if val is not None else []

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
        "search_logs": {
            1: {
                "id": 1, "user_id": 1, "phone": "9999999999", "search_type": "mobile",
                "query_value": "9876543210", "case_reference": "FIR-2026-1182",
                "credits_used": 2, "sources_queried": "Subscriber Database",
                "created_at": datetime(2026, 8, 10, 12, 0, 0),
            },
            2: {
                "id": 2, "user_id": 1, "phone": "9999999999", "search_type": "mobile",
                "query_value": "0000000000", "case_reference": None,
                "credits_used": 0, "sources_queried": "No match",
                "created_at": datetime(2026, 8, 10, 12, 5, 0),
            },
        },
        "subscriber_records": {
            "9876543210": {
                "mobile_number": "9876543210", "subscriber_name": "Ramesh Kumar",
                "father_name": "Suresh Kumar", "address": "12 MG Road", "district": "Pune",
                "state": "Maharashtra", "operator": "Airtel", "sim_type": "Prepaid",
                "activation_date": None, "status": "Active", "alternate_number": None,
                "email": None, "id_type": "Aadhaar", "id_number": "XXXX-XXXX-1234",
            },
        },
        "app_settings": {"app_name": "SENTINEL", "login_notice": "Restricted access only."},
    }


class MobileLookupPdfReportTests(unittest.TestCase):
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

    def _login(self, user_id=1):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = user_id
            sess["user_name"] = "Operator One"
            sess["user_department"] = "Cyber Cell"

    def test_requires_login(self):
        resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 401)

    def test_foreign_search_log_returns_404(self):
        self._login(user_id=2)  # log 1 belongs to user 1
        resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 404)

    def test_missing_search_log_returns_404(self):
        self._login(user_id=1)
        resp = self.client.get("/api/tools/run/report/pdf/999")
        self.assertEqual(resp.status_code, 404)

    def test_no_match_row_is_rejected(self):
        self._login(user_id=1)
        resp = self.client.get("/api/tools/run/report/pdf/2")
        self.assertEqual(resp.status_code, 400)

    def test_happy_path_returns_pdf_attachment(self):
        self._login(user_id=1)
        resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/pdf")
        self.assertIn("attachment; filename=sentinel_mobile_lookup_1.pdf", resp.headers["Content-Disposition"])
        self.assertTrue(resp.data.startswith(b"%PDF"))

    def test_missing_underlying_record_returns_404(self):
        del self.db["subscriber_records"]["9876543210"]
        self._login(user_id=1)
        resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()

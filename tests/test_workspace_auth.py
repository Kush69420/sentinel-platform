"""Security-debt Critical #3 — CDR/IPDR workspace routes had no auth check at all.

/api/analysis/workspace/<batch_id> (analysis_workspace_v2) and /workspace/<batch_id>
(workspace_page) are now @admin_required, matching every other import-batch route
(admin_data_upload, import_execute_v2, import_batches_v2). import_batches has no
per-user ownership column (imported_by is just an admin-name string) and every route
that creates or lists batches is already admin-only, so admin_required is the correct
scope here, not user_required.
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

    def execute(self, query, params=()):
        q = " ".join(query.split())

        if q.startswith("SELECT * FROM import_batches WHERE id=%s"):
            row = self.db["import_batches"].get(params[0])
            self._result = [dict(row)] if row else []

        elif q.startswith("SELECT * FROM cdr_records WHERE import_batch_id=%s"):
            self._result = [dict(r) for r in self.db["cdr_records"] if r["import_batch_id"] == params[0]]

        elif q.startswith("SELECT * FROM ipdr_records WHERE import_batch_id=%s"):
            self._result = [dict(r) for r in self.db["ipdr_records"] if r["import_batch_id"] == params[0]]

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

    def close(self):
        pass


def make_db():
    return {
        "import_batches": {
            1: {
                "id": 1, "source_type": "cdr", "original_filename": "cdr.csv",
                "total_rows": 1, "imported_by": "admin", "status": "imported",
                "created_at": datetime(2026, 8, 10, 12, 0, 0), "rolled_back_at": None,
            },
        },
        "cdr_records": [
            {
                "id": 1, "import_batch_id": 1, "calling_number": "9999999999",
                "called_number": "8888888888", "duration": "60", "imei": "123456789012345",
                "tower_address": None, "lac": "1", "cell_id": "1", "date_time": "2026-08-10T12:00:00",
            },
        ],
        "ipdr_records": [],
    }


class WorkspaceAuthTests(unittest.TestCase):
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

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_name"] = "admin"
            sess["admin_role"] = "super_admin"

    def test_api_workspace_requires_admin(self):
        resp = self.client.get("/api/analysis/workspace/1")
        self.assertEqual(resp.status_code, 401)

    def test_workspace_page_requires_admin(self):
        resp = self.client.get("/workspace/1")
        self.assertEqual(resp.status_code, 401)

    def test_api_workspace_allows_admin(self):
        self._login_admin()
        resp = self.client.get("/api/analysis/workspace/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["type"], "cdr")

    def test_workspace_page_allows_admin(self):
        self._login_admin()
        resp = self.client.get("/workspace/1")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()

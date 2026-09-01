"""Import rollback — /api/admin/data/rollback/<batch_id>.

Two view functions used to bind this same url rule: `rollback_import` (registered
first, so the one Flask dispatched) and `rollback_batch_v2` (dead code). The
reachable one deleted only from the legacy `master_data_records` table, while the
live wizard (`import_execute_v2`) writes to subscriber/vehicle/bts/cdr/ipdr
`_records` — and its `except mysql.connector.Error` fallback ran
`DELETE ... WHERE id=0`, guaranteeing a clean-looking `deleted: 0`. The admin UI
toasted "Rollback complete" while nothing relevant was removed.

Seams under test:
  - the url rule is bound exactly *once* (the regression that let this happen),
  - every per-module table is actually deleted from, `subscriber_records` above all,
  - the `import_batches` row is UPDATEd to 'rolled_back', never DELETEd
    (`loadImportBatches()` in templates/admin.html renders a 'rolled_back' badge,
    which a deleted row could never show),
  - `deleted` stays a plain integer total (`rollbackBatch()` does
    'Rollback complete: '+d.deleted+' rows deleted'),
  - a table absent from this deployment (errno 1146) is skipped, but
  - any other DB error is *not* swallowed: 500 + conn.rollback().
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mysql.connector

ROLLBACK_RULE = "/api/admin/data/rollback/<int:batch_id>"

# Tables the handler must clear, in addition to the legacy master_data_records.
MODULE_TABLES = ("cdr_records", "ipdr_records", "subscriber_records", "vehicle_records", "bts_tower_records")


class FakeCursor:
    """Records every statement; row counts and failures are driven by the conn."""

    def __init__(self, conn):
        self.conn = conn
        self.rowcount = 0

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self.conn.statements.append((q, params))
        for table, exc in self.conn.failures.items():
            if f"FROM {table} " in q or f"UPDATE {table} " in q:
                self.rowcount = 0
                raise exc
        if q.startswith("DELETE FROM "):
            table = q.split()[2]
            self.rowcount = self.conn.rows.get(table, 0)
        elif q.startswith("UPDATE import_batches"):
            self.rowcount = 1
        else:
            self.rowcount = 0

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class FakeConn:
    def __init__(self, rows=None, failures=None):
        self.rows = rows or {}
        self.failures = failures or {}
        self.statements = []
        self.committed = 0
        self.rolled_back = 0
        self.closed = 0

    def cursor(self, dictionary=False):
        return FakeCursor(self)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


def db_error(errno):
    exc = mysql.connector.Error(msg=f"simulated error {errno}", errno=errno)
    exc.errno = errno
    return exc


class ImportRollbackTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        # log_audit() opens its own connection; keep it out of the assertions.
        self.audit_patch = mock.patch.object(app_module, "log_audit")
        self.audit_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.audit_patch.stop()

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_name"] = "admin"
            sess["admin_role"] = "super_admin"
            sess["csrf_token"] = "rollback-test-token"

    def _post(self, conn, batch_id=7):
        self._login_admin()
        with mock.patch.object(self.app_module, "get_db", return_value=conn):
            return self.client.post(f"/api/admin/data/rollback/{batch_id}", headers={"X-CSRF-Token": "rollback-test-token"})

    def test_rollback_rule_is_bound_exactly_once(self):
        """Two handlers on one rule is what hid the bug; only one may own it."""
        endpoints = [r.endpoint for r in self.app_module.app.url_map.iter_rules() if r.rule == ROLLBACK_RULE]
        self.assertEqual(endpoints, ["rollback_import"])
        self.assertFalse(hasattr(self.app_module, "rollback_batch_v2"), "dead duplicate handler is still defined")

    def test_deletes_from_every_import_table_including_subscriber_records(self):
        conn = FakeConn(rows={"subscriber_records": 3})
        resp = self._post(conn)
        self.assertEqual(resp.status_code, 200)
        deletes = {q.split()[2] for q, _ in conn.statements if q.startswith("DELETE FROM ")}
        for table in MODULE_TABLES + ("master_data_records",):
            self.assertIn(table, deletes)
        self.assertIn(("DELETE FROM subscriber_records WHERE import_batch_id=%s", (7,)), conn.statements)

    def test_batch_row_is_marked_rolled_back_not_deleted(self):
        conn = FakeConn()
        resp = self._post(conn)
        self.assertEqual(resp.status_code, 200)
        updates = [q for q, _ in conn.statements if q.startswith("UPDATE import_batches")]
        self.assertEqual(len(updates), 1)
        self.assertIn("status='rolled_back'", updates[0])
        self.assertIn("rolled_back_at=NOW()", updates[0])
        self.assertNotIn("import_batches", {q.split()[2] for q, _ in conn.statements if q.startswith("DELETE FROM ")})

    def test_deleted_is_an_integer_total_of_affected_rows(self):
        conn = FakeConn(rows={"cdr_records": 10, "subscriber_records": 4, "master_data_records": 1})
        resp = self._post(conn)
        body = resp.get_json()
        self.assertIsInstance(body["deleted"], int)
        self.assertEqual(body["deleted"], 15)
        self.assertEqual(body["by_table"]["subscriber_records"], 4)
        self.assertEqual(conn.committed, 1)
        self.assertEqual(conn.closed, 1)

    def test_missing_table_is_skipped_without_failing_the_rollback(self):
        """errno 1146 just means this deployment never created that table."""
        conn = FakeConn(rows={"subscriber_records": 2}, failures={"master_data_records": db_error(1146)})
        resp = self._post(conn)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["deleted"], 2)
        self.assertNotIn("master_data_records", body["by_table"])
        self.assertEqual(conn.committed, 1)

    def test_genuine_db_error_is_not_swallowed(self):
        """A blanket `except: pass` is exactly what hid the original bug."""
        conn = FakeConn(rows={"cdr_records": 5}, failures={"subscriber_records": db_error(1213)})
        resp = self._post(conn)
        self.assertEqual(resp.status_code, 500)
        self.assertIn("error", resp.get_json())
        self.assertEqual(conn.rolled_back, 1)
        self.assertEqual(conn.committed, 0)
        self.assertEqual(conn.closed, 1)

    def test_endpoint_requires_admin_auth(self):
        resp = self.client.post("/api/admin/data/rollback/7")
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()

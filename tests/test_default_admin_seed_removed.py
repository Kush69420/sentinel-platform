"""Phase-1 deploy-blocker #1 — the hardcoded default admin credential.

db_setup.sql used to unconditionally seed a super_admin row (username=admin,
password=admin123, hashed with a static salt that has been sitting in git
history since the initial commit) on every fresh install, with nothing
enforcing rotation. This asserts:

  1. The seed INSERT is gone from db_setup.sql — a fresh database gets no
     admin at all, rather than one with a credential anyone who cloned the
     repo can compute.
  2. migration_remove_default_admin.sql exists, is idempotent by construction
     (its WHERE clause matches the exact old hash, which its own SET clause
     overwrites — so a second run matches zero rows), disables rather than
     deletes the row (avoiding admin_users(id) FK fallout), and is wired into
     deploy/db-init/00-apply-schema.sh in the run list.
  3. tools/bootstrap_admin.py — the replacement for the seed — creates or
     rotates an admin_users row correctly, reuses the platform's existing
     password_problem() policy rather than inventing a new one, refuses to
     clobber an existing username without --force, and audit-logs what it did.

No live database is available in this environment, so (1) and (2) are source
inspection rather than exercising a real idempotent re-run; (3) mocks the DB
the same way the rest of this suite does (see tests/test_workspace_auth.py).
"""
import importlib
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OLD_SEEDED_HASH = (
    "pbkdf2:sha256:600000$sentinelsalt1234$"
    "759d3c0805511946c952611fa5ce9b5f7b6b339fc60d70a80ee32657a174546a"
)


def _read(relpath):
    with open(os.path.join(BASE, relpath), encoding="utf-8") as fh:
        return fh.read()


class DbSetupSeedRemovedTests(unittest.TestCase):
    def test_db_setup_sql_no_longer_inserts_the_seeded_admin(self):
        sql = _read("db_setup.sql")
        self.assertNotIn(
            OLD_SEEDED_HASH, sql,
            "the old static-salt admin123 hash must not appear in db_setup.sql at all",
        )
        self.assertNotRegex(
            sql, r"INSERT INTO admin_users",
            "db_setup.sql must not seed any admin_users row",
        )

    def test_db_setup_sql_points_operators_at_the_bootstrap_script(self):
        sql = _read("db_setup.sql")
        self.assertIn("tools.bootstrap_admin", sql)
        self.assertIn("migration_remove_default_admin.sql", sql)


class NeutralizationMigrationTests(unittest.TestCase):
    def setUp(self):
        self.sql = _read("migration_remove_default_admin.sql")

    def test_migration_file_exists_and_targets_admin_users(self):
        self.assertIn("UPDATE admin_users", self.sql)

    def test_disables_rather_than_deletes(self):
        self.assertNotRegex(
            self.sql, r"DELETE\s+FROM\s+admin_users",
            "must neutralize the row, not delete it (FK fallout on activity_log)",
        )
        self.assertIn("is_active = 0", self.sql)

    def test_where_clause_matches_only_the_exact_old_seeded_row(self):
        self.assertIn("WHERE username = 'admin'", self.sql)
        self.assertIn(OLD_SEEDED_HASH, self.sql)

    def test_is_self_idempotent_by_construction(self):
        # The UPDATE's WHERE clause must key on the OLD hash, and its SET
        # clause must overwrite password_hash to something that is NOT that
        # old hash — that's what makes a second run match zero rows.
        match = re.search(
            r"SET\s+is_active\s*=\s*0,\s*password_hash\s*=\s*'([^']*)'", self.sql,
        )
        self.assertIsNotNone(match, "expected a SET is_active=0, password_hash='...' clause")
        new_hash_literal = match.group(1)
        self.assertNotEqual(
            new_hash_literal, OLD_SEEDED_HASH,
            "SET password_hash must differ from the WHERE clause's target hash, "
            "or re-running this migration would keep matching and stay a no-op forever "
            "in a way that looks idempotent but never actually converges",
        )

    def test_wired_into_apply_schema_script_in_run_list(self):
        script = _read("deploy/db-init/00-apply-schema.sh")
        self.assertIn("run migration_remove_default_admin.sql", script)
        # Must come after the canonical schema files it depends on (admin_users
        # is created in db_setup.sql).
        db_setup_pos = script.index("run db_setup.sql")
        this_pos = script.index("run migration_remove_default_admin.sql")
        self.assertLess(db_setup_pos, this_pos)

    def test_documented_in_claude_md_deploy_checklist(self):
        claude_md = _read("CLAUDE.md")
        self.assertIn("migration_remove_default_admin.sql", claude_md)
        self.assertIn("tools.bootstrap_admin", claude_md)


class _FakeCursor:
    def __init__(self, db):
        self.db = db
        self._result = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        if q.startswith("SELECT id FROM admin_users WHERE username=%s"):
            row = self.db["admins"].get(params[0])
            self._result = dict(row) if row else None
        elif q.startswith("UPDATE admin_users SET name=%s, password_hash=%s, role=%s, is_active=1"):
            name, password_hash, role, admin_id = params
            self.db["admins_by_id"][admin_id].update(
                name=name, password_hash=password_hash, role=role,
                is_active=1, failed_login_count=0, locked_until=None,
            )
        elif q.startswith("INSERT INTO admin_users"):
            name, username, password_hash, role = params
            new_id = max(self.db["admins_by_id"]) + 1 if self.db["admins_by_id"] else 1
            row = {
                "id": new_id, "name": name, "username": username,
                "password_hash": password_hash, "role": role, "is_active": 1,
            }
            self.db["admins"][username] = row
            self.db["admins_by_id"][new_id] = row
            self.lastrowid = new_id
        else:
            raise AssertionError(f"FakeCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result


class _FakeConn:
    def __init__(self, db):
        self.db = db

    def cursor(self, dictionary=False):
        return _FakeCursor(self.db)

    def commit(self):
        pass

    def close(self):
        pass


def _make_db():
    existing = {
        "id": 1, "name": "Super Admin", "username": "admin",
        "password_hash": "disabled-by-migration_remove_default_admin:not-a-valid-login",
        "role": "super_admin", "is_active": 0,
    }
    return {"admins": {"admin": existing}, "admins_by_id": {1: existing}}


class BootstrapAdminScriptTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.tools_bootstrap_admin = importlib.import_module("tools.bootstrap_admin")
        self.log_patch = mock.patch.object(app_module, "log_activity")
        self.mock_log_activity = self.log_patch.start()

    def tearDown(self):
        self.log_patch.stop()

    def _run(self, argv, db=None):
        db = db if db is not None else {"admins": {}, "admins_by_id": {}}
        with mock.patch.object(self.app_module, "get_db", return_value=_FakeConn(db)):
            rc = self.tools_bootstrap_admin.main(argv)
        return rc, db

    def test_creates_a_new_admin_with_a_generated_password(self):
        rc, db = self._run(["--username", "newadmin", "--name", "New Admin"])
        self.assertEqual(rc, 0)
        row = db["admins"]["newadmin"]
        self.assertEqual(row["role"], "super_admin")
        self.assertEqual(row["is_active"], 1)
        self.mock_log_activity.assert_called_once()
        args, kwargs = self.mock_log_activity.call_args
        self.assertEqual(args[1], "admin_bootstrapped")

    def test_generated_password_satisfies_the_platforms_existing_password_policy(self):
        captured = {}
        real_hash = self.app_module.generate_password_hash

        def _capture(pw):
            captured["password"] = pw
            return real_hash(pw)

        with mock.patch.object(self.app_module, "generate_password_hash", side_effect=_capture):
            self._run(["--username", "newadmin"])
        self.assertIsNone(self.app_module.password_problem(captured["password"]))

    def test_refuses_to_touch_an_existing_username_without_force(self):
        rc, db = self._run(["--username", "admin"], db=_make_db())
        self.assertEqual(rc, 1)
        # Untouched — still the disabled/neutralized state.
        self.assertEqual(db["admins"]["admin"]["is_active"], 0)
        self.mock_log_activity.assert_not_called()

    def test_force_rotates_and_reactivates_an_existing_row(self):
        rc, db = self._run(
            ["--username", "admin", "--password", "a-strong-passphrase-1", "--force"],
            db=_make_db(),
        )
        self.assertEqual(rc, 0)
        row = db["admins"]["admin"]
        self.assertEqual(row["is_active"], 1)
        self.assertTrue(self.app_module.check_password_hash(row["password_hash"], "a-strong-passphrase-1"))
        self.mock_log_activity.assert_called_once()
        args, kwargs = self.mock_log_activity.call_args
        self.assertEqual(args[1], "admin_bootstrap_rotated")

    def test_rejects_a_weak_explicit_password_via_the_shared_policy(self):
        with self.assertRaises(SystemExit):
            self._run(["--username", "newadmin", "--password", "short"])


if __name__ == "__main__":
    unittest.main()

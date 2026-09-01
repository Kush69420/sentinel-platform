"""Issue 4 — user-side audit entries were silently discarded.

`activity_log.admin_id` carries a foreign key to `admin_users(id)`
(`db_setup.sql`). Twelve call sites passed a `bot_users.id` into it: signup,
login, failed login, account lockout, recovery-code use, logout, password reset
requested/completed, password change, LEA verification submitted, payment order
created, and payment captured.

MySQL rejects every one of those with error 1452, and `log_activity()` wraps its
insert in `try/except`, so the failure was printed to stdout and swallowed. The
platform therefore had **no user audit trail whatsoever** — not a partial one, an
empty one. Nothing in the app surfaced that, which is why it survived.

The fix routes non-admin actors through the FK-free `actor_type`/`actor_id`
columns (already present via `migration_admin_customization.sql`; see
`migration_activity_log_actor.sql`) and leaves `admin_id` NULL for them.

Seams under test:
  - `log_activity()` never writes a non-admin id into the FK-constrained
    `admin_id` column — proven against a fake cursor that enforces the FK the
    way MySQL does.
  - The admin path is unchanged and still populates `admin_id`.
  - The legacy-schema fallback (no actor columns) still refuses to put a user id
    in `admin_id`, rather than "recovering" into the original bug.
  - A source-level sweep: no call site hands a `bot_users` id to the default
    admin actor_type. This is the regression that would silently come back.
"""
import ast
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mysql.connector

import app as app_module

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The ids that exist in admin_users for the fake below. Anything else passed as
# admin_id is what MySQL would reject with 1452.
KNOWN_ADMIN_IDS = {1, 7}


class _FkEnforcingCursor:
    """Records activity_log inserts and rejects FK violations like MySQL does."""

    def __init__(self, recorder, has_actor_columns=True):
        self.recorder = recorder
        self.has_actor_columns = has_actor_columns
        self.rowcount = 0

    def execute(self, query, params=()):
        q = " ".join(query.split())
        if not q.startswith("INSERT INTO activity_log"):
            return None
        columns = q.split("(", 1)[1].split(")", 1)[0]
        cols = [c.strip() for c in columns.split(",")]
        row = dict(zip(cols, params))

        if not self.has_actor_columns and ("actor_type" in cols or "ip_address" in cols):
            err = mysql.connector.Error("Unknown column 'actor_type' in 'field list'")
            err.errno = 1054
            raise err

        admin_id = row.get("admin_id")
        if admin_id is not None and admin_id not in KNOWN_ADMIN_IDS:
            err = mysql.connector.Error(
                "Cannot add or update a child row: a foreign key constraint fails"
            )
            err.errno = 1452
            raise err

        self.recorder.append(row)

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _FkEnforcingConn:
    def __init__(self, recorder, has_actor_columns=True):
        self.recorder = recorder
        self.has_actor_columns = has_actor_columns

    def cursor(self, dictionary=False):
        return _FkEnforcingCursor(self.recorder, self.has_actor_columns)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class LogActivityActorTests(unittest.TestCase):
    def setUp(self):
        self.rows = []
        self.patch = mock.patch.object(
            app_module, "get_db", return_value=_FkEnforcingConn(self.rows)
        )
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_user_actor_is_recorded_at_all(self):
        """The regression. Before the fix this produced zero rows."""
        with app_module.app.test_request_context("/"):
            app_module.log_activity(2, "user_login", "user 2 logged in", actor_type="user")
        self.assertEqual(len(self.rows), 1, "user-side activity was silently discarded")

    def test_user_actor_does_not_go_into_the_fk_column(self):
        with app_module.app.test_request_context("/"):
            app_module.log_activity(2, "user_login", "user 2 logged in", actor_type="user")
        self.assertIsNone(self.rows[0]["admin_id"])

    def test_user_actor_identity_is_preserved(self):
        """Not writing admin_id must not mean losing who did it."""
        with app_module.app.test_request_context("/"):
            app_module.log_activity(2, "user_login", "user 2 logged in", actor_type="user")
        self.assertEqual(self.rows[0]["actor_type"], "user")
        self.assertEqual(self.rows[0]["actor_id"], 2)

    def test_admin_actor_still_populates_admin_id(self):
        """The admin half worked and must keep working."""
        with app_module.app.test_request_context("/"):
            app_module.log_activity(1, "admin_login", "admin 1 logged in")
        self.assertEqual(self.rows[0]["admin_id"], 1)
        self.assertEqual(self.rows[0]["actor_type"], "admin")
        self.assertEqual(self.rows[0]["actor_id"], 1)

    def test_actorless_events_are_recorded(self):
        """Failed logins for an unknown identifier pass None — still auditable."""
        with app_module.app.test_request_context("/"):
            app_module.log_activity(None, "failed_login", "unknown identifier")
        self.assertEqual(len(self.rows), 1)
        self.assertIsNone(self.rows[0]["admin_id"])

    def test_ip_is_captured_from_the_request(self):
        with app_module.app.test_request_context("/", environ_base={"REMOTE_ADDR": "203.0.113.9"}):
            app_module.log_activity(2, "user_login", "x", actor_type="user")
        self.assertEqual(self.rows[0]["ip_address"], "203.0.113.9")

    def test_works_outside_a_request_context(self):
        app_module.log_activity(1, "startup", "no request here")
        self.assertEqual(len(self.rows), 1)
        self.assertIsNone(self.rows[0]["ip_address"])


class LegacySchemaFallbackTests(unittest.TestCase):
    """A database that predates the actor columns must degrade, not regress."""

    def setUp(self):
        self.rows = []
        self.patch = mock.patch.object(
            app_module,
            "get_db",
            return_value=_FkEnforcingConn(self.rows, has_actor_columns=False),
        )
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_user_actor_falls_back_without_reintroducing_the_fk_violation(self):
        with app_module.app.test_request_context("/"):
            app_module.log_activity(2, "user_login", "user 2 logged in", actor_type="user")
        self.assertEqual(len(self.rows), 1, "fallback lost the log line entirely")
        self.assertIsNone(
            self.rows[0]["admin_id"],
            "fallback put a bot_users id back into the admin_users FK column",
        )

    def test_admin_actor_falls_back_with_its_id_intact(self):
        with app_module.app.test_request_context("/"):
            app_module.log_activity(1, "admin_login", "admin 1 logged in")
        self.assertEqual(self.rows[0]["admin_id"], 1)


class CallSiteSweepTest(unittest.TestCase):
    """Every call site handing over a bot_users id must say so.

    Checked against the source rather than by exercising twelve routes: the
    failure mode is a *silent* one, so an end-to-end test of each route would
    pass just as happily with the bug present. What actually needs pinning is
    the argument at the call site.
    """

    # Substrings that identify a bot_users id in the first argument.
    USER_ID_MARKERS = ("user[", "user_id", "account[", "order[", 'row["id"]', "row['id']")
    # ...except these, which are admin identities that merely contain "user".
    ADMIN_MARKERS = ("admin_id", "admin[", "admin_user")

    @staticmethod
    def _log_activity_calls():
        with open(os.path.join(BASE, "app.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == "log_activity" and node.args:
                actor_type = next(
                    (kw.value.value for kw in node.keywords
                     if kw.arg == "actor_type" and isinstance(kw.value, ast.Constant)),
                    "admin",
                )
                yield node.lineno, ast.unparse(node.args[0]), actor_type

    def test_no_user_id_is_logged_as_an_admin_actor(self):
        offenders = []
        for lineno, first_arg, actor_type in self._log_activity_calls():
            if any(m in first_arg for m in self.ADMIN_MARKERS):
                continue
            if any(m in first_arg for m in self.USER_ID_MARKERS) and actor_type != "user":
                offenders.append(f"app.py:{lineno} log_activity({first_arg}, ...) -> actor_type={actor_type!r}")
        self.assertEqual(
            offenders, [],
            "these pass a bot_users id but log it as an admin actor, so MySQL "
            "rejects the insert with 1452 and the entry is silently lost:\n  "
            + "\n  ".join(offenders),
        )

    def test_the_sweep_actually_finds_the_known_user_call_sites(self):
        """Guards the guard: if the AST walk silently matched nothing, the test
        above would pass vacuously."""
        user_calls = [
            (lineno, arg) for lineno, arg, actor_type in self._log_activity_calls()
            if actor_type == "user"
        ]
        self.assertGreaterEqual(
            len(user_calls), 12,
            f"expected at least 12 user-side log_activity calls, found {len(user_calls)}",
        )


if __name__ == "__main__":
    unittest.main()

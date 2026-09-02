"""Phase-1 deploy-blocker #2 — argument injection + missing allow-list on the
admin CLI-execution endpoint (/api/admin/tools/<id>/cli-test).

Before this fix, admin_cli_test_v2() did
`template.replace('{query}', query)` on the raw command-template STRING
before shlex.split()-ing the result. An admin-supplied query containing
spaces/quotes/flags was therefore re-parsed by shlex into extra argv
elements — argument injection into whatever binary the admin-controlled
service row (external_command, settable via POST /api/admin/services) named.
Not shell injection (subprocess.run is never given shell=True), but full
control over argv[1:] regardless of what the query field was "supposed" to
be.

The fix has two independent parts, tested separately:
  1. _build_cli_argv() — shlex-splits the TEMPLATE first, substitutes
     {query} into each already-split token afterwards, so query content can
     never be re-parsed into extra argv elements. Handles {query} embedded
     in a larger token (e.g. "--target={query}") and malformed templates
     (unbalanced quotes) without crashing the request.
  2. _resolve_cli_binary() / CLI_TOOL_ALLOWED_BINARIES — even with (1) fixed,
     an admin can still point external_command at any binary. Only a binary
     on this env-configured allow-list (resolved to an absolute, symlink-
     free real path on both sides) may actually execute; the default is
     empty, i.e. deny everything.

This is not RBAC — @admin_required is unchanged and is the only auth
decorator; the allow-list is a property of the deployment, not the caller's
role, per CLAUDE.md's explicit scope note against touching RBAC.
"""
import json
import os
import shlex
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BuildCliArgvTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module

    def test_basic_substitution(self):
        argv = self.app_module._build_cli_argv("whois {query}", "example.com")
        self.assertEqual(argv, ["whois", "example.com"])

    def test_query_with_spaces_stays_one_argv_element(self):
        # This is the actual vulnerability: a query containing spaces/flags
        # must never turn into additional argv elements.
        argv = self.app_module._build_cli_argv("whois {query}", "example.com --evil-flag extra")
        self.assertEqual(argv, ["whois", "example.com --evil-flag extra"])
        self.assertEqual(len(argv), 2)

    def test_query_with_shell_metacharacters_and_quotes_stays_one_element(self):
        nasty = "x'; rm -rf /; echo \"$(whoami)\" `id`"
        argv = self.app_module._build_cli_argv("whois {query}", nasty)
        self.assertEqual(argv, ["whois", nasty])

    def test_query_embedded_in_a_larger_token(self):
        argv = self.app_module._build_cli_argv("curl --target={query} -m 5", "1.2.3.4 --extra")
        self.assertEqual(argv, ["curl", "--target=1.2.3.4 --extra", "-m", "5"])

    def test_template_with_multiple_query_placeholders(self):
        argv = self.app_module._build_cli_argv("tool -a {query} -b {query}", "v")
        self.assertEqual(argv, ["tool", "-a", "v", "-b", "v"])

    def test_malformed_template_raises_value_error_not_crash(self):
        with self.assertRaises(ValueError):
            self.app_module._build_cli_argv("whois 'unbalanced", "q")

    def test_empty_template_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.app_module._build_cli_argv("", "q")
        with self.assertRaises(ValueError):
            self.app_module._build_cli_argv("   ", "q")


class ResolveCliBinaryTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module

    def test_empty_allow_list_denies_everything(self):
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset()):
            self.assertIsNone(self.app_module._resolve_cli_binary("/bin/echo"))
            self.assertIsNone(self.app_module._resolve_cli_binary("echo"))

    def test_bare_name_resolved_via_path_and_matched(self):
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({"echo"})):
            resolved = self.app_module._resolve_cli_binary("echo")
        self.assertIsNotNone(resolved)
        self.assertTrue(os.path.isabs(resolved))
        self.assertTrue(os.path.isfile(resolved))

    def test_binary_not_on_allow_list_is_denied(self):
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({"whois"})):
            self.assertIsNone(self.app_module._resolve_cli_binary("echo"))

    def test_symlink_resolves_to_the_same_real_path_as_its_target(self):
        # /bin/echo and /usr/bin/echo are the same file on this system (one a
        # symlink to the other on modern Debian/Ubuntu, or both to usr-merge).
        # Allow-listing one must match a request for the other, and a bogus
        # unresolvable entry alongside it must not break the comparison.
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({"/bin/echo", "/no/such/binary"})):
            resolved = self.app_module._resolve_cli_binary("/usr/bin/echo")
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved, os.path.realpath("/usr/bin/echo"))

    def test_nonexistent_binary_is_denied(self):
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({"/no/such/binary"})):
            self.assertIsNone(self.app_module._resolve_cli_binary("/no/such/binary"))


class _FakeCursor:
    def __init__(self, db):
        self.db = db
        self._result = None
        self.lastrowid = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        if q.startswith("SELECT * FROM services WHERE id=%s"):
            row = self.db["services"].get(params[0])
            self._result = dict(row) if row else None
        elif q.startswith("INSERT INTO external_tool_jobs (service_id,user_id,command,status,started_at,finished_at,stderr)"):
            service_id, user_id, command, stderr = params
            jid = len(self.db["jobs"]) + 1
            self.db["jobs"][jid] = {
                "id": jid, "service_id": service_id, "user_id": user_id, "command": command,
                "status": "failed", "stderr": stderr,
            }
            self.lastrowid = jid
        elif q.startswith("INSERT INTO external_tool_jobs (service_id,user_id,command,status,started_at)"):
            service_id, user_id, command = params
            jid = len(self.db["jobs"]) + 1
            self.db["jobs"][jid] = {
                "id": jid, "service_id": service_id, "user_id": user_id, "command": command,
                "status": "running",
            }
            self.lastrowid = jid
        elif q.startswith("UPDATE external_tool_jobs SET status=%s,exit_code=%s"):
            status, exit_code, stdout, stderr, rt, jid = params
            self.db["jobs"][jid].update(status=status, exit_code=exit_code, stdout=stdout, stderr=stderr, runtime_ms=rt)
        elif q.startswith("UPDATE external_tool_jobs SET status='failed',stderr=%s"):
            stderr, jid = params
            self.db["jobs"][jid].update(status="failed", stderr=stderr)
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


CSRF_TOKEN = "cli-test-csrf-token"


class CliTestEndpointTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = {
            "services": {
                7: {
                    "id": 7, "name": "Echo Tool", "allow_cli_execution": 1,
                    # sys.executable is shlex.quote()d because the sandbox's own
                    # path can contain a space (e.g. ".../WD Black/Sentinel/..."),
                    # which would otherwise itself get split into two argv
                    # elements by _build_cli_argv()'s shlex.split(template) --
                    # a quirk of this test environment, not of the code under
                    # test (a real deployment's binary path won't have a space).
                    "external_command": f"{shlex.quote(sys.executable)} -c 'import sys,json;print(json.dumps(sys.argv[1:]))' {{query}}",
                    "timeout_seconds": 10,
                },
            },
            "jobs": {},
        }
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=_FakeConn(self.db))
        self.get_db_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["admin_name"] = "Root Admin"
            sess["admin_role"] = "super_admin"
            sess["csrf_token"] = CSRF_TOKEN

    def _post(self, service_id, query):
        return self.client.post(
            f"/api/admin/tools/{service_id}/cli-test",
            json={"query": query},
            headers={"X-CSRF-Token": CSRF_TOKEN},
        )

    def test_requires_admin(self):
        resp = self.client.post("/api/admin/tools/7/cli-test", json={"query": "x"})
        self.assertEqual(resp.status_code, 401)

    def test_default_empty_allow_list_denies_and_logs_a_failed_job(self):
        self._login_admin()
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset()):
            resp = self._post(7, "hello")
        self.assertEqual(resp.status_code, 403)
        body = resp.get_json()
        self.assertIn("not permitted", body["error"])
        self.assertIn("job_id", body)
        job = self.db["jobs"][body["job_id"]]
        self.assertEqual(job["status"], "failed")
        self.assertIn("not permitted", job["stderr"])

    def test_allowed_binary_runs_and_query_is_a_single_argv_element(self):
        self._login_admin()
        nasty_query = 'hello world --evil-flag "with quotes" $(id)'
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({sys.executable})):
            resp = self._post(7, nasty_query)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        received_argv = json.loads(body["stdout"])
        # The whole nasty query must arrive as exactly ONE argv element —
        # proof it was never re-split into extra arguments.
        self.assertEqual(received_argv, [nasty_query])
        job = self.db["jobs"][body["job_id"]]
        self.assertEqual(job["status"], "success")

    def test_binary_not_on_allow_list_is_rejected(self):
        self._login_admin()
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({"/usr/bin/whois"})):
            resp = self._post(7, "hello")
        self.assertEqual(resp.status_code, 403)
        job = self.db["jobs"][resp.get_json()["job_id"]]
        self.assertEqual(job["status"], "failed")

    def test_malformed_command_template_is_rejected_with_a_traceable_job(self):
        self._login_admin()
        self.db["services"][7]["external_command"] = "whois 'unbalanced {query}"
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({"whois"})):
            resp = self._post(7, "hello")
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("job_id", body)
        job = self.db["jobs"][body["job_id"]]
        self.assertEqual(job["status"], "failed")

    def test_cli_execution_disabled_flag_still_enforced(self):
        self._login_admin()
        self.db["services"][7]["allow_cli_execution"] = 0
        with mock.patch.object(self.app_module, "CLI_TOOL_ALLOWED_BINARIES", frozenset({sys.executable})):
            resp = self._post(7, "hello")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json()["error"], "CLI execution disabled for this tool")


if __name__ == "__main__":
    unittest.main()

"""Login response time must not depend on whether the identifier exists.

Before this fix, user_login()/_perform_admin_login() took two different-cost
paths to the same {"error": "Invalid credentials"} / 401:

  - identifier not found in bot_users/admin_users: returned immediately, no
    check_password_hash() call at all.
  - identifier found, wrong password: ran check_password_hash() first — a
    deliberately expensive, CPU-hard verification (whatever algorithm this
    checkout's werkzeug picks for generate_password_hash()/check_password_hash();
    measured directly against this install at ~95ms per call, comfortably
    network-measurable — see the comment on _DUMMY_PASSWORD_HASH in app.py).

The two responses were already byte-identical (a prior fix), but the timing
gap alone still let an attacker distinguish "no such account" from "wrong
password" by clock, defeating the point of matching the bodies — an LEA
platform enumerating which officers have accounts is itself sensitive.

The fix: the "not found" branch in both functions now also calls
check_password_hash(), against a module-level dummy hash
(app._DUMMY_PASSWORD_HASH) generated once at import. This file proves that
*structurally* — by asserting call counts on a wrapped check_password_hash,
never by measuring wall-clock time (timing assertions are inherently flaky)
and never by matching against app.py's source text.

It also re-affirms the property that must NOT regress: the known-device-
cookie lockout mitigation (tests/test_login_lockout_dos.py) short-circuits a
locked account with no valid device cookie BEFORE calling check_password_hash
at all, specifically so an attacker without that cookie gains no extra
guesses. Closing the existence-timing leak must not quietly reopen that gap by
making the locked-no-cookie path start hashing too — so this file asserts it
still does not.

Reuses the exact fixture (FakeCursor/FakeConn/make_db/_LockoutTestBase) built
for the lockout-DoS tests rather than duplicating it — see tests/test_csrf.py
for the same reuse-across-test-files pattern in this repo. That module is not
modified here.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash

from tests.test_login_lockout_dos import _LockoutTestBase


class UserLoginTimingTests(_LockoutTestBase):
    """/api/user/login — the unauthenticated-enumeration path."""

    FAILED_LOGIN_LIMIT = "5"
    LIMIT = 5

    def _post(self, identifier, password, client=None, ip="203.0.113.50"):
        return (client or self.client).post(
            "/api/user/login",
            json={"identifier": identifier, "password": password},
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def test_unknown_identifier_runs_check_password_hash_exactly_like_a_known_one(self):
        """The two branches sharing the identical {"error": "Invalid
        credentials"}/401 response — "no such account" and "found, wrong
        password" — must now both call check_password_hash() exactly once.
        Wrapping the real function (not replacing it) also proves the dummy
        path performs a genuine verification, not a no-op stand-in."""
        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp = self._post("0000000000", "whatever-guess", ip="203.0.113.51")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json(), {"error": "Invalid credentials"})
        self.assertEqual(mock_check.call_count, 1,
                          "the not-found branch must run exactly one check_password_hash() call")
        self.assertEqual(mock_check.call_args.args,
                          (self.app_module._DUMMY_PASSWORD_HASH, "whatever-guess"))

        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp2 = self._post("9999999999", "whatever-guess", ip="203.0.113.52")
        self.assertEqual(resp2.status_code, 401)
        self.assertEqual(resp2.get_json(), {"error": "Invalid credentials"})
        self.assertEqual(mock_check.call_count, 1,
                          "the found-but-wrong-password branch must also run exactly one call")
        self.assertEqual(mock_check.call_args.args[1], "whatever-guess")

    def test_dummy_hash_is_the_same_cost_class_as_a_real_stored_hash(self):
        """Guards against a future edit swapping the dummy for something
        cheap (e.g. a literal string, or a fixed/weak hash) that would
        reopen the timing gap this file exists to close. Compares the
        *algorithm tag* werkzeug embeds in its own hash format — not
        app.py's source text — against a hash generate_password_hash()
        produces for a real password right now, in this environment."""
        real_hash = generate_password_hash("some-real-password")
        dummy_method = self.app_module._DUMMY_PASSWORD_HASH.split("$", 1)[0]
        real_method = real_hash.split("$", 1)[0]
        self.assertEqual(dummy_method, real_method,
                          "the dummy hash must use the same algorithm/cost werkzeug "
                          "currently uses for real password hashes")

    def test_locked_account_without_device_cookie_still_never_calls_check_password_hash(self):
        """Regression guard for the OTHER property in tension with this fix:
        the lockout-DoS mitigation's whole point is that an attacker with no
        recognised-device cookie gets rejected BEFORE any hashing, so they
        gain no extra guesses. Closing the existence-timing leak must not
        quietly make this path start hashing too."""
        attacker_client = self.new_client()  # never logged in — no device cookie
        for _ in range(self.LIMIT):
            self._post("9999999999", "wrong", client=attacker_client, ip="203.0.113.60")
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"], "account must be locked by now")

        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp = self._post("9999999999", "CorrectHorse123!", client=attacker_client, ip="203.0.113.60")
        self.assertEqual(resp.status_code, 423)
        self.assertEqual(mock_check.call_count, 0,
                          "a locked account with no device cookie must reject before hashing, "
                          "even when the correct password is supplied — this is the guess-budget "
                          "guarantee test_login_lockout_dos.py pins; it must not regress")

    def test_locked_account_with_known_device_still_calls_check_password_hash(self):
        """The one deliberate, documented exception: a *recognised* device
        during an active lock does still hash (so the real owner's correct
        password can be honoured). Confirms the timing fix did not
        accidentally short-circuit this path too."""
        owner_client = self.new_client()
        self.assertEqual(self._post("9999999999", "CorrectHorse123!", client=owner_client,
                                     ip="198.51.100.20").status_code, 200)

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._post("9999999999", "wrong", client=attacker_client, ip="203.0.113.61")
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"])

        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp = self._post("9999999999", "CorrectHorse123!", client=owner_client, ip="198.51.100.20")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertEqual(mock_check.call_count, 1)


class AdminLoginTimingTests(_LockoutTestBase):
    """/api/admin/login — same property, admin_users side."""

    FAILED_LOGIN_LIMIT = "3"
    LIMIT = 3

    def _post(self, username, password, client=None, ip="203.0.113.70"):
        return (client or self.client).post(
            "/api/admin/login",
            json={"username": username, "password": password},
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def test_unknown_username_runs_check_password_hash_exactly_like_a_known_one(self):
        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp = self._post("no-such-admin", "whatever-guess", ip="203.0.113.71")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.get_json(), {"error": "Invalid credentials"})
        self.assertEqual(mock_check.call_count, 1,
                          "the unknown-username branch must run exactly one check_password_hash() call")
        self.assertEqual(mock_check.call_args.args,
                          (self.app_module._DUMMY_PASSWORD_HASH, "whatever-guess"))

        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp2 = self._post("opsadmin", "whatever-guess", ip="203.0.113.72")
        self.assertEqual(resp2.status_code, 401)
        self.assertEqual(resp2.get_json(), {"error": "Invalid credentials"})
        self.assertEqual(mock_check.call_count, 1)

    def test_locked_admin_without_device_cookie_still_never_calls_check_password_hash(self):
        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._post("opsadmin", "wrong", client=attacker_client, ip="203.0.113.80")
        self.assertIsNotNone(self.db["admin_users"][1]["locked_until"])

        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp = self._post("opsadmin", "AdminPass123!", client=attacker_client, ip="203.0.113.80")
        self.assertEqual(resp.status_code, 423)
        self.assertEqual(mock_check.call_count, 0,
                          "a locked admin account with no device cookie must reject before hashing")

    def test_locked_admin_with_known_device_still_calls_check_password_hash(self):
        owner_client = self.new_client()
        self.assertEqual(self._post("opsadmin", "AdminPass123!", client=owner_client,
                                     ip="198.51.100.30").status_code, 200)

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._post("opsadmin", "wrong", client=attacker_client, ip="203.0.113.81")
        self.assertIsNotNone(self.db["admin_users"][1]["locked_until"])

        with mock.patch.object(self.app_module, "check_password_hash",
                                wraps=self.app_module.check_password_hash) as mock_check:
            resp = self._post("opsadmin", "AdminPass123!", client=owner_client, ip="198.51.100.30")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertEqual(mock_check.call_count, 1)


if __name__ == "__main__":
    unittest.main()

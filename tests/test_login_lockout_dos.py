"""Account lockout was keyed on the account row alone, with no way for a
request carrying the CORRECT password to bypass an active lock. That made it
an unauthenticated, targeted denial-of-service: anyone who knew a victim's
phone/email (user) or username (admin) could send `failed_login_limit` wrong
passwords and lock the real owner out for `lockout_hours`, indefinitely
repeatable, no valid credentials or CAPTCHA required.

A first fix (letting any correct password bypass an active lock
unconditionally) closed the DoS but broke brute-force protection outright:
every attempt still runs check_password_hash(), and a correct one always
succeeds regardless of lock state, so an attacker who reached the lock
threshold could just keep guessing forever with no additional cost — the lock
stopped capping anything.

Fixed instead with a known-device cookie (OWASP's standard mitigation for
this DoS-vs-lockout tension): on every fully successful login the app mints a
signed, HttpOnly, per-account cookie. A locked account only accepts a login at
all — even with the correct password — when the request carries a valid
cookie naming that exact account, i.e. proof this browser has completed a
full login here before:

  * No cookie (or a cookie for a different account): a locked account
    rejects EVERY request outright, correct password included — the exact
    original, pre-fix behaviour. An attacker who has never logged in as the
    victim is always in this bucket, so they still top out at exactly
    `failed_login_limit` guesses, same as before this feature existed.
  * A valid cookie for this account: a wrong password is still rejected
    outright and does not grant extra guesses (a stolen/replayed cookie is
    not a fresh guessing budget); the correct password is let through and
    the lock clears.

These tests exercise all of that end to end against the real routes
(/api/user/login and /api/admin/login), using hand-written fake cursors that
dispatch on the exact SQL app.py issues — no substring-matching against
app.py's source. Separate `test_client()` instances stand in for separate
browsers: each carries its own cookie jar, so "a browser that has logged in
before" and "an attacker's browser" are modelled as two different clients
hitting the same account.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash


class FakeCursor:
    """Backs both /api/user/login and /api/admin/login against one in-memory
    dict-of-dicts DB. Mirrors the query shapes in tests/test_user_auth.py."""

    def __init__(self, db, dictionary=False):
        self.db = db
        self.dictionary = dictionary
        self._result = []
        self.rowcount = 0

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = []
        self.rowcount = 0

        if q.startswith("SELECT id, phone, name, department, official_email, password_hash"):
            phone_param, email_param = params
            u = next((u for u in self.db["bot_users"].values()
                       if u["phone"] == phone_param or u.get("official_email") == email_param), None)
            self._result = [dict(u)] if u else []

        elif q.startswith("UPDATE bot_users SET failed_login_count=%s, locked_until=DATE_ADD"):
            failed_count, lockout_hours, user_id = params
            self.db["bot_users"][user_id]["failed_login_count"] = failed_count
            self.db["bot_users"][user_id]["locked_until"] = datetime.now(timezone.utc) + timedelta(hours=int(lockout_hours))

        elif q.startswith("UPDATE bot_users SET failed_login_count=0, locked_until=NULL"):
            user_id = params[0]
            self.db["bot_users"][user_id]["failed_login_count"] = 0
            self.db["bot_users"][user_id]["locked_until"] = None

        elif q.startswith("UPDATE bot_users SET failed_login_count=%s WHERE id=%s"):
            failed_count, user_id = params
            self.db["bot_users"][user_id]["failed_login_count"] = failed_count

        elif q.startswith("SELECT 1 FROM admin_users WHERE username=%s AND is_active=1"):
            a = next((a for a in self.db.get("admin_users", {}).values()
                       if a["username"] == params[0] and a.get("is_active", 1)), None)
            self._result = [{"1": 1}] if a else []

        elif q.startswith("SELECT * FROM admin_users WHERE username=%s AND is_active=1"):
            a = next((a for a in self.db.get("admin_users", {}).values()
                       if a["username"] == params[0] and a.get("is_active", 1)), None)
            self._result = [dict(a)] if a else []

        elif q.startswith("UPDATE admin_users SET failed_login_count=%s, locked_until=DATE_ADD"):
            failed_count, lockout_hours, admin_id = params
            self.db["admin_users"][admin_id]["failed_login_count"] = failed_count
            self.db["admin_users"][admin_id]["locked_until"] = datetime.now(timezone.utc) + timedelta(hours=int(lockout_hours))

        elif q.startswith("UPDATE admin_users SET failed_login_count=0, locked_until=NULL"):
            admin_id = params[0]
            self.db["admin_users"][admin_id]["failed_login_count"] = 0
            self.db["admin_users"][admin_id]["locked_until"] = None

        elif q.startswith("UPDATE admin_users SET failed_login_count=%s"):
            self.db["admin_users"][params[-1]]["failed_login_count"] = params[0]

        elif q.startswith("SELECT setting_value FROM app_settings"):
            self._result = []  # nothing configured — routes fall back to FAILED_LOGIN_LIMIT/LOCKOUT_HOURS env defaults

        elif q.startswith("INSERT INTO activity_log"):
            pass

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
        "bot_users": {
            1: {
                "id": 1, "phone": "9999999999", "name": "Ramesh Kumar", "department": "Cyber Cell",
                "official_email": "ramesh@example.gov.in", "password_hash": generate_password_hash("CorrectHorse123!"),
                "credits": 10, "status": "approved", "verification_status": "approved",
                "twofa_enabled": 0, "twofa_secret": None,
                "failed_login_count": 0, "locked_until": None,
            },
            2: {
                "id": 2, "phone": "8888888888", "name": "Priya Singh", "department": "Cyber Cell",
                "official_email": "priya@example.gov.in", "password_hash": generate_password_hash("SecondUser456!"),
                "credits": 10, "status": "approved", "verification_status": "approved",
                "twofa_enabled": 0, "twofa_secret": None,
                "failed_login_count": 0, "locked_until": None,
            },
        },
        "admin_users": {
            1: {
                "id": 1, "name": "Super Admin", "username": "opsadmin",
                "password_hash": generate_password_hash("AdminPass123!"),
                "role": "super_admin", "is_active": 1,
                "twofa_enabled": 0, "twofa_secret": None, "recovery_codes_hash": None,
                "failed_login_count": 0, "locked_until": None,
            },
            2: {
                "id": 2, "name": "Backup Admin", "username": "backupadmin",
                "password_hash": generate_password_hash("BackupPass789!"),
                "role": "super_admin", "is_active": 1,
                "twofa_enabled": 0, "twofa_secret": None, "recovery_codes_hash": None,
                "failed_login_count": 0, "locked_until": None,
            },
        },
    }


class _LockoutTestBase(unittest.TestCase):
    # Both login routes read the limit as get_setting(<key>, os.getenv("FAILED_LOGIN_LIMIT", <hardcoded default>)).
    # get_setting() is patched to always miss (see FakeCursor's app_settings branch), so whatever
    # FAILED_LOGIN_LIMIT is set to in the environment wins over either hardcoded default — pin it
    # here so the test doesn't depend on this checkout's own .env (which happens to set it to "3").
    FAILED_LOGIN_LIMIT = "5"

    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.fake_conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        self.env_patch = mock.patch.dict(os.environ, {"FAILED_LOGIN_LIMIT": self.FAILED_LOGIN_LIMIT})
        self.env_patch.start()
        app_module._rate_limiter._windows.clear()  # per-IP rate limit is a module-level singleton
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()
        self.env_patch.stop()

    def new_client(self):
        """A fresh test client = a fresh cookie jar = a different browser."""
        return self.app_module.app.test_client()


class UserLoginLockoutDosTests(_LockoutTestBase):
    """/api/user/login — FAILED_LOGIN_LIMIT pinned to 5 for this test class."""

    FAILED_LOGIN_LIMIT = "5"
    LIMIT = 5

    def _wrong(self, client=None, ip="203.0.113.7", identifier="9999999999"):
        return (client or self.client).post(
            "/api/user/login",
            json={"identifier": identifier, "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def _correct(self, client=None, ip="198.51.100.9", identifier="9999999999", password="CorrectHorse123!"):
        return (client or self.client).post(
            "/api/user/login",
            json={"identifier": identifier, "password": password},
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def test_owner_with_a_recognised_device_survives_an_attacker_lockout(self):
        """The legitimate owner, having logged in from this browser before (so
        it holds a known-device cookie), must still be able to recover the
        account with the correct password after an attacker locks it — from
        anywhere, without waiting out lockout_hours. This is the DoS the
        finding describes; it must not reproduce for a recognised device."""
        owner_client = self.new_client()
        first_login = self._correct(client=owner_client, ip="198.51.100.9")
        self.assertEqual(first_login.status_code, 200, first_login.get_json())

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):  # attacker, from their own browser/IP, drives the account to its lock threshold
            attacker_resp = self._wrong(client=attacker_client, ip="203.0.113.7")
        self.assertEqual(attacker_resp.status_code, 423)
        self.assertTrue(attacker_resp.get_json()["locked"])
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"], "account must actually be locked at this point")

        # The owner's browser (device cookie already minted above), from a
        # different network, supplies the correct password again.
        owner_resp = self._correct(client=owner_client, ip="198.51.100.9")
        self.assertEqual(owner_resp.status_code, 200, owner_resp.get_json())
        self.assertTrue(owner_resp.get_json()["success"])

        # And the lock is actually cleared, not just bypassed for this one request.
        self.assertEqual(self.db["bot_users"][1]["failed_login_count"], 0)
        self.assertIsNone(self.db["bot_users"][1]["locked_until"])

    def test_correct_password_without_a_known_device_still_cannot_bypass_a_lock(self):
        """This is the assertion that pins the invariant: an attacker who does
        not hold a recognised-device cookie for this account must NOT gain
        entry during an active lock even if they somehow supply the correct
        password (e.g. a leaked/reused credential). Without the cookie, a
        locked account rejects every request outright, exactly as it did
        before this feature existed — the lock still caps guessing."""
        attacker_client = self.new_client()  # never logged in from here — no device cookie
        for _ in range(self.LIMIT):
            self._wrong(client=attacker_client)
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"])

        resp = self._correct(client=attacker_client)
        self.assertEqual(resp.status_code, 423, resp.get_json())
        self.assertTrue(resp.get_json()["locked"])

        # The account must still be locked in the DB — the correct password
        # bought this client nothing.
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"])
        self.assertEqual(self.db["bot_users"][1]["failed_login_count"], self.LIMIT)

    def test_known_device_with_a_wrong_password_gains_no_extra_guesses_while_locked(self):
        """A stolen/replayed device cookie must not become a fresh guessing
        budget: presenting it alongside a WRONG password during an active
        lock is still rejected outright and does not advance the
        failed-attempt counter."""
        owner_client = self.new_client()
        self.assertEqual(self._correct(client=owner_client).status_code, 200)

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._wrong(client=attacker_client)
        locked_count = self.db["bot_users"][1]["failed_login_count"]

        resp = self._wrong(client=owner_client)  # owner's browser, but the WRONG password this time
        self.assertEqual(resp.status_code, 423, resp.get_json())
        self.assertTrue(resp.get_json()["locked"])
        self.assertEqual(self.db["bot_users"][1]["failed_login_count"], locked_count, "a known device gets no extra guesses")

    def test_a_device_cookie_for_one_account_cannot_bypass_a_lock_on_another(self):
        """Per-account scoping: a device cookie minted for user #2 must not
        let that same browser bypass a lock on user #1's account, even with
        user #1's correct password."""
        other_owner_client = self.new_client()
        self.assertEqual(
            self._correct(client=other_owner_client, identifier="8888888888", password="SecondUser456!").status_code,
            200,
        )

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._wrong(client=attacker_client, identifier="9999999999")
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"])

        # Reuse the OTHER account's recognised browser against the LOCKED account.
        resp = self._correct(client=other_owner_client, identifier="9999999999", password="CorrectHorse123!")
        self.assertEqual(resp.status_code, 423, resp.get_json())
        self.assertIsNotNone(self.db["bot_users"][1]["locked_until"])

    def test_wrong_guesses_against_an_already_locked_account_gain_no_extra_attempts(self):
        """Brute-force protection must survive the fix: once locked, further
        WRONG guesses are still rejected outright (423), and the failed-attempt
        counter must not keep climbing — an attacker gets no more guesses than
        `failed_login_limit` no matter how many more wrong passwords they send."""
        for _ in range(self.LIMIT):
            self._wrong()
        locked_count = self.db["bot_users"][1]["failed_login_count"]
        self.assertEqual(locked_count, self.LIMIT)

        for _ in range(3):  # keep hammering with wrong passwords after the lock
            resp = self._wrong()
            self.assertEqual(resp.status_code, 423)
            self.assertTrue(resp.get_json()["locked"])

        # The counter did not grow past the point where the lock kicked in —
        # these extra wrong guesses bought the attacker nothing.
        self.assertEqual(self.db["bot_users"][1]["failed_login_count"], locked_count)

    def test_wrong_password_while_locked_still_reports_locked_not_invalid_credentials(self):
        """A locked-out wrong guess must read as a lock (423), not silently
        fall through to the generic 401 an unlocked wrong guess gets — that
        distinction is how a real client knows to stop retrying and wait."""
        for _ in range(self.LIMIT):
            self._wrong()
        resp = self._wrong()
        self.assertEqual(resp.status_code, 423)
        self.assertNotEqual(resp.status_code, 401)


class AdminLoginLockoutDosTests(_LockoutTestBase):
    """/api/admin/login — FAILED_LOGIN_LIMIT pinned to 3 for this test class."""

    FAILED_LOGIN_LIMIT = "3"
    LIMIT = 3

    def _wrong(self, client=None, ip="203.0.113.7", username="opsadmin"):
        return (client or self.client).post(
            "/api/admin/login",
            json={"username": username, "password": "wrong"},
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def _correct(self, client=None, ip="198.51.100.9", username="opsadmin", password="AdminPass123!"):
        return (client or self.client).post(
            "/api/admin/login",
            json={"username": username, "password": password},
            environ_overrides={"REMOTE_ADDR": ip},
        )

    def test_owner_with_a_recognised_device_survives_an_attacker_lockout(self):
        owner_client = self.new_client()
        self.assertEqual(self._correct(client=owner_client).status_code, 200)

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):  # default admin FAILED_LOGIN_LIMIT is 3
            attacker_resp = self._wrong(client=attacker_client)
        self.assertEqual(attacker_resp.status_code, 423)
        self.assertTrue(attacker_resp.get_json()["locked"])

        owner_resp = self._correct(client=owner_client, ip="198.51.100.9")
        self.assertEqual(owner_resp.status_code, 200, owner_resp.get_json())
        self.assertTrue(owner_resp.get_json()["success"])

        self.assertEqual(self.db["admin_users"][1]["failed_login_count"], 0)
        self.assertIsNone(self.db["admin_users"][1]["locked_until"])

    def test_correct_password_without_a_known_device_still_cannot_bypass_a_lock(self):
        """Same invariant-pinning assertion as the user-side test: no cookie
        means a locked admin account rejects even the correct password."""
        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._wrong(client=attacker_client)
        self.assertIsNotNone(self.db["admin_users"][1]["locked_until"])

        resp = self._correct(client=attacker_client)
        self.assertEqual(resp.status_code, 423, resp.get_json())
        self.assertTrue(resp.get_json()["locked"])
        self.assertIsNotNone(self.db["admin_users"][1]["locked_until"])
        self.assertEqual(self.db["admin_users"][1]["failed_login_count"], self.LIMIT)

    def test_known_device_with_a_wrong_password_gains_no_extra_guesses_while_locked(self):
        owner_client = self.new_client()
        self.assertEqual(self._correct(client=owner_client).status_code, 200)

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._wrong(client=attacker_client)
        locked_count = self.db["admin_users"][1]["failed_login_count"]

        resp = self._wrong(client=owner_client)
        self.assertEqual(resp.status_code, 423, resp.get_json())
        self.assertEqual(self.db["admin_users"][1]["failed_login_count"], locked_count)

    def test_a_device_cookie_for_one_admin_cannot_bypass_a_lock_on_another(self):
        other_owner_client = self.new_client()
        self.assertEqual(
            self._correct(client=other_owner_client, username="backupadmin", password="BackupPass789!").status_code,
            200,
        )

        attacker_client = self.new_client()
        for _ in range(self.LIMIT):
            self._wrong(client=attacker_client, username="opsadmin")
        self.assertIsNotNone(self.db["admin_users"][1]["locked_until"])

        resp = self._correct(client=other_owner_client, username="opsadmin", password="AdminPass123!")
        self.assertEqual(resp.status_code, 423, resp.get_json())
        self.assertIsNotNone(self.db["admin_users"][1]["locked_until"])

    def test_wrong_guesses_against_an_already_locked_admin_account_gain_no_extra_attempts(self):
        for _ in range(self.LIMIT):
            self._wrong()
        locked_count = self.db["admin_users"][1]["failed_login_count"]
        self.assertEqual(locked_count, self.LIMIT)

        for _ in range(3):
            resp = self._wrong()
            self.assertEqual(resp.status_code, 423)
            self.assertTrue(resp.get_json()["locked"])

        self.assertEqual(self.db["admin_users"][1]["failed_login_count"], locked_count)


if __name__ == "__main__":
    unittest.main()

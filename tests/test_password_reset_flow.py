"""REMEDIATION-PLAN.md §2.2 — real test_client() coverage for the admin-issued
password-reset token flow (issue_reset_token / consume_reset_token, wired
through the real routes: POST /api/admin/users/<id>/password-reset issues,
POST /api/user/password-reset/confirm consumes).

tests/test_access_control.py never calls either route. This file drives both
through a real Flask test_client() against an in-memory fake
password_reset_tokens/bot_users table and asserts:

  - the token is stored hashed, never in plaintext (issue_reset_token's own
    docstring: "the only moment it exists in readable form" is the return
    value),
  - a fresh token is consumed successfully and actually flips the account's
    password_hash,
  - it is single-use: a second consume attempt with the same token fails,
  - it is TTL-bound: a token whose expires_at has passed is rejected,
  - issuing a new token invalidates any outstanding one for that user.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import check_password_hash


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

        if q.startswith("SELECT id, name, phone FROM bot_users WHERE id=%s"):
            u = self.db["bot_users"].get(params[0])
            self._result = [{"id": u["id"], "name": u["name"], "phone": u["phone"]}] if u else []

        elif q.startswith("UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=%s AND used_at IS NULL"):
            user_id = params[0]
            now = datetime.now()
            for row in self.db["password_reset_tokens"]:
                if row["user_id"] == user_id and row["used_at"] is None:
                    row["used_at"] = now

        elif q.startswith("INSERT INTO password_reset_tokens (user_id, token_hash, purpose, issued_by, expires_at)"):
            user_id, token_hash, purpose, issued_by, ttl_hours = params
            now = datetime.now()
            row = {
                "id": self.db["_next_token_id"],
                "user_id": user_id,
                "token_hash": token_hash,
                "purpose": purpose,
                "issued_by": issued_by,
                "expires_at": now + timedelta(hours=ttl_hours),
                "used_at": None,
                "created_at": now,
            }
            self.db["password_reset_tokens"].append(row)
            self.db["_next_token_id"] += 1

        elif q.startswith("UPDATE bot_users SET failed_login_count=0, locked_until=NULL WHERE id=%s"):
            pass  # lockout-clearing side effect, not under test here

        elif q.startswith("SELECT id, user_id, token_hash FROM password_reset_tokens WHERE used_at IS NULL AND expires_at > NOW()"):
            now = datetime.now()
            rows = [r for r in self.db["password_reset_tokens"] if r["used_at"] is None and r["expires_at"] > now]
            rows.sort(key=lambda r: r["created_at"], reverse=True)
            self._result = [dict(r) for r in rows[:200]]

        elif q.startswith("UPDATE password_reset_tokens SET used_at=NOW() WHERE id=%s"):
            token_id = params[0]
            now = datetime.now()
            for row in self.db["password_reset_tokens"]:
                if row["id"] == token_id:
                    row["used_at"] = now

        elif q.startswith(
            "UPDATE bot_users SET password_hash=%s, password_set_at=NOW(), "
            "failed_login_count=0, locked_until=NULL WHERE id=%s"
        ):
            password_hash, user_id = params
            self.db["bot_users"][user_id]["password_hash"] = password_hash

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
            9: {
                "id": 9, "name": "Insp. Test Officer", "phone": "9123456780",
                "password_hash": "pbkdf2:sha256:old-hash-placeholder",
            },
        },
        "password_reset_tokens": [],
        "_next_token_id": 1,
    }


class PasswordResetFlowTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=FakeConn(self.db))
        self.get_db_patch.start()
        self.log_patch = mock.patch.object(app_module, "log_activity")
        self.log_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.log_patch.stop()
        self.get_db_patch.stop()

    CSRF_TOKEN = "reset-test-csrf-token"
    CSRF_HEADERS = {"X-CSRF-Token": CSRF_TOKEN}

    def _issue_token(self, user_id=9):
        """Issue a reset token via the real admin route and return the plaintext."""
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["admin_name"] = "Root Admin"
            sess["admin_role"] = "super_admin"
            sess["csrf_token"] = self.CSRF_TOKEN
        resp = self.client.post(
            f"/api/admin/users/{user_id}/password-reset", json={}, headers=self.CSRF_HEADERS
        )
        self.assertEqual(resp.status_code, 200)
        token = resp.get_json()["reset_token"]
        # Consuming happens from a separate, unauthenticated client below —
        # the officer resetting their own password is a different browser
        # session than the admin who issued the code out of band.
        with self.client.session_transaction() as sess:
            sess.clear()
        return token

    def _consume(self, token, password="BrandNewPass123"):
        anon_client = self.app_module.app.test_client()
        return anon_client.post(
            "/api/user/password-reset/confirm", json={"token": token, "password": password}
        )

    def test_token_is_stored_hashed_not_plaintext(self):
        token = self._issue_token()
        self.assertEqual(len(self.db["password_reset_tokens"]), 1)
        stored_hash = self.db["password_reset_tokens"][0]["token_hash"]
        self.assertNotEqual(stored_hash, token, "the plaintext token must never be written to the DB")
        self.assertNotIn(token, stored_hash)
        self.assertTrue(
            check_password_hash(stored_hash, token),
            "the stored value must be a real password-hash of the issued token",
        )

    def test_issue_then_consume_end_to_end_sets_the_new_password(self):
        token = self._issue_token()
        resp = self._consume(token, password="BrandNewPass123")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["success"])

        new_hash = self.db["bot_users"][9]["password_hash"]
        self.assertNotEqual(new_hash, "pbkdf2:sha256:old-hash-placeholder")
        self.assertTrue(check_password_hash(new_hash, "BrandNewPass123"))

        # The token itself is now burned.
        self.assertIsNotNone(self.db["password_reset_tokens"][0]["used_at"])

    def test_token_is_single_use_second_consume_attempt_fails(self):
        token = self._issue_token()
        first = self._consume(token, password="BrandNewPass123")
        self.assertEqual(first.status_code, 200)

        second = self._consume(token, password="AnotherPass456")
        self.assertEqual(second.status_code, 400)
        self.assertIn("error", second.get_json())
        # The password set by the first, legitimate consume must survive —
        # the replayed attempt must not overwrite it again.
        self.assertTrue(check_password_hash(self.db["bot_users"][9]["password_hash"], "BrandNewPass123"))

    def test_expired_token_is_rejected(self):
        token = self._issue_token()
        # Force the stored row into the past, simulating PASSWORD_RESET_TTL_HOURS
        # having elapsed, without waiting real time.
        self.db["password_reset_tokens"][0]["expires_at"] = datetime.now() - timedelta(seconds=1)

        resp = self._consume(token, password="BrandNewPass123")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())
        self.assertEqual(self.db["bot_users"][9]["password_hash"], "pbkdf2:sha256:old-hash-placeholder")

    def test_issuing_a_new_token_invalidates_the_previous_outstanding_one(self):
        old_token = self._issue_token()
        new_token = self._issue_token()
        self.assertNotEqual(old_token, new_token)
        self.assertEqual(len(self.db["password_reset_tokens"]), 2)

        stale = self._consume(old_token, password="ShouldNotWork123")
        self.assertEqual(stale.status_code, 400)

        fresh = self._consume(new_token, password="ShouldWork123456")
        self.assertEqual(fresh.status_code, 200)
        self.assertTrue(check_password_hash(self.db["bot_users"][9]["password_hash"], "ShouldWork123456"))

    def test_unknown_token_is_rejected(self):
        resp = self._consume("this-token-was-never-issued", password="BrandNewPass123")
        self.assertEqual(resp.status_code, 400)

    def test_weak_new_password_is_rejected_before_the_token_is_burned(self):
        token = self._issue_token()
        resp = self._consume(token, password="short1")  # under MIN_PASSWORD_LENGTH
        self.assertEqual(resp.status_code, 400)
        # Token must still be usable — a rejected password shouldn't burn it.
        self.assertIsNone(self.db["password_reset_tokens"][0]["used_at"])

        good = self._consume(token, password="LongEnoughPass1")
        self.assertEqual(good.status_code, 200)


if __name__ == "__main__":
    unittest.main()

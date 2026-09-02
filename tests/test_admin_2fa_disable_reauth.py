"""Phase-1 deploy-blocker #3 — disable_2fa() cleared an admin's 2FA with zero
re-authentication: any request that reached the (session-authenticated,
CSRF-checked) /api/admin/2fa/disable endpoint succeeded unconditionally, so a
hijacked session or a CSRF-adjacent bug could strip the second factor without
proving the caller still holds the password or a live OTP.

Fixed to require current_password OR a fresh otp in the JSON body, verified
BEFORE anything is cleared — mirrors user_password_change()'s re-auth pattern
(check_password_hash against the stored hash) and reuses the same OTP
verification call admin login already uses:
pyotp.TOTP(decrypt_text(secret)).verify(otp, valid_window=1).

Confirmed (by inspection — see grep below in the test) that no user-side
equivalent (/api/user/2fa/disable) exists in app.py; none is added here, per
the task's explicit instruction to only fix it if it already existed.

No RBAC change: @admin_required is unchanged and is the only decorator on
this route.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash

CSRF_TOKEN = "disable-2fa-csrf-token"
CORRECT_PASSWORD = "CorrectHorse123!"


class _FakeCursor:
    def __init__(self, db):
        self.db = db
        self._result = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        if q.startswith("SELECT password_hash, twofa_secret FROM admin_users WHERE id=%s"):
            admin = self.db["admin_users"].get(params[0])
            self._result = dict(admin) if admin else None
        elif q.startswith("UPDATE admin_users SET twofa_enabled=0, twofa_secret=NULL, recovery_codes_hash=NULL"):
            admin_id = params[0]
            self.db["admin_users"][admin_id].update(
                twofa_enabled=0, twofa_secret=None, recovery_codes_hash=None
            )
        elif q.startswith("INSERT INTO activity_log"):
            self.db.setdefault("activity_log", []).append(params)
        else:
            raise AssertionError(f"_FakeCursor got an unexpected query: {q!r}")

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


def _make_db(twofa_enabled=1, twofa_secret_plain="JBSWY3DPEHPK3PXP"):
    import app as app_module
    return {
        "admin_users": {
            1: {
                "id": 1,
                "password_hash": generate_password_hash(CORRECT_PASSWORD),
                "twofa_enabled": twofa_enabled,
                "twofa_secret": app_module.encrypt_text(twofa_secret_plain) if twofa_enabled else None,
                "recovery_codes_hash": None,
            },
        },
        "activity_log": [],
    }


class NoUserSideDisableRouteTests(unittest.TestCase):
    def test_no_user_2fa_disable_route_exists(self):
        # Confirms the investigation this fix relied on: only the admin route
        # exists. Per task scope, none is added for the user side.
        app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
        with open(app_path, encoding="utf-8") as f:
            src = f.read()
        self.assertIn('"/api/admin/2fa/disable"', src)
        self.assertNotIn('"/api/user/2fa/disable"', src)


class Disable2FAReauthTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = _make_db()
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

    def _post(self, body):
        return self.client.post(
            "/api/admin/2fa/disable",
            json=body,
            headers={"X-CSRF-Token": CSRF_TOKEN},
        )

    def test_requires_admin_session(self):
        resp = self.client.post("/api/admin/2fa/disable", json={"current_password": CORRECT_PASSWORD})
        self.assertEqual(resp.status_code, 401)

    def test_no_credential_at_all_is_rejected_and_2fa_stays_enabled(self):
        self._login_admin()
        resp = self._post({})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["admin_users"][1]["twofa_enabled"], 1)
        self.assertIsNotNone(self.db["admin_users"][1]["twofa_secret"])

    def test_wrong_password_and_no_otp_is_rejected(self):
        self._login_admin()
        resp = self._post({"current_password": "TotallyWrongPassword1"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["admin_users"][1]["twofa_enabled"], 1)

    def test_wrong_otp_and_no_password_is_rejected(self):
        self._login_admin()
        resp = self._post({"otp": "000000"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.db["admin_users"][1]["twofa_enabled"], 1)

    def test_correct_password_disables_2fa(self):
        self._login_admin()
        resp = self._post({"current_password": CORRECT_PASSWORD})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["success"])
        self.assertEqual(self.db["admin_users"][1]["twofa_enabled"], 0)
        self.assertIsNone(self.db["admin_users"][1]["twofa_secret"])

    def test_correct_otp_disables_2fa_without_password(self):
        import pyotp
        self._login_admin()
        secret_plain = "JBSWY3DPEHPK3PXP"
        otp = pyotp.TOTP(secret_plain).now()
        resp = self._post({"otp": otp})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["success"])
        self.assertEqual(self.db["admin_users"][1]["twofa_enabled"], 0)

    def test_disabling_when_2fa_was_never_enabled_still_requires_password(self):
        # twofa_secret is NULL in this case, so only the password path can
        # verify — confirms the OTP branch is skipped safely (no crash on
        # decrypt_text(None)) rather than silently succeeding.
        self.db.update(_make_db(twofa_enabled=0))
        self._login_admin()
        resp = self._post({"otp": "123456"})
        self.assertEqual(resp.status_code, 401)
        resp = self._post({"current_password": CORRECT_PASSWORD})
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()

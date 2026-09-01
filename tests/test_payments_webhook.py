"""REMEDIATION-PLAN.md §2.2 — real test_client() coverage for the payment webhook.

tests/test_access_control.py's webhook "test" only asserted that the string
"verify_webhook(" appears at a lower string index than "credit_payment_order("
in app.py's source text — satisfied by an empty guard body or dead code. This
file actually POSTs to /api/payments/webhook/<provider>, drives the real
RazorpayProvider.verify_webhook() HMAC check and the real credit_payment_order()
crediting path against an in-memory fake DB, and asserts on the resulting DB
state and HTTP responses.

Covers:
  - a validly-signed webhook is accepted and credits the order exactly once,
  - a forged/invalid signature is rejected (400) and nothing is credited,
  - replaying an already-processed webhook does not double-credit — this is
    the `UPDATE payment_orders ... WHERE status<>'paid'` + rowcount guard in
    credit_payment_order(), exercised here rather than merely read.
"""
import hashlib
import hmac
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEBHOOK_SECRET = "whsec_test_only_do_not_use_in_prod"


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

        if q.startswith("SELECT * FROM payment_orders WHERE provider=%s AND provider_order_id=%s LIMIT 1"):
            provider, provider_order_id = params
            order = next(
                (o for o in self.db["payment_orders"].values()
                 if o["provider"] == provider and o["provider_order_id"] == provider_order_id),
                None,
            )
            self._result = [dict(order)] if order else []

        elif q.startswith(
            "UPDATE payment_orders SET status='paid', credited_at=NOW(), "
            "provider_payment_id=%s, confirmed_by=%s WHERE id=%s AND status<>'paid'"
        ):
            provider_payment_id, confirmed_by, order_id = params
            order = self.db["payment_orders"].get(order_id)
            if order and order["status"] != "paid":
                order["status"] = "paid"
                order["provider_payment_id"] = provider_payment_id
                order["confirmed_by"] = confirmed_by
                self.rowcount = 1
            else:
                self.rowcount = 0

        elif q.startswith("UPDATE bot_users SET credits = credits + %s WHERE id=%s"):
            amount, user_id = params
            self.db["bot_users"][user_id]["credits"] += amount

        elif q.startswith(
            "INSERT INTO credit_transactions (phone, type, amount, reason, razorpay_order_id, status) "
            "VALUES (%s,'credit',%s,%s,%s,'success')"
        ):
            phone, amount, reason, provider_order_id = params
            self.db["credit_transactions"].append(
                {"phone": phone, "amount": amount, "reason": reason, "provider_order_id": provider_order_id}
            )

        else:
            raise AssertionError(f"FakeCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class FakeConn:
    def __init__(self, db):
        self.db = db
        self.committed = 0
        self.closed = 0

    def cursor(self, dictionary=False):
        return FakeCursor(self.db, dictionary=dictionary)

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass

    def close(self):
        self.closed += 1


def make_db():
    return {
        "bot_users": {
            5: {"id": 5, "phone": "9999999999", "credits": 10},
        },
        "payment_orders": {
            1: {
                "id": 1, "order_ref": "SNT-20260830-AAAA1111", "user_id": 5, "phone": "9999999999",
                "plan_id": 2, "plan_name": "Pro", "credits": 150, "amount_inr": 99,
                "provider": "razorpay", "provider_order_id": "order_XYZ789",
                "provider_payment_id": None, "status": "pending", "confirmed_by": None,
            },
        },
        "credit_transactions": [],
    }


def sign(raw_body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()


def razorpay_body(order_id="order_XYZ789", payment_id="pay_ABC001", event="payment.captured"):
    return json.dumps({
        "event": event,
        "payload": {"payment": {"entity": {"id": payment_id, "order_id": order_id}}},
    }).encode("utf-8")


class PaymentsWebhookTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.conn)
        self.get_db_patch.start()
        # log_activity opens its own DB connection (reusing the same patched
        # get_db) and writes to activity_log, which this fake DB doesn't model
        # (out of scope for this test — the crediting path is what's under
        # test). Mirrors how test_import_rollback.py keeps log_audit out of
        # its assertions.
        self.log_patch = mock.patch.object(app_module, "log_activity")
        self.log_patch.start()
        self.env_patch = mock.patch.dict(os.environ, {"RAZORPAY_WEBHOOK_SECRET": WEBHOOK_SECRET})
        self.env_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.env_patch.stop()
        self.log_patch.stop()
        self.get_db_patch.stop()

    def _post(self, raw_body, signature):
        return self.client.post(
            "/api/payments/webhook/razorpay",
            data=raw_body,
            content_type="application/json",
            headers={"X-Razorpay-Signature": signature},
        )

    def test_valid_signature_credits_the_order_exactly_once(self):
        raw_body = razorpay_body()
        resp = self._post(raw_body, sign(raw_body))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["credited"])

        self.assertEqual(self.db["payment_orders"][1]["status"], "paid")
        self.assertEqual(self.db["payment_orders"][1]["provider_payment_id"], "pay_ABC001")
        self.assertEqual(self.db["bot_users"][5]["credits"], 160)  # 10 + 150
        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["credit_transactions"][0]["amount"], 150)
        self.assertEqual(self.db["credit_transactions"][0]["phone"], "9999999999")

    def test_forged_signature_is_rejected_and_nothing_is_credited(self):
        raw_body = razorpay_body()
        resp = self._post(raw_body, "0" * 64)  # well-formed hex, but not HMAC(secret, body)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

        self.assertEqual(self.db["payment_orders"][1]["status"], "pending")
        self.assertEqual(self.db["bot_users"][5]["credits"], 10)
        self.assertEqual(self.db["credit_transactions"], [])

    def test_signature_from_the_wrong_secret_is_rejected(self):
        raw_body = razorpay_body()
        resp = self._post(raw_body, sign(raw_body, secret="not-the-real-secret"))
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.db["payment_orders"][1]["status"], "pending")

    def test_replaying_an_already_processed_webhook_does_not_double_credit(self):
        raw_body = razorpay_body()
        signature = sign(raw_body)

        first = self._post(raw_body, signature)
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.get_json()["credited"])

        second = self._post(raw_body, signature)  # exact replay
        self.assertEqual(second.status_code, 200)
        self.assertFalse(second.get_json()["credited"], "a replayed webhook must not report a fresh credit")

        # The UPDATE ... WHERE status<>'paid' + rowcount guard must have held:
        # exactly one credit, one transaction row, no matter how many times the
        # gateway (or an attacker) resends the same signed payload.
        self.assertEqual(self.db["bot_users"][5]["credits"], 160)
        self.assertEqual(len(self.db["credit_transactions"]), 1)

    def test_webhook_for_an_order_already_marked_paid_by_another_path_is_not_credited(self):
        """Directly exercises the WHERE status<>'paid' guard, independent of
        whether *this* webhook was the one that first marked it paid — e.g. an
        admin manually confirmed a bank transfer for the same order first."""
        self.db["payment_orders"][1]["status"] = "paid"
        raw_body = razorpay_body(payment_id="pay_DIFFERENT")
        resp = self._post(raw_body, sign(raw_body))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.get_json()["credited"])
        self.assertEqual(self.db["bot_users"][5]["credits"], 10)
        self.assertEqual(self.db["credit_transactions"], [])

    def test_non_captured_event_is_ignored_without_touching_the_order(self):
        raw_body = razorpay_body(event="payment.failed")
        resp = self._post(raw_body, sign(raw_body))
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertNotIn("credited", body)
        self.assertEqual(self.db["payment_orders"][1]["status"], "pending")

    def test_unknown_order_id_is_rejected(self):
        raw_body = razorpay_body(order_id="order_DOES_NOT_EXIST")
        resp = self._post(raw_body, sign(raw_body))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.db["bot_users"][5]["credits"], 10)


if __name__ == "__main__":
    unittest.main()

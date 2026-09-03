"""Request-size cap (MAX_CONTENT_LENGTH) and its 413 JSON error handler.

No MAX_CONTENT_LENGTH was set anywhere before this fix — Werkzeug happily read an
entire oversized body into memory the moment a view touched request.form/request.files,
which under gunicorn --workers 1 (see Dockerfile) is a one-request memory-exhaustion
DoS reachable by any authenticated user, not just an admin (lea_register()'s gov-ID
upload is reachable by any freshly self-registered account).

This exercises the cap against a real matched route — admin_data_preview(), chosen
because @admin_required only checks the session (no DB round trip), so this needs no
live MySQL — and confirms an oversized request gets a JSON body, not Werkzeug's default
HTML 413 page: the frontend does `await r.json().catch(()=>({}))` and reads `d.error`
everywhere (see templates/admin.html), so an HTML page here would silently become `{}`
and a meaningless generic toast.
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MaxContentLengthTest(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

        # Shrink the cap so the test doesn't need to push real megabytes through
        # test_client() to exceed it — the exact number isn't the point, only that
        # request.files parsing is cut off before the body is fully buffered. Both
        # the enforced byte cap and the MB constant the 413 message reports from are
        # overridden together so the two stay consistent.
        self._orig_bytes = app_module.app.config["MAX_CONTENT_LENGTH"]
        self._orig_mb = app_module.MAX_CONTENT_LENGTH_MB
        app_module.app.config["MAX_CONTENT_LENGTH"] = 1024
        app_module.MAX_CONTENT_LENGTH_MB = 1024 / (1024 * 1024)
        self.addCleanup(self._restore)

    def _restore(self):
        self.app_module.app.config["MAX_CONTENT_LENGTH"] = self._orig_bytes
        self.app_module.MAX_CONTENT_LENGTH_MB = self._orig_mb

    # Every state-changing request from an authenticated session must carry a
    # matching X-CSRF-Token (see _enforce_csrf(), app.py) — an admin session with no
    # csrf_token gets silently cleared by that same before_request hook (by design,
    # so it fails back to a normal 401 rather than wedging forever), which would
    # otherwise make this test's POST look unauthenticated rather than testing the
    # size cap at all. Same pattern as tests/test_import_rollback.py.
    _CSRF_TOKEN = "max-content-length-test-token"

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["csrf_token"] = self._CSRF_TOKEN

    def test_oversized_upload_gets_413_json_not_html(self):
        self._login_admin()
        oversized = io.BytesIO(b"x" * 5000)  # well past the 1024-byte test cap
        resp = self.client.post(
            "/api/admin/data/preview",
            data={"file": (oversized, "big.csv")},
            content_type="multipart/form-data",
            headers={"X-CSRF-Token": self._CSRF_TOKEN},
        )
        self.assertEqual(resp.status_code, 413)
        body = resp.get_json()
        self.assertIsInstance(
            body, dict,
            "413 response was not JSON — frontend's r.json().catch(()=>({})) would "
            "silently swallow it and show a meaningless generic failure",
        )
        self.assertIn("error", body)

    def test_request_within_the_cap_is_not_rejected(self):
        self._login_admin()
        small = io.BytesIO(b"a,b\n1,2\n")
        resp = self.client.post(
            "/api/admin/data/preview",
            data={"file": (small, "small.csv")},
            content_type="multipart/form-data",
            headers={"X-CSRF-Token": self._CSRF_TOKEN},
        )
        # Whatever happens downstream (parsing succeeds, a 400, etc.) is not this
        # test's concern — only that the size cap itself doesn't fire under it.
        self.assertNotEqual(resp.status_code, 413)


if __name__ == "__main__":
    unittest.main()

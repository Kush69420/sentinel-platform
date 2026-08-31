"""Day 2 (f) — two independent hardening fixes:

  1. `/uploads/<filename>` built the filesystem path directly from the URL
     segment with no secure_filename()/basename guard — admin-only already,
     but nothing stopped a path-traversal segment from being joined onto
     UPLOAD_FOLDER. The write path (lea_register()) already runs uploaded
     names through secure_filename(); this is the same guard on the read side.
  2. `/api/events` was a fully unauthenticated SSE endpoint with an unbounded
     `while True` generator loop per connection — anyone could open unlimited
     connections that never terminated. Now requires a session (user or
     admin — the payload is identical for both) and each connection self-
     closes after EVENT_STREAM_MAX_SECONDS.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class UploadsPathTraversalTest(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

        # Everything this test writes goes in a temp tree, not next to app.py.
        # The container image runs as a non-root uid against a root-owned /app,
        # so writing into BASE_DIR fails with PermissionError there — correctly.
        # UPLOAD_FOLDER is read as a module global by the /uploads route, so
        # repointing it here is enough to redirect the route at the temp tree.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = self._tmp.name

        self._orig_upload_folder = app_module.UPLOAD_FOLDER
        app_module.UPLOAD_FOLDER = os.path.join(base, "uploads")
        os.makedirs(app_module.UPLOAD_FOLDER, exist_ok=True)
        self.addCleanup(
            setattr, app_module, "UPLOAD_FOLDER", self._orig_upload_folder
        )

        # A "secret" file living outside UPLOAD_FOLDER, sibling to it, that a
        # traversal segment might try to reach.
        self.secret_path = os.path.join(base, "day2_traversal_secret.txt")
        with open(self.secret_path, "w", encoding="utf-8") as fh:
            fh.write("outside the upload folder")

        # A legitimate file actually inside UPLOAD_FOLDER, to prove the fix
        # doesn't also break normal admin downloads.
        self.legit_name = "day2_test_upload.png"
        self.legit_path = os.path.join(app_module.UPLOAD_FOLDER, self.legit_name)
        with open(self.legit_path, "wb") as fh:
            fh.write(b"\x89PNG\r\n not a real png but bytes are bytes")

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1

    def test_requires_admin(self):
        resp = self.client.get(f"/uploads/{self.legit_name}")
        self.assertEqual(resp.status_code, 401)

    def test_legitimate_file_is_still_served(self):
        self._login_admin()
        resp = self.client.get(f"/uploads/{self.legit_name}")
        self.assertEqual(resp.status_code, 200)
        resp.close()

    def test_traversal_segment_cannot_escape_upload_folder(self):
        self._login_admin()
        for traversal in (
            "../day2_traversal_secret.txt",
            "..%2Fday2_traversal_secret.txt",
            "....//day2_traversal_secret.txt",
        ):
            with self.subTest(traversal=traversal):
                resp = self.client.get(f"/uploads/{traversal}")
                # Every one of these segments contains a slash once decoded, so
                # Werkzeug's single-segment <filename> converter never matches
                # the route at all (generic 404) — and even if it did,
                # secure_filename() would strip it to a name that isn't on
                # disk, hitting the route's own explicit 404. Confirmed by
                # direct execution: all three cases return exactly 404.
                self.assertEqual(resp.status_code, 404,
                                  f"traversal segment {traversal!r} did not get a clean 404")
                self.assertNotIn(b"outside the upload folder", resp.data)

    def test_absolute_path_segment_is_rejected(self):
        self._login_admin()
        resp = self.client.get("/uploads/%2Fetc%2Fpasswd")
        # %2F decodes to a literal slash, which the single-segment <filename>
        # converter can never match — Werkzeug 404s before serve_upload() is
        # even reached. Confirmed by direct execution.
        self.assertEqual(resp.status_code, 404)


class EventStreamAuthTest(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def test_requires_a_session(self):
        resp = self.client.get("/api/events")
        self.assertEqual(resp.status_code, 401)

    def test_admin_session_is_accepted(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
        resp = self.client.get("/api/events")
        self.assertEqual(resp.status_code, 200)
        resp.close()

    def test_user_session_is_accepted(self):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = 1
        resp = self.client.get("/api/events")
        self.assertEqual(resp.status_code, 200)
        resp.close()


class EventStreamBoundedLoopTest(unittest.TestCase):
    """The generator must terminate on its own rather than loop forever."""

    def test_stream_terminates_once_the_time_budget_elapses(self):
        import app as app_module
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()
        with client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1

        # A real (tiny) sleep, not a no-op: disabling it entirely lets the loop
        # spin as fast as the interpreter can manage within the time budget,
        # which says nothing about whether the bound works — it would pass
        # (eventually terminate) even for a huge/wrong budget just because 50ms
        # of wall-clock time did elapse. A small real per-iteration delay keeps
        # the iteration count itself meaningful evidence of the bound.
        original_budget = app_module.EVENT_STREAM_MAX_SECONDS
        original_sleep = app_module.time.sleep
        app_module.EVENT_STREAM_MAX_SECONDS = 0.05
        app_module.time.sleep = lambda _s: original_sleep(0.01)
        try:
            resp = client.get("/api/events")
            chunks = list(resp.response)  # fully drains the generator
            resp.close()
        finally:
            app_module.EVENT_STREAM_MAX_SECONDS = original_budget
            app_module.time.sleep = original_sleep

        self.assertGreater(len(chunks), 0, "no heartbeat was emitted at all")
        # A `while True` regression would make this call hang/never return;
        # reaching this assertion at all is already part of the proof the loop
        # ends. The count itself pins the bound: ~0.05s budget / ~0.01s per
        # iteration is a handful of chunks, not hundreds.
        self.assertLess(len(chunks), 20, "loop ran far more iterations than the time budget allows")


if __name__ == "__main__":
    unittest.main()

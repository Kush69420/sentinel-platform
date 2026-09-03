"""Server-side enforcement of the idle/inactivity timeout.

Before this fix, `inactivity_timeout_seconds` (from `session_info()`, app.py)
was only ever *reported* to the client — enforcement lived entirely in JS
timers in dashboard.html/admin.html. A session cookie replayed directly
(curl, no JS) ignored the advertised idle window completely; the only real
server-side limit was Flask's *absolute* `app.permanent_session_lifetime`
(itsdangerous `max_age` on the signed cookie), a much wider window than the
idle timeout the product advertises.

The fix is `_enforce_inactivity_timeout()`, a `before_request` hook in app.py
registered ahead of `_enforce_csrf()`, backed by a `last_activity_at` marker
in the signed session cookie. Only state-changing requests (method not in
`CSRF_SAFE_METHODS`) refresh that marker — deliberately, because
dashboard.html/admin.html poll several read-only endpoints on timers that
have nothing to do with a human being present (`/api/user/session` every
60s, `/api/admin/session-info` on page load, and `/api/events`, an SSE stream
that itself pushes a sync ping every 5 seconds and drives further background
GETs). If any of those counted as activity, an abandoned-but-open tab would
refresh the marker forever and the idle timeout could never fire in
production. See the module comment above `_enforce_inactivity_timeout()` in
app.py for the full reasoning.

Seams under test:
  - idle past the configured window -> 401, and the session is actually
    cleared (not just short-circuited for one request).
  - a fresh/active session is accepted.
  - a state-changing request (POST) slides the window forward.
  - a plain GET does NOT slide the window forward — the polling trap.
  - the check also gates /api/events (the SSE stream), without opening it
    counting as activity either.
  - Flask's absolute permanent_session_lifetime still applies independently,
    even when the idle marker is fresh.

Every test patches `_inactivity_timeout_seconds()` directly rather than going
through app_settings/env, so the window is a known, fixed value independent
of both the real clock and whatever a developer's local .env happens to say.
"""
import os
import sys
import time
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _ActivityOnlyCursor:
    """Ignores whatever query it's handed.

    Enough to exercise routes that touch the DB in passing (log_activity's
    INSERT, the 2FA-secret UPDATE) without pulling in a full admin_users
    fixture — none of these tests care what those queries do, only whether
    the request as a whole is accepted or rejected before it gets that far.
    """

    def execute(self, query, params=()):
        return None

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    @property
    def rowcount(self):
        return 0


class _ActivityOnlyConn:
    def cursor(self, dictionary=False):
        return _ActivityOnlyCursor()

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _iso(dt):
    return dt.isoformat()


class InactivityTimeoutTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=_ActivityOnlyConn())
        self.get_db_patch.start()
        self.addCleanup(self.get_db_patch.stop)
        # Fixed 15-minute window, independent of app_settings/env — see module docstring.
        self.timeout_patch = mock.patch.object(app_module, "_inactivity_timeout_seconds", return_value=900)
        self.timeout_patch.start()
        self.addCleanup(self.timeout_patch.stop)
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def _seed_admin_session(self, last_activity_ago=None, csrf_token="tok"):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_id"] = 1
            sess["admin_name"] = "Ops Admin"
            sess["csrf_token"] = csrf_token
            if last_activity_ago is not None:
                sess["last_activity_at"] = _iso(datetime.utcnow() - last_activity_ago)

    # ── idle past the window ──────────────────────────────────────────
    def test_idle_past_the_window_is_rejected(self):
        """A session whose last activity is older than the configured window
        is rejected outright, before the view (or even @admin_required) runs
        — a replayed/stolen cookie nobody has touched in 16 minutes is dead,
        regardless of what client-side JS would have done."""
        self._seed_admin_session(last_activity_ago=timedelta(minutes=16))
        resp = self.client.get("/api/admin/session-info")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("inactivity", resp.get_json()["error"].lower())

    def test_expiry_clears_the_session(self):
        """Expiry actually clears the session rather than just answering 401
        once — a follow-up request gets the ordinary "no session" 401 an
        anonymous caller would (admin_required's own message), proving
        session.clear() really ran and this isn't merely a one-off block."""
        self._seed_admin_session(last_activity_ago=timedelta(minutes=16))
        first = self.client.get("/api/admin/session-info")
        self.assertEqual(first.status_code, 401)
        second = self.client.get("/api/admin/session-info")
        self.assertEqual(second.status_code, 401)
        self.assertEqual(second.get_json()["error"], "Unauthorized")

    def test_fresh_session_within_the_window_is_accepted(self):
        self._seed_admin_session(last_activity_ago=timedelta(minutes=5))
        resp = self.client.get("/api/admin/session-info")
        self.assertEqual(resp.status_code, 200)

    # ── sliding window ─────────────────────────────────────────────────
    def test_a_state_changing_request_slides_the_window_forward(self):
        """The core of the fix: activity (here, an authenticated POST) refreshes
        the marker, so a session that would otherwise expire by minute 16 is
        still alive at effective minute 24, because something reset the clock
        at minute 10."""
        self._seed_admin_session(last_activity_ago=timedelta(minutes=10))
        # Something happens at minute 10 — a real, state-changing admin action.
        resp = self.client.post("/api/admin/2fa/setup", headers={"X-CSRF-Token": "tok"})
        self.assertEqual(resp.status_code, 200)

        # Wind the refreshed marker back by 14 minutes instead of sleeping:
        # 14 minutes past a marker the POST just reset is still inside the
        # 15-minute window, whereas 14 minutes past the *original* minute-10
        # marker would not be (10 + 14 = 24 > 15) — this only passes if the
        # POST actually moved the marker forward.
        with self.client.session_transaction() as sess:
            refreshed = datetime.fromisoformat(sess["last_activity_at"])
            sess["last_activity_at"] = _iso(refreshed - timedelta(minutes=14))

        resp2 = self.client.get("/api/admin/session-info")
        self.assertEqual(resp2.status_code, 200)

    def test_a_pure_get_does_not_slide_the_window(self):
        """The polling trap. dashboard.html/admin.html poll read-only GET
        endpoints (session-info itself, /api/user/session, /api/events and
        what its onmessage handlers fetch) on timers unrelated to whether a
        human is present. If a GET refreshed the marker, an abandoned-but-open
        tab would never idle out. Prove the opposite: repeatedly GETting
        session-info does NOT push the expiry further out."""
        self._seed_admin_session(last_activity_ago=timedelta(minutes=10))

        # Poll it several times, the way an open browser tab would.
        for _ in range(3):
            r = self.client.get("/api/admin/session-info")
            self.assertEqual(r.status_code, 200)

        # Wind the marker back by 6 more minutes (10 + 6 = 16 > 15): if any of
        # the GETs above had refreshed last_activity_at, this would still read
        # as fresh. It must not.
        with self.client.session_transaction() as sess:
            marker = datetime.fromisoformat(sess["last_activity_at"])
            sess["last_activity_at"] = _iso(marker - timedelta(minutes=6))

        resp = self.client.get("/api/admin/session-info")
        self.assertEqual(resp.status_code, 401)

    # ── /api/events (SSE) ───────────────────────────────────────────────
    def test_sse_endpoint_is_gated_by_the_same_check(self):
        """/api/events is the long-lived SSE stream dashboard.html/admin.html
        keep open. An idle-expired session must not be able to open it either
        — the content-free sync ping is harmless, but the connection itself
        must not be handed to a session that should already be dead."""
        self._seed_admin_session(last_activity_ago=timedelta(minutes=20))
        resp = self.client.get("/api/events")
        self.assertEqual(resp.status_code, 401)

    def test_opening_the_sse_stream_does_not_slide_the_window(self):
        """The other half of the polling trap: opening /api/events (a GET)
        must not itself extend the session, or an open tab's live connection
        alone would keep it alive forever."""
        self._seed_admin_session(last_activity_ago=timedelta(minutes=10))
        r = self.client.get("/api/events")
        self.assertEqual(r.status_code, 200)
        r.close()

        with self.client.session_transaction() as sess:
            marker = datetime.fromisoformat(sess["last_activity_at"])
            sess["last_activity_at"] = _iso(marker - timedelta(minutes=6))  # 10 + 6 = 16 > 15

        resp = self.client.get("/api/admin/session-info")
        self.assertEqual(resp.status_code, 401)

    # ── absolute lifetime is untouched ──────────────────────────────────
    def test_absolute_session_lifetime_still_applies_independent_of_activity(self):
        """The idle check is the *inner* bound; Flask's signed-cookie
        app.permanent_session_lifetime (itsdangerous max_age) is the *outer*
        one and this fix does not touch it. Simulate it lapsing by moving
        itsdangerous's own clock forward past that lifetime while
        last_activity_at is deliberately kept fresh — proving the absolute
        cap fires on its own, not via anything the idle check does."""
        self._seed_admin_session(last_activity_ago=timedelta(seconds=1))
        self.assertEqual(self.client.get("/api/admin/session-info").status_code, 200)

        real_time = time.time
        lifetime = self.app_module.app.permanent_session_lifetime.total_seconds()
        with mock.patch("itsdangerous.timed.time.time", return_value=real_time() + lifetime + 60):
            resp = self.client.get("/api/admin/session-info")
        self.assertEqual(resp.status_code, 401)
        # admin_required's own message, not the inactivity one: the signed
        # cookie failed to decode at all, so this hook never saw is_admin set.
        self.assertEqual(resp.get_json()["error"], "Unauthorized")


if __name__ == "__main__":
    unittest.main()

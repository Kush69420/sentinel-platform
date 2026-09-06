"""Integration tests for the email_lookup module's app.py wiring.

sentinel_modules/gaia_resolver.py, sentinel_modules/google_osint.py and
sentinel_modules/serpapi_fallback.py each have their own unit tests
(tests/test_gaia_resolver.py, tests/test_google_osint.py,
tests/test_serpapi_fallback.py) that mock at the HTTP/DB boundary inside
each module — this file does not repeat that. It covers only the app.py
layer on top of them:

  * run_tool_generic()'s `code == "email_lookup"` branch (credit charging,
    audit logging, the primary-OSINT / SerpApi-fallback chain).
  * mobile_lookup_report_pdf()'s dispatch to the email_lookup re-fetch path.
  * _fetch_remote_image_safe(), the SSRF guard used when embedding a Google
    profile photo into the PDF report.
  * the two admin health/usage routes that wrap gaia_resolver.health_check()
    and serpapi_fallback.check_quota().

The three sentinel_modules functions/exceptions are mocked at the
app.py-imported-name boundary (app.py does `import sentinel_modules.gaia_resolver
as gaia_resolver`, etc.), i.e. `mock.patch.object(app_module.gaia_resolver,
"resolve_gaia", ...)` — mirrors how tests/test_mobile_lookup_credits.py patches
`app_module._http_json`.

Uses distinct bot_users ids (501/502) from test_mobile_lookup_credits.py's
(1/2): app.py's in-process `_rate_limiter` is a module-level singleton keyed
by `f"{endpoint_name}:user:{user_id}"`, shared across every test file in the
same pytest process. Reusing user id 1 against the same `run_tool_generic`
endpoint that test_mobile_lookup_credits.py (and its
MobileNumberNormalizationTests subclass, which reruns all of its parent's
tests) already exercises ~25+ times would risk tripping the 30-requests/60s
cap and producing flaky 429s unrelated to anything under test here.
"""
import os
import sys
import socket
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────
# Fake DB layer for run_tool_generic()'s email_lookup branch
# ─────────────────────────────────────────────
class FakeCursor:
    def __init__(self, db, dictionary=False):
        self.db = db
        self.dictionary = dictionary
        self._result = []
        self.rowcount = 0
        self.lastrowid = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = []
        self.rowcount = 0

        if q.startswith("SELECT * FROM services WHERE code=%s"):
            svc = self.db["services"].get(params[0])
            self._result = [dict(svc)] if svc else []

        elif q.startswith("SELECT id, phone, name, department, official_email, credits, status,"):
            # load_current_user(): called both by @verified_required (its own
            # fresh db_conn()) and again inside run_tool_generic() itself
            # (passed the route's own cursor) — same query text either way.
            u = self.db["bot_users"].get(params[0])
            self._result = [dict(u)] if u else []

        elif q.startswith("UPDATE bot_users SET credits = credits - %s WHERE id=%s AND credits >= %s"):
            amount, user_id, required = params
            u = self.db["bot_users"].get(user_id)
            if u and u["credits"] >= required:
                u["credits"] -= amount
                self.rowcount = 1
            else:
                self.rowcount = 0

        elif q.startswith("INSERT INTO credit_transactions"):
            phone, amount, reason = params
            self.db["credit_transactions"].append(
                {"id": len(self.db["credit_transactions"]) + 1, "phone": phone, "type": "debit",
                 "amount": amount, "reason": reason, "status": "success", "created_at": None}
            )

        elif q.startswith("INSERT INTO search_logs"):
            user_id, phone, search_type, query_value, case_reference, credits_used, source = params
            self.db["search_logs"].append(
                {"user_id": user_id, "phone": phone, "search_type": search_type, "query_value": query_value,
                 "case_reference": case_reference, "credits_used": credits_used, "sources_queried": source}
            )
            self.lastrowid = len(self.db["search_logs"])

        else:
            raise AssertionError(f"FakeCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class FakeConn:
    def __init__(self, db):
        self.db = db
        self.committed = False
        self.rolled_back = False

    def cursor(self, dictionary=False):
        return FakeCursor(self.db, dictionary=dictionary)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


def make_db():
    return {
        "bot_users": {
            501: {"id": 501, "phone": "7000000001", "name": "Officer Email One", "department": "Cyber",
                  "official_email": "email-one@police.gov.in", "credits": 5, "status": "approved",
                  "verification_status": "approved", "twofa_enabled": 0},
            502: {"id": 502, "phone": "7000000002", "name": "Officer Email Two", "department": "Cyber",
                  "official_email": "email-two@police.gov.in", "credits": 1, "status": "approved",
                  "verification_status": "approved", "twofa_enabled": 0},
        },
        # credits_per_use=2, is_free=0, sort_order=2 match db_setup.sql's real
        # email_lookup seed row exactly; status='enabled'/is_enabled=1 match
        # what migration_email_lookup.sql flips it to on go-live.
        "services": {
            "email_lookup": {"code": "email_lookup", "credits_per_use": 2, "is_free": 0,
                              "is_enabled": 1, "maintenance_mode": 0, "status": "enabled"},
        },
        "credit_transactions": [],
        "search_logs": [],
    }


def _profile(with_review=True):
    """A profile dict shaped like google_osint.fetch_profile_and_reviews()'s
    (and serpapi_fallback's, same shape) return value."""
    reviews = []
    if with_review:
        reviews.append({
            "business_name": "Cafe Test", "business_address": "1 Test Street",
            "maps_url": "https://www.google.com/maps?cid=123",
            "date": datetime(2026, 8, 1, 10, 30, 0, tzinfo=timezone.utc),
            "comment": "Great coffee", "lat": 12.34, "lon": 56.78,
        })
    return {
        "display_name": "Jane Doe", "photo_url": "https://lh3.googleusercontent.com/photo.jpg",
        "total_reviews": 7, "reviews": reviews,
    }


class RunToolGenericEmailLookupTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_db()
        self.fake_conn = FakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    CSRF_TOKEN = "test-csrf-token"
    CSRF_HEADERS = {"X-CSRF-Token": CSRF_TOKEN}

    def _login(self, user_id=501, phone="7000000001"):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = user_id
            sess["user_phone"] = phone
            sess["csrf_token"] = self.CSRF_TOKEN

    def _post(self, query, case_reference=""):
        return self.client.post(
            "/api/tools/run",
            json={"code": "email_lookup", "query": query, "case_reference": case_reference},
            headers=self.CSRF_HEADERS)

    # ---- 1. Malformed email shape ----
    def test_malformed_email_is_400_and_costs_nothing(self):
        self._login()
        resp = self._post("not-an-email")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json().get("reason"), "invalid_query")
        self.assertEqual(self.db["bot_users"][501]["credits"], 5)
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(self.db["search_logs"], [])

    # ---- 2. GAIA resolves, no Google account found ----
    def test_no_match_is_logged_but_not_charged(self):
        self._login()
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=None):
            resp = self._post("nogoogleaccount@example.com")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json().get("reason"), "no_match")
        self.assertEqual(self.db["bot_users"][501]["credits"], 5)  # untouched
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["credits_used"], 0)
        self.assertEqual(log["sources_queried"], "No match")
        self.assertEqual(log["query_value"], "nogoogleaccount@example.com")

    # ---- 3. GAIA resolution raises GaiaResolverCredentialError ----
    def test_credential_error_returns_502_and_writes_no_log(self):
        self._login()
        err = self.app_module.gaia_resolver.GaiaResolverCredentialError("master token dead")
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", side_effect=err):
            resp = self._post("someone@example.com")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.get_json().get("reason"), "credential_error")
        # Confirmed against app.py: this branch returns before any db_conn()
        # use at all (unlike the "no_match" case above) — no search_logs
        # write, no credit_transactions write, nothing charged.
        self.assertEqual(self.db["search_logs"], [])
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(self.db["bot_users"][501]["credits"], 5)

    # ---- 4. Primary path succeeds ----
    def test_primary_path_success_charges_and_logs(self):
        self._login()
        gaia = {"gaia_id": "112233445566778899", "cached": False}
        profile = _profile(with_review=True)
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", return_value=profile) as m_osint:
            resp = self._post("jane@example.com", case_reference="FIR-EMAIL-1")
        self.assertEqual(m_osint.call_count, 1)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["credits_charged"], 2)
        self.assertEqual(body["credits_remaining"], 3)  # 5 - 2
        self.assertEqual(body["search_log_id"], 1)
        result = body["results"][0]
        self.assertEqual(result["source"], "Google OSINT")
        data = result["data"]
        self.assertEqual(set(data.keys()), {"display_name", "photo_url", "total_reviews", "reviews"})
        self.assertEqual(data["display_name"], "Jane Doe")
        self.assertEqual(data["total_reviews"], 7)
        # The datetime object in the mocked profile must have been converted
        # to an isoformat string — a raw datetime would fail jsonify().
        self.assertEqual(data["reviews"][0]["date"], "2026-08-01T10:30:00+00:00")
        self.assertIsInstance(data["reviews"][0]["date"], str)

        self.assertEqual(self.db["bot_users"][501]["credits"], 3)
        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["credit_transactions"][0]["amount"], 2)
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["credits_used"], 2)
        self.assertEqual(log["sources_queried"], "Google OSINT")
        self.assertEqual(log["case_reference"], "FIR-EMAIL-1")
        self.assertEqual(log["query_value"], "jane@example.com")

    # ---- 5. Primary raises GoogleOsintError, fallback succeeds ----
    def test_fallback_to_serpapi_success_charges_and_logs(self):
        self._login()
        gaia = {"gaia_id": "112233445566778899", "cached": True}
        profile = _profile(with_review=False)
        osint_err = self.app_module.google_osint.GoogleOsintError("status-3, gave up after retry")
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", side_effect=osint_err), \
             mock.patch.object(self.app_module.serpapi_fallback, "fetch_profile_and_reviews_via_serpapi",
                                return_value=profile) as m_serp:
            resp = self._post("jane@example.com")
        self.assertEqual(m_serp.call_count, 1)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["results"][0]["source"], "SerpApi (fallback)")
        self.assertEqual(body["credits_charged"], 2)
        self.assertEqual(self.db["bot_users"][501]["credits"], 3)
        self.assertEqual(len(self.db["credit_transactions"]), 1)
        self.assertEqual(self.db["search_logs"][0]["sources_queried"], "SerpApi (fallback)")
        self.assertEqual(self.db["search_logs"][0]["credits_used"], 2)

    def _both_fail(self, serpapi_side_effect):
        self._login()
        gaia = {"gaia_id": "112233445566778899", "cached": True}
        osint_err = self.app_module.google_osint.GoogleOsintError("status-3")
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", side_effect=osint_err), \
             mock.patch.object(self.app_module.serpapi_fallback, "fetch_profile_and_reviews_via_serpapi",
                                side_effect=serpapi_side_effect):
            return self._post("jane@example.com")

    # ---- 6a. Both fail: SerpApi quota exceeded ----
    def test_both_fail_quota_exceeded_is_uncharged_but_logged(self):
        err = self.app_module.serpapi_fallback.SerpApiQuotaExceededError("250/250 used this month")
        resp = self._both_fail(err)
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json().get("reason"), "quota_exceeded")
        self.assertEqual(self.db["bot_users"][501]["credits"], 5)  # untouched
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["credits_used"], 0)
        self.assertEqual(log["sources_queried"], "Lookup failed")

    # ---- 6b. Both fail: generic SerpApiError ----
    def test_both_fail_generic_serpapi_error_is_uncharged_but_logged(self):
        err = self.app_module.serpapi_fallback.SerpApiError("SERPAPI_KEY not configured")
        resp = self._both_fail(err)
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.get_json().get("reason"), "lookup_failed")
        self.assertEqual(self.db["bot_users"][501]["credits"], 5)
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(len(self.db["search_logs"]), 1)
        log = self.db["search_logs"][0]
        self.assertEqual(log["credits_used"], 0)
        self.assertEqual(log["sources_queried"], "Lookup failed")

    # ---- 6c. InsufficientCredits at the charge step ----
    def test_credits_drained_during_lookup_returns_402_and_does_not_overspend(self):
        """Mirrors test_mobile_lookup_credits.py's
        test_race_lost_between_check_and_deduct_returns_402_and_does_not_overspend,
        adapted to this branch's structure: mobile_lookup's race window sits
        between a pre-flight balance read and the atomic UPDATE, with a real
        SQL query (the subscriber_records SELECT) executing in between that
        test hooks to drain the balance. email_lookup's equivalent window is
        between the same pre-flight read and the same atomic UPDATE, but
        nothing SQL-shaped runs in between — only the mocked external
        gaia_resolver/google_osint calls do. So the drain is injected as a
        side_effect on the mocked fetch_profile_and_reviews call instead of
        via a FakeCursor.execute() hook: functionally the same "concurrent
        request drains the balance while this one is in flight" scenario,
        exercising the same `UPDATE ... WHERE credits >= %s` guard in
        charge_for_lookup().
        """
        self._login()
        gaia = {"gaia_id": "112233445566778899", "cached": True}
        profile = _profile(with_review=False)

        def draining_fetch(gaia_id):
            self.db["bot_users"][501]["credits"] = 0  # concurrent request drains it first
            return profile

        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", side_effect=draining_fetch):
            resp = self._post("jane@example.com")
        self.assertEqual(resp.status_code, 402)
        body = resp.get_json()
        self.assertEqual(body.get("reason"), "insufficient_credits")
        self.assertEqual(body.get("credits_required"), 2)
        self.assertEqual(self.db["bot_users"][501]["credits"], 0)
        # The UPDATE's rowcount!=1 guard raises before either INSERT is ever
        # reached, so neither the ledger nor the audit trail gets a row here.
        self.assertEqual(self.db["credit_transactions"], [])
        self.assertEqual(self.db["search_logs"], [])


# ─────────────────────────────────────────────
# Fake DB layer for mobile_lookup_report_pdf()'s email_lookup dispatch
# ─────────────────────────────────────────────
class PdfFakeCursor:
    def __init__(self, db, dictionary=False):
        self.db = db
        self.dictionary = dictionary
        self._result = []

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = []
        if q.startswith("SELECT * FROM search_logs WHERE id=%s AND user_id=%s"):
            log_id, user_id = params
            row = self.db["search_logs"].get(log_id)
            self._result = [dict(row)] if row and row["user_id"] == user_id else []
        else:
            # Deliberately narrow: if charge_for_lookup() (or anything else
            # DB-touching) ever runs on this path, it hits an UPDATE/INSERT
            # this fake doesn't implement and fails loudly here rather than
            # silently recording a phantom charge.
            raise AssertionError(f"PdfFakeCursor got an unexpected query: {q!r}")

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return self._result


class PdfFakeConn:
    def __init__(self, db):
        self.db = db

    def cursor(self, dictionary=False):
        return PdfFakeCursor(self.db, dictionary=dictionary)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def make_pdf_db():
    return {
        "search_logs": {
            1: {
                "id": 1, "user_id": 501, "phone": "7000000001", "search_type": "email_lookup",
                "query_value": "jane@example.com", "case_reference": "FIR-EMAIL-9",
                "credits_used": 2, "sources_queried": "Google OSINT",
                "created_at": datetime(2026, 8, 10, 12, 0, 0),
            },
            2: {
                "id": 2, "user_id": 999, "phone": "7000099999", "search_type": "email_lookup",
                "query_value": "other@example.com", "case_reference": None,
                "credits_used": 2, "sources_queried": "Google OSINT",
                "created_at": datetime(2026, 8, 10, 12, 5, 0),
            },
            3: {
                "id": 3, "user_id": 501, "phone": "7000000001", "search_type": "email_lookup",
                "query_value": "absent@example.com", "case_reference": None,
                "credits_used": 0, "sources_queried": "No match",
                "created_at": datetime(2026, 8, 10, 12, 10, 0),
            },
        },
    }


class EmailLookupPdfReportTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.db = make_pdf_db()
        self.fake_conn = PdfFakeConn(self.db)
        self.get_db_patch = mock.patch.object(app_module, "get_db", return_value=self.fake_conn)
        self.get_db_patch.start()
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.get_db_patch.stop()

    def _login(self, user_id=501):
        with self.client.session_transaction() as sess:
            sess["is_user"] = True
            sess["user_id"] = user_id
            sess["user_name"] = "Operator Email"
            sess["user_department"] = "Cyber Cell"

    # ---- 1. Ownership scoping (existing mobile_lookup pattern — not
    # duplicated exhaustively, this checks it still applies to email_lookup
    # rows since the scoping happens before the search_type dispatch) ----
    def test_foreign_search_log_returns_404(self):
        self._login(user_id=501)  # log 2 belongs to user_id 999
        resp = self.client.get("/api/tools/run/report/pdf/2")
        self.assertEqual(resp.status_code, 404)

    # Pre-existing "no match" 400 check (before search_type dispatch) still
    # applies to email_lookup rows.
    def test_no_match_row_is_rejected_for_email_lookup_too(self):
        self._login(user_id=501)
        resp = self.client.get("/api/tools/run/report/pdf/3")
        self.assertEqual(resp.status_code, 400)

    # ---- 2. search_type == "email_lookup" re-runs the live fetch ----
    def test_rerun_returns_pdf_and_charges_nothing(self):
        self._login(user_id=501)
        gaia = {"gaia_id": "112233445566778899", "cached": True}
        profile = _profile(with_review=True)
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", return_value=profile), \
             mock.patch.object(self.app_module, "charge_for_lookup") as m_charge:
            resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/pdf")
        self.assertTrue(resp.data.startswith(b"%PDF"))
        self.assertIn("attachment; filename=sentinel_email_lookup_1.pdf", resp.headers["Content-Disposition"])
        m_charge.assert_not_called()
        # No new search_logs row either: PdfFakeCursor only implements the
        # single ownership-scoped SELECT, so any attempted INSERT would have
        # raised AssertionError above rather than silently succeeding.

    def test_rerun_calls_build_pdf_with_log_and_profile_including_gaia_id(self):
        self._login(user_id=501)
        gaia = {"gaia_id": "gaia-xyz-789", "cached": False}
        profile = _profile(with_review=False)
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", return_value=profile), \
             mock.patch.object(self.app_module, "_build_email_lookup_pdf", return_value=b"%PDF-fake") as m_build:
            resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, b"%PDF-fake")
        m_build.assert_called_once()
        called_log, called_profile = m_build.call_args[0]
        self.assertEqual(called_log["id"], 1)
        self.assertEqual(called_log["query_value"], "jane@example.com")
        self.assertEqual(called_profile["gaia_id"], "gaia-xyz-789")
        self.assertEqual(called_profile["display_name"], "Jane Doe")

    def test_rerun_credential_error_returns_502(self):
        self._login(user_id=501)
        err = self.app_module.gaia_resolver.GaiaResolverCredentialError("master token dead")
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", side_effect=err):
            resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.get_json().get("reason"), "credential_error")

    def test_rerun_gaia_no_longer_resolves_returns_502(self):
        self._login(user_id=501)
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=None):
            resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.get_json().get("reason"), "no_match")

    def test_rerun_fallback_to_serpapi_success(self):
        self._login(user_id=501)
        gaia = {"gaia_id": "112233445566778899", "cached": True}
        profile = _profile(with_review=False)
        osint_err = self.app_module.google_osint.GoogleOsintError("status-3")
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", side_effect=osint_err), \
             mock.patch.object(self.app_module.serpapi_fallback, "fetch_profile_and_reviews_via_serpapi",
                                return_value=profile):
            resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data.startswith(b"%PDF"))

    def test_rerun_both_fail_quota_exceeded_returns_503(self):
        self._login(user_id=501)
        gaia = {"gaia_id": "112233445566778899", "cached": True}
        osint_err = self.app_module.google_osint.GoogleOsintError("status-3")
        quota_err = self.app_module.serpapi_fallback.SerpApiQuotaExceededError("250/250 used")
        with mock.patch.object(self.app_module.gaia_resolver, "resolve_gaia", return_value=gaia), \
             mock.patch.object(self.app_module.google_osint, "fetch_profile_and_reviews", side_effect=osint_err), \
             mock.patch.object(self.app_module.serpapi_fallback, "fetch_profile_and_reviews_via_serpapi",
                                side_effect=quota_err):
            resp = self.client.get("/api/tools/run/report/pdf/1")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json().get("reason"), "quota_exceeded")


# ─────────────────────────────────────────────
# _fetch_remote_image_safe() — SSRF guard
# ─────────────────────────────────────────────
class FetchRemoteImageSafeTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module

    def _addrinfo(self, ip, port=443):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    def test_private_ip_returns_none_and_makes_no_request(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("10.0.0.1")), \
             mock.patch.object(self.app_module.requests, "get") as m_get:
            result = self.app_module._fetch_remote_image_safe("https://example.com/photo.jpg")
        self.assertIsNone(result)
        m_get.assert_not_called()

    def test_loopback_ip_returns_none(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("127.0.0.1")), \
             mock.patch.object(self.app_module.requests, "get") as m_get:
            result = self.app_module._fetch_remote_image_safe("https://example.com/photo.jpg")
        self.assertIsNone(result)
        m_get.assert_not_called()

    def test_cloud_metadata_ip_returns_none(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("169.254.169.254")), \
             mock.patch.object(self.app_module.requests, "get") as m_get:
            result = self.app_module._fetch_remote_image_safe("https://example.com/latest/meta-data/")
        self.assertIsNone(result)
        m_get.assert_not_called()

    def test_non_https_scheme_returns_none_before_dns_resolution(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo") as m_dns, \
             mock.patch.object(self.app_module.requests, "get") as m_get:
            result = self.app_module._fetch_remote_image_safe("http://example.com/photo.jpg")
        self.assertIsNone(result)
        m_dns.assert_not_called()
        m_get.assert_not_called()

        with mock.patch.object(self.app_module.socket, "getaddrinfo") as m_dns2, \
             mock.patch.object(self.app_module.requests, "get") as m_get2:
            result2 = self.app_module._fetch_remote_image_safe("ftp://example.com/photo.jpg")
        self.assertIsNone(result2)
        m_dns2.assert_not_called()
        m_get2.assert_not_called()

    def test_oversized_response_stops_reading_and_returns_none(self):
        chunk = b"x" * (3 * 1024 * 1024)  # 3 MB

        def iter_content(chunk_size=65536):
            yield chunk  # total 3 MB, under the 5 MB cap
            yield chunk  # total 6 MB, exceeds the cap here
            raise RuntimeError("must not be reached — cap should have stopped iteration")

        resp = mock.Mock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "image/jpeg"}
        resp.iter_content = iter_content
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("93.184.216.34")), \
             mock.patch.object(self.app_module.requests, "get", return_value=resp):
            result = self.app_module._fetch_remote_image_safe("https://example.com/big.jpg")
        self.assertIsNone(result)

    def test_wrong_content_type_returns_none(self):
        resp = mock.Mock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        resp.iter_content = lambda chunk_size=65536: iter([b"<html></html>"])
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("93.184.216.34")), \
             mock.patch.object(self.app_module.requests, "get", return_value=resp):
            result = self.app_module._fetch_remote_image_safe("https://example.com/notanimage")
        self.assertIsNone(result)

    def test_redirects_not_followed(self):
        resp = mock.Mock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "image/png"}
        resp.iter_content = lambda chunk_size=65536: iter([b"\x89PNG"])
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("93.184.216.34")), \
             mock.patch.object(self.app_module.requests, "get", return_value=resp) as m_get:
            self.app_module._fetch_remote_image_safe("https://example.com/photo.png")
        self.assertEqual(m_get.call_count, 1)
        _, kwargs = m_get.call_args
        self.assertIs(kwargs.get("allow_redirects"), False)

    def test_clean_success_returns_bytes(self):
        body = b"\x89PNG\r\n\x1a\nfakepngdata"
        resp = mock.Mock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "image/png"}
        resp.iter_content = lambda chunk_size=65536: iter([body])
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("93.184.216.34")), \
             mock.patch.object(self.app_module.requests, "get", return_value=resp):
            result = self.app_module._fetch_remote_image_safe("https://example.com/photo.png")
        self.assertEqual(result, body)

    def test_dns_resolution_failure_returns_none(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo", side_effect=socket.gaierror("no such host")), \
             mock.patch.object(self.app_module.requests, "get") as m_get:
            result = self.app_module._fetch_remote_image_safe("https://nonexistent.invalid/photo.jpg")
        self.assertIsNone(result)
        m_get.assert_not_called()

    def test_connection_exception_during_fetch_returns_none_not_raises(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("93.184.216.34")), \
             mock.patch.object(self.app_module.requests, "get",
                                side_effect=self.app_module.requests.exceptions.ConnectionError("refused")):
            result = self.app_module._fetch_remote_image_safe("https://example.com/photo.jpg")
        self.assertIsNone(result)

    def test_timeout_during_fetch_returns_none_not_raises(self):
        with mock.patch.object(self.app_module.socket, "getaddrinfo",
                                return_value=self._addrinfo("93.184.216.34")), \
             mock.patch.object(self.app_module.requests, "get",
                                side_effect=self.app_module.requests.exceptions.Timeout("timed out")):
            result = self.app_module._fetch_remote_image_safe("https://example.com/photo.jpg")
        self.assertIsNone(result)


# ─────────────────────────────────────────────
# Admin health/usage routes
# ─────────────────────────────────────────────
class AdminEmailLookupRoutesTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def _login_admin(self):
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True

    def test_serpapi_usage_requires_admin(self):
        resp = self.client.get("/api/admin/serpapi-usage")
        self.assertEqual(resp.status_code, 401)

    def test_serpapi_usage_success(self):
        self._login_admin()
        status = {"year_month": "2026-09", "request_count": 10, "limit": 250}
        with mock.patch.object(self.app_module.serpapi_fallback, "check_quota", return_value=status):
            resp = self.client.get("/api/admin/serpapi-usage")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["used"], 10)
        self.assertEqual(body["limit"], 250)
        self.assertEqual(body["period"], "2026-09")
        self.assertIsNone(body["error"])

    def test_serpapi_usage_failure_mode_returns_200_not_500(self):
        self._login_admin()
        with mock.patch.object(self.app_module.serpapi_fallback, "check_quota",
                                side_effect=Exception("db unreachable")):
            resp = self.client.get("/api/admin/serpapi-usage")
        # Defensive-by-design: a broken check must surface as a red/error
        # indicator in the JSON body, never as a 500.
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("db unreachable", body["error"])

    def test_google_credential_health_requires_admin(self):
        resp = self.client.get("/api/admin/google-credential-health")
        self.assertEqual(resp.status_code, 401)

    def test_google_credential_health_success(self):
        self._login_admin()
        health = {"ok": True, "checked_at": "2026-09-05T00:00:00+00:00", "error": None}
        with mock.patch.object(self.app_module.gaia_resolver, "health_check", return_value=health):
            resp = self.client.get("/api/admin/google-credential-health")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertIsNone(body["error"])

    def test_google_credential_health_failure_mode_returns_200_not_500(self):
        self._login_admin()
        with mock.patch.object(self.app_module.gaia_resolver, "health_check",
                                side_effect=Exception("token dead")):
            resp = self.client.get("/api/admin/google-credential-health")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("token dead", body["error"])


if __name__ == "__main__":
    unittest.main()

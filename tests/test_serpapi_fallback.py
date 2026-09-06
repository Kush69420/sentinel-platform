"""sentinel_modules/serpapi_fallback.py — paid SerpApi fallback for Step B
of the email_lookup module (GAIA id -> public Google Maps profile + reviews).

Offline only: every HTTP call is mocked (patched `requests.get`) and the
database is an in-memory fake cursor/connection (patched `app.db_conn`),
mirroring the fake-DB pattern in tests/test_gaia_resolver.py and the
fake-HTTP-response pattern in tests/test_google_osint.py. No real network or
real database calls happen anywhere in this file.

What matters most here, mirroring the module's own emphasis:

  * the quota reservation is atomic and happens BEFORE any HTTP call —
    an exhausted quota must never place a billed request
  * a missing SERPAPI_KEY fails closed with a clear error, before touching
    either the database or the network
  * a non-200 response or a JSON body containing an "error" key are both
    treated as a hard failure, uniformly
  * one malformed review is skipped, never crashes the batch
  * an unparseable review date is kept in a "date_raw" fallback field
    instead of being silently dropped or crashing the parse
"""
import contextlib
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402  (FLASK_ENV set by tests/__init__ first)
from sentinel_modules import serpapi_fallback  # noqa: E402

TEST_GAIA_ID = "111544054649252019208"


# ─────────────────────────────────────────────
# Fake DB — mirrors app.get_db()/db_conn() shape closely enough for the
# quota table's three query shapes: guarded UPDATE, INSERT IGNORE, plain
# SELECT (get_quota_status).
# ─────────────────────────────────────────────
class _FakeCursor:
    def __init__(self, db):
        self.db = db
        self.rowcount = 0
        self._result = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        self._result = None

        if q.startswith("UPDATE serpapi_usage_quota SET request_count = request_count + 1"):
            year_month, limit = params
            row = self.db["quota"].get(year_month)
            self.db["update_calls"] += 1
            if row is not None and row["request_count"] < limit:
                row["request_count"] += 1
                self.rowcount = 1
            else:
                self.rowcount = 0

        elif q.startswith("INSERT IGNORE INTO serpapi_usage_quota"):
            (year_month,) = params
            self.db["insert_ignore_calls"] += 1
            if year_month not in self.db["quota"]:
                self.db["quota"][year_month] = {"request_count": 0}
            self.rowcount = 1

        elif q.startswith("SELECT request_count FROM serpapi_usage_quota WHERE `year_month`=%s"):
            (year_month,) = params
            row = self.db["quota"].get(year_month)
            self._result = {"request_count": row["request_count"]} if row else None

        else:
            raise AssertionError(f"unexpected query in test fake: {q!r}")

    def fetchone(self):
        return self._result

    def close(self):
        pass


class _FakeConn:
    def __init__(self, db):
        self.db = db
        self.committed = False

    def cursor(self, dictionary=False):
        return _FakeCursor(self.db)

    def commit(self):
        self.committed = True

    def close(self):
        pass


def _new_fake_db(quota=None):
    return {
        "quota": quota or {},
        "update_calls": 0,
        "insert_ignore_calls": 0,
    }


def _db_conn_for(db):
    @contextlib.contextmanager
    def _db_conn():
        yield _FakeConn(db)

    return _db_conn


# ─────────────────────────────────────────────
# Fake HTTP response — mirrors test_google_osint.py's _make_response helper.
# ─────────────────────────────────────────────
def _make_response(body_text, status_code=200, force_chunk_size=None):
    resp = mock.Mock()
    resp.status_code = status_code
    body_bytes = body_text.encode("utf-8")

    def iter_content(chunk_size=65536):
        size = force_chunk_size or chunk_size
        for i in range(0, len(body_bytes), size):
            yield body_bytes[i : i + size]

    resp.iter_content = iter_content
    resp.close = mock.Mock()
    return resp


_SAMPLE_RESPONSE = {
    "contributor": {
        "name": "Jitendra Kumar Markam",
        "thumbnail": "https://lh3.googleusercontent.com/a/fake=s120",
        "points": 500,
        "level": 4,
        "local_guide": True,
        "contributions": {"reviews": 42, "ratings": 10, "photos": 3},
    },
    "reviews": [
        {
            "place_info": {
                "title": "Swaraj Tractors",
                "address": "Sector 5, Raipur, Chhattisgarh",
                "gps_coordinates": {"latitude": 21.2514, "longitude": 81.6296},
                "type": "Tractor dealer",
                "data_id": "0x123:0x456",
            },
            "date": "2026-08-02",
            "snippet": "Great service and fast delivery.",
            "review_id": "r1",
            "rating": 5,
            "likes": 2,
            "link": "https://www.google.com/maps/reviews/@21.25,81.62,data=abc",
        },
        {
            "place_info": {
                "title": "MMI Narayana Hospital",
                "address": "Baderajpur",
                "gps_coordinates": {"latitude": 21.1, "longitude": 81.5},
            },
            "date": "a month ago",
            "snippet": "Good doctors.",
            "review_id": "r2",
            "rating": 4,
            "likes": 0,
            "link": "http://not-https.example.com/maps",
        },
    ],
}


class SerpApiFallbackTestCase(unittest.TestCase):
    def setUp(self):
        self.db = _new_fake_db()
        self._patches = [
            mock.patch.object(app_module, "db_conn", _db_conn_for(self.db)),
            mock.patch.dict(os.environ, {"SERPAPI_KEY": "fake-serpapi-key"}),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def _patch_http(self, response_or_exc):
        p = mock.patch.object(
            serpapi_fallback.requests, "get",
            side_effect=[response_or_exc] if isinstance(response_or_exc, Exception) else None,
            return_value=None if isinstance(response_or_exc, Exception) else response_or_exc,
        )
        p.start()
        self.addCleanup(p.stop)
        return p

    # ── successful fetch + field mapping ──────────────────────────────
    def test_successful_fetch_and_field_mapping(self):
        resp = _make_response(json.dumps(_SAMPLE_RESPONSE))
        self._patch_http(resp)

        result = serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

        self.assertEqual(result["display_name"], "Jitendra Kumar Markam")
        self.assertEqual(result["photo_url"], "https://lh3.googleusercontent.com/a/fake=s120")
        self.assertEqual(result["total_reviews"], 42)
        self.assertEqual(len(result["reviews"]), 2)

        # Sorted newest-first: the ISO-dated review outranks the unparseable
        # "a month ago" one (which sorts as datetime.min).
        r1, r2 = result["reviews"]
        self.assertEqual(r1["business_name"], "Swaraj Tractors")
        self.assertEqual(r1["business_address"], "Sector 5, Raipur, Chhattisgarh")
        self.assertEqual(r1["comment"], "Great service and fast delivery.")
        self.assertAlmostEqual(r1["lat"], 21.2514)
        self.assertAlmostEqual(r1["lon"], 81.6296)
        self.assertIsInstance(r1["date"], datetime)
        self.assertEqual(r1["date"].tzinfo, timezone.utc)
        self.assertEqual(r1["date"], datetime(2026, 8, 2, tzinfo=timezone.utc))
        self.assertEqual(
            r1["maps_url"], "https://www.google.com/maps/reviews/@21.25,81.62,data=abc"
        )
        self.assertNotIn("date_raw", r1)

        # Second review: unparseable relative date -> None + date_raw kept;
        # non-https link -> maps_url dropped to None, not fabricated.
        self.assertEqual(r2["business_name"], "MMI Narayana Hospital")
        self.assertIsNone(r2["date"])
        self.assertEqual(r2["date_raw"], "a month ago")
        self.assertIsNone(r2["maps_url"])

        # Quota was reserved exactly once, before the (single) HTTP call.
        self.assertEqual(self.db["quota"][serpapi_fallback._current_year_month()]["request_count"], 1)

    # ── missing API key ────────────────────────────────────────────────
    def test_missing_api_key_raises_before_touching_db_or_network(self):
        os.environ.pop("SERPAPI_KEY", None)
        self._patch_http(_make_response("{}"))

        with self.assertRaises(serpapi_fallback.SerpApiError) as ctx:
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)
        self.assertIn("SERPAPI_KEY", str(ctx.exception))

        serpapi_fallback.requests.get.assert_not_called()
        self.assertEqual(self.db["quota"], {}, "must fail before reserving any quota")

    # ── non-200 / error response ───────────────────────────────────────
    def test_non_200_response_is_serpapi_error(self):
        self._patch_http(_make_response("{}", status_code=500))
        with self.assertRaises(serpapi_fallback.SerpApiError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)
        # Quota was still consumed — reserved before the call, not refunded.
        self.assertEqual(self.db["quota"][serpapi_fallback._current_year_month()]["request_count"], 1)

    def test_error_key_in_body_is_serpapi_error(self):
        self._patch_http(_make_response(json.dumps({"error": "Invalid API key."})))
        with self.assertRaises(serpapi_fallback.SerpApiError) as ctx:
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)
        self.assertIn("Invalid API key", str(ctx.exception))

    def test_non_json_response_is_serpapi_error(self):
        self._patch_http(_make_response("not actually json{{{"))
        with self.assertRaises(serpapi_fallback.SerpApiError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

    def test_non_object_json_response_is_serpapi_error(self):
        self._patch_http(_make_response(json.dumps([1, 2, 3])))
        with self.assertRaises(serpapi_fallback.SerpApiError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

    def test_network_error_is_serpapi_error(self):
        import requests as requests_module

        self._patch_http(requests_module.ConnectionError("boom"))
        with self.assertRaises(serpapi_fallback.SerpApiError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

    def test_response_size_cap_enforced(self):
        huge_body = json.dumps({"contributor": {}, "reviews": [{"snippet": "x" * 2000}] * 50})
        oversized = _make_response(huge_body, force_chunk_size=256)
        with mock.patch.object(serpapi_fallback, "_MAX_RESPONSE_BYTES", 1024):
            self._patch_http(oversized)
            with self.assertRaises(serpapi_fallback.SerpApiError):
                serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

    # ── malformed reviews are skipped, not crashed ──────────────────────
    def test_malformed_review_entries_are_skipped_not_crashed(self):
        body = {
            "contributor": {"name": "Someone"},
            "reviews": [
                None,
                "garbage",
                42,
                {"place_info": {}},  # no title, no snippet -> not review-shaped
                {"place_info": {"title": "Good Place"}, "snippet": "Nice.", "date": "2026-01-01"},
            ],
        }
        self._patch_http(_make_response(json.dumps(body)))
        result = serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)
        self.assertEqual(len(result["reviews"]), 1)
        self.assertEqual(result["reviews"][0]["business_name"], "Good Place")

    # ── input validation ────────────────────────────────────────────────
    def test_empty_gaia_id_raises_value_error(self):
        with self.assertRaises(ValueError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi("")

    def test_non_positive_max_reviews_raises_value_error(self):
        with self.assertRaises(ValueError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID, max_reviews=0)

    def test_max_reviews_is_capped_at_serpapi_hard_limit(self):
        resp = _make_response(json.dumps({"contributor": {}, "reviews": []}))
        self._patch_http(resp)
        serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID, max_reviews=99999)
        called_params = serpapi_fallback.requests.get.call_args.kwargs["params"]
        self.assertEqual(called_params["num"], serpapi_fallback._SERPAPI_NUM_HARD_CAP)

    # ── quota exhaustion ────────────────────────────────────────────────
    def test_quota_exhausted_before_call_no_http_attempted(self):
        year_month = serpapi_fallback._current_year_month()
        self.db["quota"][year_month] = {"request_count": serpapi_fallback.MONTHLY_QUOTA_LIMIT}
        http_patch = self._patch_http(_make_response(json.dumps(_SAMPLE_RESPONSE)))

        with self.assertRaises(serpapi_fallback.SerpApiQuotaExceededError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

        serpapi_fallback.requests.get.assert_not_called()

    # ── month rollover ──────────────────────────────────────────────────
    def test_month_rollover_creates_row_and_reserves_slot(self):
        self.assertEqual(self.db["quota"], {})  # no row for any month yet
        self._patch_http(_make_response(json.dumps({"contributor": {}, "reviews": []})))

        serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)

        year_month = serpapi_fallback._current_year_month()
        self.assertEqual(self.db["quota"][year_month]["request_count"], 1)
        self.assertGreaterEqual(self.db["insert_ignore_calls"], 1)

    # ── concurrent-near-cap race, at the DB-logic level ─────────────────
    def test_two_sequential_reservations_at_cap_only_one_succeeds(self):
        """Simulates two callers racing for the last slot: a fake cursor that
        only lets the request_count go from limit-1 to limit once. The second
        reservation attempt must see the row already at the cap and raise,
        without ever making an HTTP call."""
        year_month = serpapi_fallback._current_year_month()
        self.db["quota"][year_month] = {"request_count": serpapi_fallback.MONTHLY_QUOTA_LIMIT - 1}

        self._patch_http(_make_response(json.dumps({"contributor": {}, "reviews": []})))

        # First caller: succeeds, consumes the last slot.
        serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)
        self.assertEqual(self.db["quota"][year_month]["request_count"], serpapi_fallback.MONTHLY_QUOTA_LIMIT)

        # Second caller: quota is now exhausted, must raise before any HTTP call.
        serpapi_fallback.requests.get.reset_mock()
        with self.assertRaises(serpapi_fallback.SerpApiQuotaExceededError):
            serpapi_fallback.fetch_profile_and_reviews_via_serpapi(TEST_GAIA_ID)
        serpapi_fallback.requests.get.assert_not_called()


class QuotaStatusTests(unittest.TestCase):
    def setUp(self):
        self.db = _new_fake_db()
        self._patches = [mock.patch.object(app_module, "db_conn", _db_conn_for(self.db))]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def test_no_row_yet_reports_zero_without_creating_one(self):
        status = serpapi_fallback.check_quota()
        self.assertEqual(status, {
            "year_month": serpapi_fallback._current_year_month(),
            "request_count": 0,
            "limit": serpapi_fallback.MONTHLY_QUOTA_LIMIT,
        })
        self.assertEqual(self.db["quota"], {}, "reading status must not create a row")

    def test_existing_row_reports_actual_count(self):
        year_month = serpapi_fallback._current_year_month()
        self.db["quota"][year_month] = {"request_count": 17}
        status = serpapi_fallback.check_quota()
        self.assertEqual(status["request_count"], 17)


if __name__ == "__main__":
    unittest.main()

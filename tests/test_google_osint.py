"""sentinel_modules/google_osint.py — Step B of the email_lookup module
(GAIA id -> public Google Maps profile + reviews).

Offline only: every HTTP call is mocked (patched `requests.get`). Nothing
here reaches google.com.

Fixture provenance matters a lot for this module, so it's split explicitly
by what each fixture proves:

  * `google_osint_sample_response.json` — a REAL `status == 0` response,
    captured live 2026-09-05 against the public example GAIA id used
    throughout this project's research (`111544054649252019208`). Proves
    `display_name`, `photo_url`, and `total_reviews` extraction against
    real data. See its sibling `.README.md` for exactly what it does and
    does not verify.
  * `google_osint_bootstrap_response.json` — mirrors the real (also
    live-captured) shape of a tokenless bootstrap response: all-null except
    a token at index 12 and status 3.
  * `google_osint_synthetic_*.json` — hand-built, NOT verified against any
    real Google response. These exist only to exercise `_parse_review`'s
    field extraction, HTML-unescaping, sorting, and defensive
    skip-on-malformed-entry behavior, none of which the real fixture above
    can exercise (that account's reviews collection came back genuinely
    empty). A human should confirm `_parse_review` against a real populated
    response before this ships — see the module docstring.
"""
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_modules import google_osint  # noqa: E402

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
TEST_GAIA_ID = "111544054649252019208"


def _load_fixture_text(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name), encoding="utf-8") as f:
        return f.read()


def _make_response(body_text: str, status_code: int = 200, force_chunk_size: int | None = None):
    """A minimal fake of a `requests.Response` supporting exactly what
    `_get_envelope` uses: `.status_code`, `.iter_content()`, `.close()`.
    `force_chunk_size`, when given, overrides whatever chunk size the real
    code asks for — used to make the size-cap test accumulate across
    several chunks instead of tripping on the first one."""
    body_bytes = body_text.encode("utf-8")
    resp = mock.Mock()
    resp.status_code = status_code

    def iter_content(chunk_size=65536):
        size = force_chunk_size or chunk_size or len(body_bytes) or 1
        for i in range(0, len(body_bytes), size):
            yield body_bytes[i : i + size]

    resp.iter_content = iter_content
    resp.close = mock.Mock()
    return resp


class GoogleOsintTestCase(unittest.TestCase):
    def setUp(self):
        # Module-level token cache — reset between tests so they don't leak
        # state into each other.
        google_osint._TOKEN_CACHE["token"] = None
        google_osint._TOKEN_CACHE["minted_at"] = None

    # ─────────────────────────────────────────────
    # Real fixture: profile fields verified live
    # ─────────────────────────────────────────────
    def test_real_fixture_profile_fields(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real = _make_response(_load_fixture_text("google_osint_sample_response.json"))

        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real]) as m:
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        self.assertEqual(m.call_count, 2)  # one bootstrap + one real request
        self.assertEqual(result["display_name"], "Jitendra Kumar Markam")
        self.assertIsNotNone(result["photo_url"])
        self.assertIn("googleusercontent.com", result["photo_url"])
        self.assertEqual(result["total_reviews"], 1)
        # This specific real account's reviews collection came back
        # genuinely empty — see the fixture's README for why. A profile
        # with zero visible reviews is a valid, non-error outcome.
        self.assertEqual(result["reviews"], [])

    def test_cached_token_is_reused_across_calls(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real1 = _make_response(_load_fixture_text("google_osint_sample_response.json"))
        real2 = _make_response(_load_fixture_text("google_osint_sample_response.json"))

        with mock.patch(
            "sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real1, real2]
        ) as m:
            google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)
            google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        # Only ONE bootstrap call total across both fetches — the harvested
        # token is cached and reused, not re-minted every lookup.
        self.assertEqual(m.call_count, 3)

    # ─────────────────────────────────────────────
    # Synthetic fixtures: html-unescaping, sorting, defensive skipping
    # ─────────────────────────────────────────────
    def test_display_name_is_html_unescaped(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real = _make_response(
            _load_fixture_text("google_osint_synthetic_reviews_populated_positional.json")
        )
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real]):
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        self.assertEqual(result["display_name"], "Caro & Keith Napier")

    def test_missing_photo_returns_none_not_crash(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real = _make_response(_load_fixture_text("google_osint_synthetic_missing_photo.json"))
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real]):
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        self.assertEqual(result["display_name"], "No Photo Person")
        self.assertIsNone(result["photo_url"])
        self.assertEqual(result["total_reviews"], 3)

    def test_reviews_parsed_sorted_and_unescaped_positional_field45(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real = _make_response(
            _load_fixture_text("google_osint_synthetic_reviews_populated_positional.json")
        )
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real]):
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        self._assert_two_reviews_parsed_correctly(result["reviews"])

    def test_reviews_parsed_from_trailing_dict_field46(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real = _make_response(
            _load_fixture_text("google_osint_synthetic_reviews_populated_trailing_dict.json")
        )
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real]):
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        self._assert_two_reviews_parsed_correctly(result["reviews"])

    def _assert_two_reviews_parsed_correctly(self, reviews):
        self.assertEqual(len(reviews), 2)

        # Sorted newest-first (r1's timestamp > r2's), independent of the
        # order they appeared in the response.
        self.assertEqual(reviews[0]["business_name"], "Swaraj Tractors")
        self.assertEqual(reviews[1]["business_name"], "MMI Narayana Hospital")

        r1 = reviews[0]
        self.assertEqual(r1["business_address"], "Sector 5, Raipur, Chhattisgarh")
        self.assertEqual(r1["comment"], "Great service! Caro & Keith were wonderful.")  # unescaped
        self.assertAlmostEqual(r1["lat"], 21.2514)
        self.assertAlmostEqual(r1["lon"], 81.6296)
        self.assertIsInstance(r1["date"], datetime)
        self.assertEqual(r1["date"].tzinfo, timezone.utc)
        self.assertEqual(
            r1["maps_url"], f"https://www.google.com/maps?cid={int('123456789abcdef0', 16)}"
        )

    def test_malformed_review_entries_are_skipped_not_crashed(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        real = _make_response(_load_fixture_text("google_osint_synthetic_malformed_review.json"))
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, real]):
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        # Four garbage entries alongside one good one — only the good one
        # should survive, and nothing should raise.
        self.assertEqual(len(result["reviews"]), 1)
        self.assertEqual(result["reviews"][0]["business_name"], "Swaraj Tractors")

    # ─────────────────────────────────────────────
    # Token re-bootstrap on stale/expired token (status 3 mid-session)
    # ─────────────────────────────────────────────
    def test_status_3_on_real_request_triggers_rebootstrap_then_succeeds(self):
        bootstrap1 = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        stale = _make_response(")]}'\n" + json.dumps([None] * 15 + [3]))
        bootstrap2 = _make_response(")]}'\n" + json.dumps([None] * 12 + ["FRESH_TOKEN"] + [None, None, 3]))
        real = _make_response(_load_fixture_text("google_osint_sample_response.json"))

        with mock.patch(
            "sentinel_modules.google_osint.requests.get",
            side_effect=[bootstrap1, stale, bootstrap2, real],
        ) as m:
            result = google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

        self.assertEqual(m.call_count, 4)
        self.assertEqual(result["display_name"], "Jitendra Kumar Markam")

    def test_repeated_status_3_raises_after_one_rebootstrap_retry(self):
        bootstrap1 = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        stale1 = _make_response(")]}'\n" + json.dumps([None] * 15 + [3]))
        bootstrap2 = _make_response(")]}'\n" + json.dumps([None] * 12 + ["FRESH_TOKEN"] + [None, None, 3]))
        stale2 = _make_response(")]}'\n" + json.dumps([None] * 15 + [3]))

        with mock.patch(
            "sentinel_modules.google_osint.requests.get",
            side_effect=[bootstrap1, stale1, bootstrap2, stale2],
        ):
            with self.assertRaises(google_osint.GoogleOsintError):
                google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    # ─────────────────────────────────────────────
    # Failure modes: must raise, never return a silently-empty result
    # ─────────────────────────────────────────────
    def test_network_error_raises_google_osint_error(self):
        import requests as requests_module

        with mock.patch(
            "sentinel_modules.google_osint.requests.get",
            side_effect=requests_module.ConnectionError("boom"),
        ):
            with self.assertRaises(google_osint.GoogleOsintError):
                google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    def test_non_200_status_raises(self):
        bad = _make_response("not json", status_code=500)
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[bad]):
            with self.assertRaises(google_osint.GoogleOsintError):
                google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    def test_non_json_body_raises(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        garbage = _make_response(")]}'\nnot actually json{{{")
        with mock.patch(
            "sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, garbage]
        ):
            with self.assertRaises(google_osint.GoogleOsintError):
                google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    def test_response_size_cap_enforced(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        huge_body = ")]}'\n" + json.dumps([None] * 15 + [0, ["x" * 1000] * 5000])
        oversized = _make_response(huge_body, force_chunk_size=256)

        with mock.patch("sentinel_modules.google_osint._MAX_RESPONSE_BYTES", 1024):
            with mock.patch(
                "sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, oversized]
            ):
                with self.assertRaises(google_osint.GoogleOsintError):
                    google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    def test_bootstrap_missing_token_raises(self):
        no_token = _make_response(")]}'\n" + json.dumps([None] * 16 + [3]))
        with mock.patch("sentinel_modules.google_osint.requests.get", side_effect=[no_token]):
            with self.assertRaises(google_osint.GoogleOsintError):
                google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    def test_missing_profile_block_raises(self):
        bootstrap = _make_response(_load_fixture_text("google_osint_bootstrap_response.json"))
        no_profile = _make_response(")]}'\n" + json.dumps([None] * 15 + [0]))
        with mock.patch(
            "sentinel_modules.google_osint.requests.get", side_effect=[bootstrap, no_profile]
        ):
            with self.assertRaises(google_osint.GoogleOsintError):
                google_osint.fetch_profile_and_reviews(TEST_GAIA_ID)

    # ─────────────────────────────────────────────
    # Input validation
    # ─────────────────────────────────────────────
    def test_empty_gaia_id_raises_value_error(self):
        with self.assertRaises(ValueError):
            google_osint.fetch_profile_and_reviews("")

    def test_zero_max_reviews_raises_value_error(self):
        with self.assertRaises(ValueError):
            google_osint.fetch_profile_and_reviews(TEST_GAIA_ID, max_reviews=0)

    def test_negative_max_reviews_raises_value_error(self):
        with self.assertRaises(ValueError):
            google_osint.fetch_profile_and_reviews(TEST_GAIA_ID, max_reviews=-5)


if __name__ == "__main__":
    unittest.main()

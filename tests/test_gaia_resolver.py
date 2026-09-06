"""sentinel_modules/gaia_resolver.py — Step A of the email_lookup module
(email -> GAIA id).

Offline only: every Google network call is mocked (patched
`requests.Session`) and the database is an in-memory fake (patched
`app.db_conn`/`app.decrypt_text`). No real master token exists in this
environment and none is required — nothing here reaches
android.googleapis.com or any other Google host.

What matters most here is the three-way outcome split the module's callers
depend on:

  * cache hit / successful new resolution -> dict with a gaia_id
  * clean miss (working credential, no Google account for the address) -> None
  * credential failure (missing/disabled row, dead token, Google rejecting
    the minted session, network/parse failure) -> GaiaResolverCredentialError

A caller that confuses the second and third would either silently fail to
bill (miss look like broken) or, worse, charge/log a user for a lookup that
never actually ran (broken look like miss) — so each is tested separately,
including that a clean miss never writes to the cache.
"""
import contextlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402  (FLASK_ENV set by tests/__init__ first)
from sentinel_modules import gaia_resolver  # noqa: E402

TEST_EMAIL = "target@gmail.com"
TEST_TOKEN = "aas_et/fake-master-token"
TEST_GAIA_ID = "111544054649252019208"


# ─────────────────────────────────────────────
# Fake DB — mirrors app.get_db()/db_conn() shape closely enough for the
# three queries gaia_resolver issues: integrations lookup, cache read,
# cache write (+ the health-check "most recent" query).
# ─────────────────────────────────────────────
class _FakeCursor:
    def __init__(self, db):
        self.db = db
        self._result = None

    def execute(self, query, params=()):
        q = " ".join(query.split())
        if q.startswith("SELECT api_key, is_enabled FROM integrations"):
            self._result = self.db["integrations"].get(params[0])
        elif q.startswith("SELECT gaia_id FROM email_gaia_cache WHERE email=%s"):
            gaia_id = self.db["cache"].get(params[0])
            self._result = {"gaia_id": gaia_id} if gaia_id else None
        elif q.startswith("INSERT INTO email_gaia_cache"):
            email, gaia_id = params
            self.db["cache"][email] = gaia_id
            self.db["cache_writes"].append((email, gaia_id))
            self.db["most_recent_email"] = email
            self._result = None
        elif q.startswith("SELECT email FROM email_gaia_cache ORDER BY resolved_at"):
            recent = self.db.get("most_recent_email")
            self._result = {"email": recent} if recent else None
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


def _new_fake_db(integrations=None):
    return {
        "integrations": integrations or {},
        "cache": {},
        "cache_writes": [],
        "most_recent_email": None,
    }


def _db_conn_for(db):
    @contextlib.contextmanager
    def _db_conn():
        yield _FakeConn(db)
    return _db_conn


# ─────────────────────────────────────────────
# Fake Google session — every HTTP call the module can make.
# ─────────────────────────────────────────────
class _FakeResponse:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body configured on this fake response")
        return self._json_data


class _FakeCookie:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _FakeSession:
    """Scripted stand-in for requests.Session covering the 3-call chain
    (android auth -> uberauth -> MergeSession) plus the People API call.
    `script` maps a short stage name to either a _FakeResponse or an
    exception instance to raise."""

    def __init__(self, script, sapisid="fake-sapisid-value"):
        self.script = script
        self.sapisid = sapisid
        self.cookies = []
        self.closed = False
        self.calls = []

    def _resolve(self, stage):
        outcome = self.script.get(stage)
        if outcome is None:
            raise AssertionError(f"fake session got unscripted call for stage {stage!r}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(("POST", url))
        assert url == gaia_resolver._ANDROID_AUTH_URL
        return self._resolve("android_auth")

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(("GET", url))
        if url == gaia_resolver._OAUTH_LOGIN_URL:
            return self._resolve("uberauth")
        if url == gaia_resolver._MERGE_SESSION_URL:
            resp = self._resolve("merge_session")
            if resp.status_code == 200:
                self.cookies.append(_FakeCookie("SAPISID", self.sapisid))
            return resp
        if url == gaia_resolver._PEOPLE_API_URL:
            assert headers["Host"] == gaia_resolver._PEOPLE_API_HOST
            assert headers["Authorization"].startswith("SAPISIDHASH ")
            return self._resolve("people")
        raise AssertionError(f"fake session got unexpected URL {url!r}")

    def close(self):
        self.closed = True


_FULL_SUCCESS_SCRIPT = {
    "android_auth": _FakeResponse(200, text="Auth=fake-oauth-token\ngrantedScopes=x\nExpiry=123\n"),
    "uberauth": _FakeResponse(200, text="fake-uberauth-token"),
    "merge_session": _FakeResponse(200),
}


class GaiaResolverTests(unittest.TestCase):
    def setUp(self):
        self.db = _new_fake_db(integrations={
            gaia_resolver._INTEGRATION_NAME: {"api_key": TEST_TOKEN, "is_enabled": 1},
        })
        self._patches = [
            mock.patch.object(app_module, "db_conn", _db_conn_for(self.db)),
            mock.patch.object(app_module, "decrypt_text", lambda v: v),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)

    def _patch_session(self, fake_session):
        p = mock.patch.object(gaia_resolver.requests, "Session", return_value=fake_session)
        p.start()
        self.addCleanup(p.stop)
        return fake_session

    # ── credential errors ──────────────────────────────────────────
    def test_missing_credential_row_raises_before_any_network_call(self):
        self.db["integrations"] = {}  # no google_master_token row at all
        fake = self._patch_session(_FakeSession({}))
        with self.assertRaises(gaia_resolver.GaiaResolverCredentialError):
            gaia_resolver.resolve_gaia(TEST_EMAIL)
        self.assertEqual(fake.calls, [], "must fail before touching the network")

    def test_disabled_credential_row_raises(self):
        self.db["integrations"][gaia_resolver._INTEGRATION_NAME]["is_enabled"] = 0
        self._patch_session(_FakeSession({}))
        with self.assertRaises(gaia_resolver.GaiaResolverCredentialError):
            gaia_resolver.resolve_gaia(TEST_EMAIL)

    def test_android_auth_missing_auth_key_is_credential_error(self):
        """Exactly the 'master token died' failure mode: the endpoint responds
        200 but with no Auth= line."""
        script = {"android_auth": _FakeResponse(200, text="grantedScopes=x\n")}
        self._patch_session(_FakeSession(script))
        with self.assertRaises(gaia_resolver.GaiaResolverCredentialError) as ctx:
            gaia_resolver.resolve_gaia(TEST_EMAIL)
        self.assertIn("Auth", str(ctx.exception))
        self.assertEqual(self.db["cache_writes"], [])

    def test_android_auth_http_error_is_credential_error(self):
        script = {"android_auth": _FakeResponse(401, text="")}
        self._patch_session(_FakeSession(script))
        with self.assertRaises(gaia_resolver.GaiaResolverCredentialError):
            gaia_resolver.resolve_gaia(TEST_EMAIL)

    def test_people_api_403_is_credential_error_not_a_miss(self):
        script = dict(_FULL_SUCCESS_SCRIPT, people=_FakeResponse(403, text="Forbidden"))
        self._patch_session(_FakeSession(script))
        with self.assertRaises(gaia_resolver.GaiaResolverCredentialError):
            gaia_resolver.resolve_gaia(TEST_EMAIL)
        self.assertEqual(self.db["cache_writes"], [])

    def test_network_error_is_wrapped_as_credential_error(self):
        script = {"android_auth": gaia_resolver.requests.RequestException("boom")}
        self._patch_session(_FakeSession(script))
        with self.assertRaises(gaia_resolver.GaiaResolverCredentialError):
            gaia_resolver.resolve_gaia(TEST_EMAIL)

    # ── clean miss ─────────────────────────────────────────────────
    def test_no_people_key_is_clean_miss_not_error(self):
        script = dict(_FULL_SUCCESS_SCRIPT, people=_FakeResponse(200, json_data={"people": {}}))
        self._patch_session(_FakeSession(script))
        result = gaia_resolver.resolve_gaia(TEST_EMAIL)
        self.assertIsNone(result)
        self.assertEqual(self.db["cache_writes"], [], "a clean miss must not be cached")

    def test_person_with_no_person_id_is_clean_miss(self):
        script = dict(_FULL_SUCCESS_SCRIPT,
                       people=_FakeResponse(200, json_data={"people": {"k1": {"metadata": {}}}}))
        self._patch_session(_FakeSession(script))
        self.assertIsNone(gaia_resolver.resolve_gaia(TEST_EMAIL))

    # ── success ────────────────────────────────────────────────────
    def test_full_chain_success_resolves_and_caches(self):
        script = dict(_FULL_SUCCESS_SCRIPT,
                       people=_FakeResponse(200, json_data={
                           "people": {"key1": {"personId": TEST_GAIA_ID, "metadata": {}}}
                       }))
        fake = self._patch_session(_FakeSession(script))
        result = gaia_resolver.resolve_gaia(TEST_EMAIL)
        self.assertEqual(result, {"gaia_id": TEST_GAIA_ID, "cached": False})
        self.assertEqual(self.db["cache_writes"], [(TEST_EMAIL, TEST_GAIA_ID)])
        self.assertTrue(fake.closed, "session must be closed after use")
        # Full chain actually ran end to end.
        stages = [url for _, url in fake.calls]
        self.assertIn(gaia_resolver._ANDROID_AUTH_URL, stages)
        self.assertIn(gaia_resolver._OAUTH_LOGIN_URL, stages)
        self.assertIn(gaia_resolver._MERGE_SESSION_URL, stages)
        self.assertIn(gaia_resolver._PEOPLE_API_URL, stages)

    def test_email_is_normalized_lowercase_for_cache_key(self):
        script = dict(_FULL_SUCCESS_SCRIPT,
                       people=_FakeResponse(200, json_data={
                           "people": {"k": {"personId": TEST_GAIA_ID}}
                       }))
        self._patch_session(_FakeSession(script))
        gaia_resolver.resolve_gaia("  Target@Gmail.com  ")
        self.assertIn(TEST_EMAIL, self.db["cache"])

    # ── cache hit ──────────────────────────────────────────────────
    def test_cache_hit_never_touches_network_or_credential(self):
        self.db["cache"][TEST_EMAIL] = TEST_GAIA_ID
        self.db["integrations"] = {}  # even a missing credential must not matter on a hit
        fake = self._patch_session(_FakeSession({}))
        result = gaia_resolver.resolve_gaia(TEST_EMAIL)
        self.assertEqual(result, {"gaia_id": TEST_GAIA_ID, "cached": True})
        self.assertEqual(fake.calls, [])

    def test_empty_email_raises_value_error(self):
        with self.assertRaises(ValueError):
            gaia_resolver.resolve_gaia("   ")


class SapisidHashTests(unittest.TestCase):
    def test_matches_documented_formula(self):
        with mock.patch.object(gaia_resolver.time, "time", return_value=1700000000.0):
            result = gaia_resolver.gen_sapisidhash("sid123", "https://photos.google.com")
        import hashlib
        expected_ts = "1700000000"
        expected = f"{expected_ts}_{hashlib.sha1(' '.join([expected_ts, 'sid123', 'https://photos.google.com']).encode()).hexdigest()}"
        self.assertEqual(result, expected)


class HealthCheckTests(unittest.TestCase):
    def setUp(self):
        self.db = _new_fake_db(integrations={
            gaia_resolver._INTEGRATION_NAME: {"api_key": TEST_TOKEN, "is_enabled": 1},
        })
        self._patches = [
            mock.patch.object(app_module, "db_conn", _db_conn_for(self.db)),
            mock.patch.object(app_module, "decrypt_text", lambda v: v),
        ]
        for p in self._patches:
            p.start()
            self.addCleanup(p.stop)
        # Never let a stray real env var leak into a test run.
        self._env_patch = mock.patch.dict(os.environ, {}, clear=False)
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)
        os.environ.pop(gaia_resolver._HEALTHCHECK_EMAIL_ENV, None)

    def _patch_session(self, fake_session):
        p = mock.patch.object(gaia_resolver.requests, "Session", return_value=fake_session)
        p.start()
        self.addCleanup(p.stop)
        return fake_session

    def test_no_test_email_available_anywhere_reports_not_ok_without_raising(self):
        result = gaia_resolver.health_check()
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])
        self.assertIn("checked_at", result)

    def test_explicit_test_email_used_and_credential_error_surfaced(self):
        self.db["integrations"] = {}
        result = gaia_resolver.health_check(test_email=TEST_EMAIL)
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])

    def test_success_reports_ok_true(self):
        script = dict(_FULL_SUCCESS_SCRIPT,
                       people=_FakeResponse(200, json_data={
                           "people": {"k": {"personId": TEST_GAIA_ID}}
                       }))
        self._patch_session(_FakeSession(script))
        result = gaia_resolver.health_check(test_email=TEST_EMAIL)
        self.assertTrue(result["ok"])
        self.assertIsNone(result["error"])

    def test_clean_miss_still_reports_ok_true(self):
        """A miss proves the credential chain itself works end to end."""
        script = dict(_FULL_SUCCESS_SCRIPT, people=_FakeResponse(200, json_data={"people": {}}))
        self._patch_session(_FakeSession(script))
        result = gaia_resolver.health_check(test_email=TEST_EMAIL)
        self.assertTrue(result["ok"])

    def test_falls_back_to_most_recently_cached_email(self):
        self.db["cache"][TEST_EMAIL] = TEST_GAIA_ID
        self.db["most_recent_email"] = TEST_EMAIL
        fake = self._patch_session(_FakeSession({}))
        result = gaia_resolver.health_check()
        self.assertTrue(result["ok"])
        self.assertEqual(fake.calls, [], "a cache hit shouldn't need the network")


if __name__ == "__main__":
    unittest.main()

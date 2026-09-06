"""Step A of the `email_lookup` module — resolve a Gmail address to a Google
GAIA id, using a pre-obtained Android master token.

This is an original implementation, not a copy of GHunt's client. The
endpoints, form fields and header names below are facts about Google's own
internal auth/People-API surface (verified by reading GHunt's installed
source at helpers/auth.py, objects/apis.py, apis/peoplepa.py,
apis/accounts.py, knowledge/keys.py while building this), not GHunt's
expression of them. GHunt itself is not a runtime dependency of SENTINEL —
its own People-API response parser has a known dead-code bug (name/cover
photo fields Google has since "patched" client-side), which is part of why
this module talks to Google directly instead.

The chain, all through one `requests.Session` so cookies persist naturally:

  1. POST android.googleapis.com/auth with the master token -> short-lived
     OAuth token ("Auth").
  2. GET accounts.google.com/OAuthLogin with that OAuth token -> a one-shot
     "uberauth" token.
  3. GET accounts.google.com/MergeSession with the uberauth token -> real
     browser-style session cookies, including SAPISID. These are minted
     fresh per call and are not meant to be persisted — only the master
     token is durable.
  4. Sign requests with a SAPISIDHASH built from SAPISID + the calling
     origin (Google's cookie-auth scheme for internal APIs).
  5. GET the People API (routed to people-pa.clients6.google.com via a Host
     header override on a googleapis.com URL, exactly how Google's own
     frontend dispatches this call) for the email, and pull `personId`
     (the GAIA id) out of the first result.

Two outcomes are NOT the same and callers must not confuse them:

  * A working credential that finds no Google account for an email is a
    clean miss -> `resolve_gaia()` returns `None`. Nothing is wrong.
  * A dead/revoked master token, or Google rejecting the minted session, is
    a credential failure -> `resolve_gaia()` raises
    `GaiaResolverCredentialError`. Callers (the tool runner and the admin
    health check) must treat this as "our integration is broken", never as
    "no Google account" — in particular, a caller that charges credits per
    lookup must not charge for this outcome.

Resolutions are cached in `email_gaia_cache` (see migration_email_lookup.sql
at the repo root) so a dead credential only blocks *new* addresses; every
previously-resolved email keeps working and every existing report stays
re-printable.

Deferred imports of `app` (inside functions, not at module load time) are
deliberate, matching the pattern already used by tools/bootstrap_admin.py:
this module must stay importable — and its own logic testable with mocked
HTTP — without pulling in app.py's fail-fast startup checks or a live DB
connection just because it was imported.
"""
import hashlib
import os
import time
from datetime import datetime, timezone

import requests

__all__ = [
    "resolve_gaia",
    "health_check",
    "gen_sapisidhash",
    "GaiaResolverError",
    "GaiaResolverCredentialError",
]

# ─────────────────────────────────────────────
# Constants — Google's endpoints and fixed client identifiers.
# ─────────────────────────────────────────────
_ANDROID_AUTH_URL = "https://android.googleapis.com/auth"
_ANDROID_APP_ID = "com.android.chrome"
_ANDROID_SERVICE = "oauth2:https://www.google.com/accounts/OAuthLogin"
_ANDROID_CLIENT_SIG = "38918a453d07199354f8b19af05ec6562ced5788"

_OAUTH_LOGIN_URL = "https://accounts.google.com/OAuthLogin"
_MERGE_SESSION_URL = "https://accounts.google.com/MergeSession"

_PEOPLE_API_URL = "https://googleapis.com/v2/people/lookup"
_PEOPLE_API_HOST = "people-pa.clients6.google.com"
_PEOPLE_API_KEY = "AIzaSyAa2odBewW-sPJu3jMORr0aNedh3YlkiQc"
_SAPISID_ORIGIN = "https://photos.google.com"

_REQUEST_TIMEOUT = 15  # seconds, per HTTP call

_INTEGRATION_NAME = "google_master_token"
_CACHE_TABLE = "email_gaia_cache"
_HEALTHCHECK_EMAIL_ENV = "GAIA_HEALTHCHECK_EMAIL"


# ─────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────
class GaiaResolverError(Exception):
    """Base class for errors raised by this module."""


class GaiaResolverCredentialError(GaiaResolverError):
    """The Google credential path is broken: no master token is configured,
    the token was rejected by Google (dead/revoked/expired), the minted
    session was refused by the People API, or a network/parsing failure
    means we simply don't know the answer.

    Distinct, on purpose, from a clean miss (`resolve_gaia()` returning
    `None`), which means the credential worked fine and Google just has no
    account for that address. Callers must never treat this exception as a
    clean miss — no silent "no results" success, and no billing the user
    for a lookup that never actually ran.
    """


# ─────────────────────────────────────────────
# SAPISIDHASH signing
# ─────────────────────────────────────────────
def gen_sapisidhash(sapisid: str, origin: str) -> str:
    ts = str(int(time.time()))
    return f"{ts}_{hashlib.sha1(' '.join([ts, sapisid, origin]).encode()).hexdigest()}"


def _redact_secret(text: str, secret: str) -> str:
    """Strip a known secret value out of arbitrary text before it can reach
    a caller. `GaiaResolverCredentialError` messages are returned directly
    to ordinary authenticated users (not just admins) via
    `run_tool_generic()`/`mobile_lookup_report_pdf()`'s email_lookup
    branches. `_merge_session()` sends `uberauth` as a query parameter, so a
    connection-level failure raised by `requests`/`urllib3` embeds the full
    request URL — query string included — in its own `str()` (verified
    directly against `requests` behaviour); that single-use Google session
    token must not leak into a message a caller can see."""
    if not secret:
        return text
    return text.replace(secret, "***REDACTED***")


# ─────────────────────────────────────────────
# The five-step Google auth chain
# ─────────────────────────────────────────────
def _android_auth(session: requests.Session, master_token: str) -> str:
    """Step 1: exchange the durable master token for a short-lived OAuth token."""
    try:
        resp = session.post(
            _ANDROID_AUTH_URL,
            data={
                "app": _ANDROID_APP_ID,
                "service": _ANDROID_SERVICE,
                "client_sig": _ANDROID_CLIENT_SIG,
                "Token": master_token,
            },
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GaiaResolverCredentialError(f"Network error during Android auth step: {exc}") from exc

    if resp.status_code != 200:
        raise GaiaResolverCredentialError(
            f"Android auth endpoint returned HTTP {resp.status_code} — the master "
            "token is likely revoked or expired."
        )

    values = {}
    for line in resp.text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key] = value

    auth = values.get("Auth")
    if not auth:
        raise GaiaResolverCredentialError(
            "Android auth endpoint responded but returned no 'Auth' token — the "
            "master token is likely dead (password change, security flag, or ToS "
            "action on the source account). Re-run tools/extract_ghunt_token.py and "
            "tools/set_integration_credential.py --name google_master_token to replace it."
        )
    return auth


def _issue_uberauth(session: requests.Session, oauth_token: str) -> str:
    """Step 2: trade the OAuth token for a one-shot uberauth token."""
    try:
        resp = session.get(
            _OAUTH_LOGIN_URL,
            params={"source": "ChromiumBrowser", "issueuberauth": "1"},
            headers={"Authorization": f"OAuth {oauth_token}"},
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GaiaResolverCredentialError(f"Network error issuing uberauth token: {exc}") from exc

    uberauth = (resp.text or "").strip()
    if resp.status_code != 200 or not uberauth:
        raise GaiaResolverCredentialError(
            f"Failed to issue uberauth token (HTTP {resp.status_code}) — the OAuth "
            "token from the Android auth step was not accepted."
        )
    return uberauth


def _cookie_value(session: requests.Session, name: str):
    """Look up a cookie by name across the whole jar. Deliberately not
    session.cookies.get(name), which can raise CookieConflictError if the
    same cookie name exists under more than one domain in the jar — we just
    want the first match, domain-agnostic, same as the value MergeSession
    just minted."""
    for cookie in session.cookies:
        if cookie.name == name:
            return cookie.value
    return None


def _merge_session(session: requests.Session, uberauth: str) -> str:
    """Step 3: mint real browser-style session cookies, including SAPISID."""
    try:
        resp = session.get(
            _MERGE_SESSION_URL,
            params={
                "uberauth": uberauth,
                "continue": "https://www.google.com",
                "source": "ChromiumAccountReconcilor",
                "externalCcResult": "doubleclick:null,youtube:null",
            },
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GaiaResolverCredentialError(
            f"Network error during MergeSession: {_redact_secret(str(exc), uberauth)}"
        ) from exc

    if resp.status_code != 200:
        raise GaiaResolverCredentialError(f"MergeSession failed (HTTP {resp.status_code}).")

    sapisid = _cookie_value(session, "SAPISID")
    if not sapisid:
        raise GaiaResolverCredentialError("MergeSession did not mint a SAPISID cookie.")
    return sapisid


def _people_lookup(session: requests.Session, sapisid: str, email: str):
    """Step 5: call the People API and pull the GAIA id out of the result.
    Returns the GAIA id string, or None on a clean miss (no Google account
    for this email)."""
    auth_header = f"SAPISIDHASH {gen_sapisidhash(sapisid, _SAPISID_ORIGIN)}"
    try:
        resp = session.get(
            _PEOPLE_API_URL,
            headers={
                "Host": _PEOPLE_API_HOST,
                "Authorization": auth_header,
                "X-Goog-Api-Key": _PEOPLE_API_KEY,
                "Origin": _SAPISID_ORIGIN,
                "Referer": _SAPISID_ORIGIN + "/",
            },
            params={
                "id": email,
                "type": "EMAIL",
                "matchType": "EXACT",
                "requestMask.includeField.paths": "person.metadata",
            },
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise GaiaResolverCredentialError(f"Network error calling the People API: {exc}") from exc

    if resp.status_code in (401, 403):
        raise GaiaResolverCredentialError(
            f"People API rejected the session (HTTP {resp.status_code}) — the "
            "cookies minted from the master token were not accepted."
        )
    if resp.status_code != 200:
        raise GaiaResolverCredentialError(f"People API call failed (HTTP {resp.status_code}).")

    try:
        data = resp.json()
    except ValueError as exc:
        raise GaiaResolverCredentialError(f"People API returned a non-JSON response: {exc}") from exc

    people = data.get("people") or {}
    if not people:
        return None  # clean miss — no Google account for this email

    person_data = next(iter(people.values())) or {}
    gaia_id = person_data.get("personId")
    if not gaia_id:
        return None  # clean miss
    return gaia_id


# ─────────────────────────────────────────────
# Credential loading + cache (DB-backed)
# ─────────────────────────────────────────────
def _load_master_token(cursor) -> str:
    cursor.execute(
        "SELECT api_key, is_enabled FROM integrations WHERE name=%s",
        (_INTEGRATION_NAME,),
    )
    row = cursor.fetchone()
    if not row or not row.get("is_enabled"):
        raise GaiaResolverCredentialError(
            f"No enabled '{_INTEGRATION_NAME}' credential configured. Run "
            "tools/extract_ghunt_token.py on the machine holding GHunt's session, "
            "then tools/set_integration_credential.py --name google_master_token "
            "to store it."
        )

    from app import decrypt_text  # deferred — see module docstring

    token = decrypt_text(row.get("api_key"))
    if not token:
        raise GaiaResolverCredentialError(
            f"'{_INTEGRATION_NAME}' credential row exists but decrypted to nothing "
            "usable. Re-run tools/set_integration_credential.py --name google_master_token."
        )
    return token


def _cached_gaia_id(cursor, email: str):
    cursor.execute(
        f"SELECT gaia_id FROM {_CACHE_TABLE} WHERE email=%s",
        (email,),
    )
    row = cursor.fetchone()
    return row.get("gaia_id") if row else None


def _store_cache(cursor, email: str, gaia_id: str) -> None:
    cursor.execute(
        f"INSERT INTO {_CACHE_TABLE} (email, gaia_id) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE gaia_id=VALUES(gaia_id)",
        (email, gaia_id),
    )


def _most_recently_resolved_email(cursor):
    cursor.execute(f"SELECT email FROM {_CACHE_TABLE} ORDER BY resolved_at DESC LIMIT 1")
    row = cursor.fetchone()
    return row.get("email") if row else None


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────
def resolve_gaia(email: str) -> dict | None:
    """Resolve an email address to a Google GAIA id.

    Returns `{"gaia_id": str, "cached": bool}` on success (including cache
    hits), or `None` on a clean miss (working credential, no Google account
    for this address). Raises `GaiaResolverCredentialError` when the
    credential itself is the problem — missing/disabled row, dead master
    token, or Google rejecting the minted session/network failure — which
    callers must not treat as a miss.
    """
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email is required")

    from app import db_conn  # deferred — see module docstring

    with db_conn() as conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cached = _cached_gaia_id(cursor, email)
            if cached:
                return {"gaia_id": cached, "cached": True}

            master_token = _load_master_token(cursor)

            session = requests.Session()
            try:
                oauth_token = _android_auth(session, master_token)
                uberauth = _issue_uberauth(session, oauth_token)
                sapisid = _merge_session(session, uberauth)
                gaia_id = _people_lookup(session, sapisid, email)
            finally:
                session.close()

            if not gaia_id:
                return None  # clean miss — nothing to cache

            _store_cache(cursor, email, gaia_id)
            conn.commit()
            return {"gaia_id": gaia_id, "cached": False}
        finally:
            cursor.close()


def health_check(test_email: str | None = None) -> dict:
    """Cheap self-test of the whole credential chain against a fixed,
    known-good address, for the admin health-check panel.

    Address resolution order: explicit `test_email` argument, then the
    `GAIA_HEALTHCHECK_EMAIL` env var, then the most recently cached
    successful resolution. If none of those is available, this returns
    ok=False asking for one to be configured rather than guessing.

    Does not touch billing/credits — diagnostic only.
    """
    checked_at = datetime.now(timezone.utc).isoformat()

    email = (test_email or "").strip().lower()
    if not email:
        email = (os.environ.get(_HEALTHCHECK_EMAIL_ENV) or "").strip().lower()

    if not email:
        from app import db_conn  # deferred — see module docstring

        with db_conn() as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                email = _most_recently_resolved_email(cursor) or ""
            finally:
                cursor.close()

    if not email:
        return {
            "ok": False,
            "checked_at": checked_at,
            "error": (
                "No test email configured and no address has ever resolved "
                f"successfully to seed a default. Pass test_email, set "
                f"{_HEALTHCHECK_EMAIL_ENV}, or resolve one real address first."
            ),
        }

    try:
        resolve_gaia(email)
    except GaiaResolverCredentialError as exc:
        return {"ok": False, "checked_at": checked_at, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — health check must never raise
        return {"ok": False, "checked_at": checked_at, "error": f"Unexpected error: {exc}"}

    # A clean miss here still proves the credential chain works end to end —
    # only a GaiaResolverCredentialError means the credential itself is broken.
    return {"ok": True, "checked_at": checked_at, "error": None}

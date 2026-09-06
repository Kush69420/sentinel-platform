"""sentinel_modules/serpapi_fallback.py — SerpApi fallback for Step B of the
`email_lookup` module (GAIA id -> public Google Maps profile + reviews).

`sentinel_modules/google_osint.py` (the primary path) talks directly to an
undocumented Google internal endpoint with no credentials — cheap, but it can
break the moment Google reshapes that response, with no warning and no SLA.
This module is the paid, hard-capped fallback for when that happens: it goes
through SerpApi's `google_maps_contributor_reviews` engine instead, which is
a documented, supported product built on top of the same kind of scrape, so
it degrades independently of Google's internal endpoint.

This module is used ONLY when `google_osint.fetch_profile_and_reviews()` has
already raised `GoogleOsintError` — never as a primary path, and never
speculatively. Wiring that fallback order into `run_tool_generic()` is a
separate task; this module is deliberately self-contained and independently
importable/testable in the meantime (see the plan doc).

Endpoint
--------
`GET https://serpapi.com/search` with `engine=google_maps_contributor_reviews`
and `contributor_id=<gaia_id>` — SerpApi confirms directly in its own docs
(https://serpapi.com/google-maps-contributor-reviews-api, fetched live while
scoping this module) that `contributor_id` is the same GAIA id
`google_osint.py` already works with, so no extra identifier translation is
needed between the two Step-B implementations.

SerpApi's docs do not document an explicit error-response shape or
rate-limit-specific fields, so this module treats any of the following as a
hard failure, uniformly, via `SerpApiError`: a non-200 HTTP status, a
response body that isn't a JSON object, or a JSON object containing an
`"error"` key. There is no soft/degraded-but-usable response class here.

Field mapping (SerpApi's documented response -> this module's return shape)
-----------------------------------------------------------------------------
  * `contributor.name`                    -> `display_name`
  * `contributor.thumbnail`                -> `photo_url`
  * `contributor.contributions.reviews`    -> `total_reviews`
  * per review, `place_info.title`         -> `business_name`
  * per review, `place_info.address`       -> `business_address`
  * per review, `place_info.gps_coordinates.latitude`/`.longitude` -> `lat`/`lon`
  * per review, `snippet`                  -> `comment` (`""` if absent, same
    convention `google_osint.py` uses rather than `None`)
  * per review, `link`                     -> `maps_url`, but ONLY if it looks
    like a valid `https://` Google URL. SerpApi's `place_info.data_id` format
    is not confirmed to match what `google_osint.py`'s own
    `_maps_url_from_data_id()` expects (a `0x..:0x..` CID pair), so this
    module deliberately does not try to fabricate a maps URL from it —
    `maps_url` is `None` rather than a guessed/wrong link.

Date handling
-------------
SerpApi's own docs do not pin down the exact format of a review's `date`
field — it may be an absolute date or a relative string like "a month ago".
Mirroring how defensively `google_osint.py`'s own (unverified) review parser
is written, `_parse_date()` here tries ISO 8601 first, then a short list of
plausible absolute-date formats, and gives up cleanly rather than raising: an
unparseable date leaves `"date": None` and stashes the original string in an
extra `"date_raw"` field so nothing is silently dropped, and one bad date
never takes down the rest of the review or the rest of the batch.

Quota enforcement
------------------
SerpApi is paid and hard-capped at `MONTHLY_QUOTA_LIMIT` (250) calls/month by
policy, not by anything SerpApi itself enforces — this module is the only
thing standing between a Google-outage-triggered fallback storm and a
surprise bill. `_reserve_quota_slot()` reserves a slot in
`serpapi_usage_quota` (see migration_email_lookup.sql) with an atomic
`UPDATE ... WHERE request_count < <limit>` guard, checked by `rowcount`, the
same optimistic-concurrency idiom `app.py`'s `charge_for_lookup()` uses for
`bot_users.credits` — never a read-then-write race. The slot is reserved
*before* the HTTP call is made and is not refunded if the call then fails:
the cap exists to bound how many calls this integration is ever allowed to
attempt in a month, not merely how many succeed.

Deferred imports of `app` (inside functions, not at module load time) match
the pattern already used by `sentinel_modules/gaia_resolver.py` and
`tools/bootstrap_admin.py`: this module must stay importable — and its own
logic testable with a mocked HTTP layer and a fake DB cursor — without
pulling in `app.py`'s fail-fast startup checks or a live DB connection just
because it was imported.
"""
import json
import os
import urllib.parse
from datetime import datetime, timezone

import requests

__all__ = [
    "fetch_profile_and_reviews_via_serpapi",
    "get_quota_status",
    "check_quota",
    "SerpApiError",
    "SerpApiQuotaExceededError",
    "MONTHLY_QUOTA_LIMIT",
]

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
_SERPAPI_URL = "https://serpapi.com/search"
_SERPAPI_ENGINE = "google_maps_contributor_reviews"

_REQUEST_TIMEOUT = 20  # seconds, per HTTP call
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # hard cap on the HTTP response body
_DEFAULT_MAX_REVIEWS = 20
_SERPAPI_NUM_HARD_CAP = 200  # SerpApi's own documented per-request cap

_QUOTA_TABLE = "serpapi_usage_quota"
MONTHLY_QUOTA_LIMIT = 250

# A short list of plausible absolute-date formats to try after ISO 8601,
# since SerpApi's docs don't pin down the exact shape of `date`.
_ABSOLUTE_DATE_FORMATS = (
    "%Y-%m-%d",
    "%B %d, %Y",
    "%b %d, %Y",
    "%m/%d/%Y",
)


# ─────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────
class SerpApiError(Exception):
    """Raised on network failure, a non-200 response, a malformed/error JSON
    body, or a missing `SERPAPI_KEY`.

    Callers must treat this as "we could not fetch this profile via the
    fallback" — never silently return an empty-looking result, and never
    charge a user's credits for this outcome (same contract
    `GoogleOsintError`/`GaiaResolverCredentialError` already establish for
    the sibling modules).
    """


class SerpApiQuotaExceededError(SerpApiError):
    """Raised when the monthly SerpApi call budget (`MONTHLY_QUOTA_LIMIT`)
    is already used up. Distinct from a generic `SerpApiError` so callers can
    tell "the fallback itself is broken/misconfigured" apart from "the
    fallback is fine but we've deliberately capped spend for this month" —
    the two should likely surface different messages to an investigator.

    Raised BEFORE any HTTP call to SerpApi is made — an exhausted quota must
    never place another billed request.
    """


# ─────────────────────────────────────────────
# Quota tracking — atomic reserve-before-call, month-rollover-safe
# ─────────────────────────────────────────────
def _current_year_month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def get_quota_status(cursor, year_month: str | None = None) -> dict:
    """Read this month's SerpApi usage WITHOUT incrementing anything.

    Returns `{"year_month": "2026-09", "request_count": N, "limit": 250}`.
    `request_count` is 0 if no row exists yet for this month (nothing has
    reserved a slot this month, so nothing has been used) — this is a normal
    outcome, not an error.
    """
    year_month = year_month or _current_year_month()
    cursor.execute(
        f"SELECT request_count FROM {_QUOTA_TABLE} WHERE `year_month`=%s",
        (year_month,),
    )
    row = cursor.fetchone()
    request_count = (row.get("request_count") if row else 0) or 0
    return {"year_month": year_month, "request_count": request_count, "limit": MONTHLY_QUOTA_LIMIT}


def check_quota() -> dict:
    """Convenience wrapper over `get_quota_status()` that opens its own
    connection — for admin/health-check callers that don't already have a
    cursor open. Not wired into any route yet; provided for the next task
    (app.py integration) and for tests exercising the quota table shape
    directly. Never increments anything."""
    from app import db_conn  # deferred — see module docstring

    with db_conn() as conn:
        cursor = conn.cursor(dictionary=True)
        try:
            return get_quota_status(cursor)
        finally:
            cursor.close()


def _reserve_quota_slot(cursor, year_month: str) -> None:
    """Atomically reserve one call against this month's quota.

    Mirrors the optimistic-concurrency idiom `app.py`'s `charge_for_lookup()`
    uses for `bot_users.credits`: a single guarded `UPDATE ... WHERE
    request_count < %s`, success measured by `cursor.rowcount`, never a
    read-then-write race that two concurrent callers could both pass.

    `UPDATE ... ON DUPLICATE KEY UPDATE` can't express "only increment under
    the cap" in one statement the way a plain `UPDATE` with a `WHERE` guard
    can, so month-rollover (no row yet) is handled as: try the guarded
    UPDATE first; if it affected no row, `INSERT IGNORE` the row (a no-op if
    one already exists — created by us a moment ago in a race, or already
    exhausted) and retry the guarded UPDATE exactly once more. If that also
    affects no row, the month is genuinely exhausted.

    Raises `SerpApiQuotaExceededError` if the cap is already reached — this
    must run, and raise, before any HTTP call to SerpApi.
    """
    cursor.execute(
        f"UPDATE {_QUOTA_TABLE} SET request_count = request_count + 1 "
        "WHERE `year_month`=%s AND request_count < %s",
        (year_month, MONTHLY_QUOTA_LIMIT),
    )
    if cursor.rowcount == 1:
        return

    # Either no row exists yet for this month (rollover) or it's exhausted.
    # INSERT IGNORE only creates the row if genuinely missing; it is a no-op
    # if it already exists for any reason (exhausted, or a concurrent
    # reservation just created it), so this can't clobber a real count.
    cursor.execute(
        f"INSERT IGNORE INTO {_QUOTA_TABLE} (`year_month`, request_count) VALUES (%s, 0)",
        (year_month,),
    )
    cursor.execute(
        f"UPDATE {_QUOTA_TABLE} SET request_count = request_count + 1 "
        "WHERE `year_month`=%s AND request_count < %s",
        (year_month, MONTHLY_QUOTA_LIMIT),
    )
    if cursor.rowcount == 1:
        return

    raise SerpApiQuotaExceededError(
        f"SerpApi monthly quota exhausted ({MONTHLY_QUOTA_LIMIT}/{MONTHLY_QUOTA_LIMIT} "
        f"calls used for {year_month}). The fallback is unavailable until next month, "
        "or until MONTHLY_QUOTA_LIMIT is raised deliberately."
    )


# ─────────────────────────────────────────────
# Low-level HTTP: capped, timed-out GET against SerpApi
# ─────────────────────────────────────────────
def _redact_secret(text: str, secret: str) -> str:
    """Strip a known secret value out of arbitrary text before it can reach
    a caller. Needed because `api_key` is sent as a query parameter (SerpApi
    requires it that way), so a connection-level failure raised by
    `requests`/`urllib3` (e.g. `ConnectionError`/`MaxRetryError`) embeds the
    *full request URL, query string included* in its own `str()` — verified
    directly against `requests` behaviour, not assumed. `SerpApiError`
    messages are returned to ordinary authenticated users (not just admins)
    via `run_tool_generic()`/`mobile_lookup_report_pdf()`'s email_lookup
    branches, so the durable, reusable SERPAPI_KEY must never survive into
    one of those messages, including on a transient network blip."""
    if not secret:
        return text
    return text.replace(secret, "***REDACTED***")


def _call_serpapi(gaia_id: str, max_reviews: int, api_key: str) -> dict:
    params = {
        "engine": _SERPAPI_ENGINE,
        "contributor_id": gaia_id,
        "api_key": api_key,
        "hl": "en",
        "gl": "in",
        "num": max_reviews,
    }
    try:
        resp = requests.get(
            _SERPAPI_URL,
            params=params,
            timeout=_REQUEST_TIMEOUT,
            stream=True,
        )
    except requests.RequestException as exc:
        raise SerpApiError(
            f"Network error calling SerpApi: {_redact_secret(str(exc), api_key)}"
        ) from exc

    try:
        if resp.status_code != 200:
            raise SerpApiError(f"SerpApi returned HTTP {resp.status_code}.")

        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise SerpApiError(
                    f"SerpApi response exceeded the {_MAX_RESPONSE_BYTES}-byte cap; aborting."
                )
            chunks.append(chunk)
        body = b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        resp.close()

    try:
        data = json.loads(body)
    except ValueError as exc:
        raise SerpApiError(f"SerpApi returned a non-JSON response: {exc}") from exc

    if not isinstance(data, dict):
        raise SerpApiError("SerpApi response was not the expected JSON object shape.")

    if "error" in data:
        raise SerpApiError(f"SerpApi returned an error: {data.get('error')!r}")

    return data


# ─────────────────────────────────────────────
# Date parsing — defensive, never raises
# ─────────────────────────────────────────────
def _parse_date(raw):
    """Try ISO 8601, then a short list of absolute formats. Returns a
    tz-aware UTC datetime, or None if nothing matched (a relative string like
    "a month ago", or something unrecognized) — never raises."""
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw:
        return None

    iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in _ABSOLUTE_DATE_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


# ─────────────────────────────────────────────
# maps_url validation — never fabricate, only pass through a plausible link
# ─────────────────────────────────────────────
def _valid_google_maps_url(url):
    if not isinstance(url, str) or not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if parsed.scheme != "https":
        return None
    if "google.com" not in (parsed.netloc or "").lower():
        return None
    return url


# ─────────────────────────────────────────────
# Parsing — per-review extraction and profile mapping
# ─────────────────────────────────────────────
def _parse_review(entry) -> dict | None:
    """Parse a single SerpApi review entry. Returns None (skip, don't crash
    the batch) if the entry doesn't look review-shaped at all — mirrors how
    defensively `google_osint.py`'s own `_parse_review` is written, even
    though the two response shapes have nothing structurally in common."""
    if not isinstance(entry, dict):
        return None

    try:
        place_info = entry.get("place_info")
        if not isinstance(place_info, dict):
            place_info = {}

        business_name = place_info.get("title")
        if not isinstance(business_name, str):
            business_name = None

        business_address = place_info.get("address")
        if not isinstance(business_address, str):
            business_address = None

        gps = place_info.get("gps_coordinates")
        lat = lon = None
        if isinstance(gps, dict):
            maybe_lat = gps.get("latitude")
            maybe_lon = gps.get("longitude")
            if isinstance(maybe_lat, (int, float)):
                lat = float(maybe_lat)
            if isinstance(maybe_lon, (int, float)):
                lon = float(maybe_lon)

        maps_url = _valid_google_maps_url(entry.get("link"))

        comment = entry.get("snippet")
        comment = comment if isinstance(comment, str) else ""

        date_raw = entry.get("date")
        date_parsed = _parse_date(date_raw)

        rating = entry.get("rating")
        if not isinstance(rating, (int, float)):
            rating = None

        if not business_name and not comment:
            # Nothing usable extracted — likely not a review-shaped entry.
            return None

        result = {
            "business_name": business_name,
            "business_address": business_address,
            "maps_url": maps_url,
            "date": date_parsed,
            "comment": comment,
            "rating": rating,
            "lat": lat,
            "lon": lon,
        }
        if date_raw and date_parsed is None:
            # Unparseable date (e.g. a relative string like "a month ago") —
            # keep the original rather than silently dropping it.
            result["date_raw"] = date_raw
        return result
    except Exception:
        # Never let one malformed review take down the whole parse.
        return None


def _map_response(data: dict) -> dict:
    contributor = data.get("contributor")
    if not isinstance(contributor, dict):
        contributor = {}

    display_name = contributor.get("name")
    if not isinstance(display_name, str):
        display_name = None

    photo_url = contributor.get("thumbnail")
    if not isinstance(photo_url, str):
        photo_url = None

    contributions = contributor.get("contributions")
    total_reviews = contributions.get("reviews") if isinstance(contributions, dict) else None
    if not isinstance(total_reviews, int):
        total_reviews = None

    raw_reviews = data.get("reviews")
    if not isinstance(raw_reviews, list):
        raw_reviews = []

    reviews = []
    for entry in raw_reviews:
        parsed = _parse_review(entry)
        if parsed is not None:
            reviews.append(parsed)

    reviews.sort(
        key=lambda r: r["date"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    return {
        "display_name": display_name,
        "photo_url": photo_url,
        "total_reviews": total_reviews,
        "reviews": reviews,
    }


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────
def fetch_profile_and_reviews_via_serpapi(gaia_id: str, max_reviews: int = _DEFAULT_MAX_REVIEWS) -> dict:
    """Fetch a public Google Maps profile + reviews for the given GAIA id,
    via SerpApi's `google_maps_contributor_reviews` engine.

    This is the paid fallback for Step B, used ONLY after
    `google_osint.fetch_profile_and_reviews()` has already raised
    `GoogleOsintError` — never as a primary path. Costs one call against the
    `MONTHLY_QUOTA_LIMIT`-per-month budget, reserved atomically BEFORE the
    HTTP call is made; the reservation is not refunded if the call then
    fails.

    Returns the same shape as `google_osint.fetch_profile_and_reviews()`:
        {
            "display_name": str | None,
            "photo_url": str | None,
            "total_reviews": int | None,
            "reviews": [
                {
                    "business_name": str | None,
                    "business_address": str | None,
                    "maps_url": str | None,
                    "date": datetime | None,   # tz-aware, UTC
                    "comment": str,
                    "lat": float | None,
                    "lon": float | None,
                    # plus "rating" (int | float | None) and, only when the
                    # review's date could not be parsed, "date_raw" (str) —
                    # both additive, matching the extra fields
                    # google_osint.py's own review dicts already carry.
                },
                ...
            ],
        }

    Raises:
        `ValueError` — `gaia_id` empty, or `max_reviews` not a positive int.
        `SerpApiError` — `SERPAPI_KEY` not configured, network failure,
            non-200 response, or a malformed/error response body.
        `SerpApiQuotaExceededError` — the monthly call budget is already
            used up. Raised before any HTTP call is attempted.
    """
    gaia_id = (gaia_id or "").strip()
    if not gaia_id:
        raise ValueError("gaia_id is required")

    max_reviews = int(max_reviews)
    if max_reviews <= 0:
        raise ValueError("max_reviews must be a positive integer")
    max_reviews = min(max_reviews, _SERPAPI_NUM_HARD_CAP)

    api_key = os.environ.get("SERPAPI_KEY")
    if not api_key:
        raise SerpApiError("SERPAPI_KEY not configured")

    from app import db_conn  # deferred — see module docstring

    year_month = _current_year_month()
    with db_conn() as conn:
        cursor = conn.cursor(dictionary=True)
        try:
            _reserve_quota_slot(cursor, year_month)
            conn.commit()
        finally:
            cursor.close()

    data = _call_serpapi(gaia_id, max_reviews, api_key)
    return _map_response(data)

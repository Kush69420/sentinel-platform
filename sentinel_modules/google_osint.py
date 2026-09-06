"""Step B of the `email_lookup` module — GAIA id -> public Google Maps
profile (display name, photo, total review count) + public Maps reviews,
entirely unauthenticated. No credentials, no cookies, no browser: this half
of the module talks to one plain HTTP endpoint with a `User-Agent` header
and nothing else.

Endpoint
--------
`GET https://www.google.com/locationhistory/preview/mas` — the same XHR the
Google Maps "contributor profile" page (`maps/contrib/<gaia_id>/reviews/`)
calls client-side to render itself. The response body is a JSON array
prefixed with Google's `)]}'` XSSI guard, which must be stripped before
`json.loads`.

The `pb` query parameter is an opaque, undocumented protobuf-text field
mask. Two facts about it, both verified against live traffic while building
this module:

  * A session **token** segment (`!2m3!1s<token>!7e81`) is required — a
    request without one returns a 104-byte empty envelope
    (`data[15] == 3`, "empty"), regardless of anything else in `pb`.
  * A **tokenless** request still mints a fresh token, at `data[12]` of that
    same empty envelope. So the flow is bootstrap-then-fetch: one throwaway
    tokenless request to harvest a token, then the real request reusing it.
    Tokens are not single-use — the same harvested token was reused
    successfully across multiple calls in the same process during
    development — so it is cached in memory and only re-minted when Google
    starts rejecting it (`data[15] == 3` on what should be a real request).

The exact `pb` template used here for the real (non-bootstrap) request is
**not our own reverse-engineering** — it is GHunt's own
`templates["gmaps_pb"]["reviews"]["first"]` (read from the installed
package at `ghunt/config.py`, used by `ghunt/helpers/gmaps.py`), with
GHunt's own hardcoded example token replaced by our harvested one and its
hardcoded `!41m15!1i20` review-count segment reparametrized. That template,
substituted this way, was confirmed live during development to return
`data[15] == 0` (real payload, not the empty/error envelope) against the
public example account referenced throughout this project's research
(`111544054649252019208`) — see the module-level `_REVIEWS_PB_TEMPLATE`
docstring note below for exactly what was and was not confirmed.

Response layout (`d` = the parsed, XSSI-stripped JSON array)
--------------------------------------------------------------
  * `d[12]`  — session token (present on every response, including the
    empty bootstrap one).
  * `d[15]`  — status. `0` = real payload. `3` = empty/rejected (no token,
    dead token, or Google momentarily refusing the request).
  * `d[16]`  — the profile block, confirmed live:
      - `d[16][0]`  — display name (has appeared HTML-escaped in the wild,
        e.g. `Caro &amp; Keith Napier` — always `html.unescape()`d here
        before being returned; callers doing PDF/XML rendering are
        responsible for re-escaping for their own output format).
      - `d[16][1]`  — a nested block containing the profile photo URL as
        the sole `googleusercontent.com` string inside it (confirmed at
        `d[16][1][6][0]` on the one real account exercised during
        development, but located here by structural search — "the only
        URL in the block" — not by that fixed index, since GHunt's own
        source repeatedly warns this array's shape has shifted before).
      - `d[16][8][0]` — a list of contribution-type stat sections, each
        shaped `[type_id, ..., name_str, count_int, icon_url, ?,
        human_str]` (e.g. `[1, None, None, None, None, None, "Reviews", 1,
        "https://maps.gstatic.com/.../review.png", 1, "1 review"]`). The
        `"Reviews"` section's count is used as `total_reviews`.
  * The reviews list itself — **NOT verified against a live populated
    response**. See the "What was and was not verified" note in
    `fetch_profile_and_reviews`'s docstring: every live account exercised
    while building this module returned a real (`status == 0`) profile
    block but a structurally-empty reviews collection (Google represents an
    absent/empty high-numbered optional field as a trailing `{"46": []}`
    object appended after the main positional array, rather than a 46th
    positional slot — both shapes are handled defensively here). The
    per-review field layout implemented below (`_parse_review`) is a
    best-reasoned reconstruction from GHunt's own **commented-out, never-
    completed** parser for this same response (`ghunt/helpers/gmaps.py`,
    `get_reviews()` — the real implementation is dead code behind `if
    False`-equivalent comments and stray `pdb.set_trace()` calls, which is
    itself evidence GHunt's authors never finished verifying it either).
    Treat every field extracted by `_parse_review` as unverified until
    checked against a real populated response.

Date handling
-------------
Review timestamps in the (unverified) review shape are microsecond Unix
epoch integers. They are converted to full, precise UTC `datetime` objects
here — never truncated to a date and re-stamped with a fixed clock time.
The reference vendor's own report generator has a known bug where every
printed timestamp shows exactly `05:30:00` (India's UTC+5:30 offset applied
to a date-only value, i.e. a lossy date-then-offset conversion) — this
module deliberately does not reproduce that. Downstream display code is
expected to call `.astimezone(ZoneInfo("Asia/Kolkata"))` (or equivalent) on
the tz-aware UTC datetimes returned here, which preserves the real
time-of-day.
"""
import html
import re
import time
import urllib.parse
from datetime import datetime, timezone

import requests

__all__ = [
    "fetch_profile_and_reviews",
    "GoogleOsintError",
]

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
_MAS_URL = "https://www.google.com/locationhistory/preview/mas"
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"

_REQUEST_TIMEOUT = 20  # seconds, per HTTP call
_MAX_RESPONSE_BYTES = 3 * 1024 * 1024  # hard cap; real responses were ~few KB
_DEFAULT_MAX_REVIEWS = 20

_STATUS_OK = 0
_STATUS_EMPTY = 3

# Bootstrap: tokenless request, used only to harvest a fresh session token.
_BOOTSTRAP_PB_TEMPLATE = "!1s{gaia_id}!6m2!1i0!2i0"

# The real request. This is GHunt's own `templates["gmaps_pb"]["reviews"]["first"]`
# (ghunt/config.py), transcribed with its hardcoded example token replaced by
# `{token}` and its hardcoded `!41m15!1i20` review-count replaced by
# `{max_reviews}`. `{gaia_id}` slots into the same `!1s{}` GHunt uses for the
# *contributor's own* gaia id (this is the contributor-profile reviews XHR,
# not the place-reviews XHR — confirmed by reading `ghunt/helpers/gmaps.py`,
# which calls this exact template with a gaia id, not a place id). The
# `18m15` segment is a map viewport (Sydney, Australia, in GHunt's own
# hardcoded template) — varying it during development did not change
# results, so it is left as-is rather than guessed at further.
_REVIEWS_PB_TEMPLATE = (
    "!1s{gaia_id}!2m3!1s{token}!7e81!15i14416!6m2!4b1!7b1!9m0!17m28"
    "!1m6!1m2!1i0!2i0!2m2!1i530!2i1279"
    "!1m6!1m2!1i3390!2i0!2m2!1i3440!2i1279"
    "!1m6!1m2!1i0!2i0!2m2!1i3440!2i20"
    "!1m6!1m2!1i0!2i1259!2m2!1i3440!2i1279"
    "!18m15!1m3!1d2834470.167608874!2d150.05636185!3d-33.57307085"
    "!2m3!1f0!2f0!3f0!3m2!1i3440!2i1279!4f13.1"
    "!6m2!1f0!2f0"
    "!41m15!1i{max_reviews}!2m9!2b1!3b1!5b1!7b1!12m4!1b1!2b1!4m1!1e1!3sCAESA0VnQQ=="
    "!7m2!1m1!1e1"
)

# In-memory token cache. Deliberately not persisted (see module docstring
# and the plan doc: "do not over-engineer this, fresh process re-bootstrap
# cheaply"). A single slot is enough — one token works for any gaia id.
_TOKEN_CACHE = {"token": None, "minted_at": None}


# ─────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────
class GoogleOsintError(Exception):
    """Raised on network failure, a malformed/unrecognized response, or
    repeated status-3 (empty/rejected) responses even after a
    re-bootstrap-and-retry.

    Callers must treat this as "we could not fetch this profile", never
    silently return an empty-looking result — a caller that charges credits
    per lookup must not charge for this outcome.
    """


# ─────────────────────────────────────────────
# Low-level HTTP: capped, timed-out GET with the XSSI guard stripped
# ─────────────────────────────────────────────
def _build_url(pb: str) -> str:
    # A single clean percent-encoding pass over the whole pb string, with
    # '!' left literal (Google expects it unescaped) and everything else
    # (including '=' from the trailing base64 field) encoded normally.
    encoded_pb = urllib.parse.quote(pb, safe="!")
    query = urllib.parse.urlencode(
        {"authuser": "0", "hl": "en", "gl": "in"}, safe=""
    )
    return f"{_MAS_URL}?{query}&pb={encoded_pb}"


def _get_envelope(pb: str) -> list:
    """GET the `mas` endpoint with the given `pb`, enforce a size cap and
    timeout, strip the XSSI guard, and return the parsed JSON array.
    Raises `GoogleOsintError` on any network, size, or parse failure."""
    url = _build_url(pb)
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": _USER_AGENT},
            timeout=_REQUEST_TIMEOUT,
            stream=True,
        )
    except requests.RequestException as exc:
        raise GoogleOsintError(f"Network error calling Google Maps: {exc}") from exc

    try:
        if resp.status_code != 200:
            raise GoogleOsintError(
                f"Google Maps returned HTTP {resp.status_code} for the profile/reviews request."
            )

        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise GoogleOsintError(
                    f"Response exceeded the {_MAX_RESPONSE_BYTES}-byte cap; aborting."
                )
            chunks.append(chunk)
        body = b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        resp.close()

    if body.startswith(")]}'"):
        body = body.split("\n", 1)[1] if "\n" in body else body[4:]

    try:
        import json

        data = json.loads(body)
    except ValueError as exc:
        raise GoogleOsintError(f"Google Maps returned a non-JSON response: {exc}") from exc

    if not isinstance(data, list):
        raise GoogleOsintError("Google Maps response was not the expected JSON array shape.")

    return data


def _bootstrap_token(gaia_id: str) -> str:
    """Tokenless request whose only purpose is harvesting a fresh session
    token from index 12 of the (otherwise empty) response envelope."""
    pb = _BOOTSTRAP_PB_TEMPLATE.format(gaia_id=gaia_id)
    data = _get_envelope(pb)
    token = data[12] if len(data) > 12 else None
    if not token or not isinstance(token, str):
        raise GoogleOsintError(
            "Bootstrap request did not yield a session token at the expected "
            "position — Google's response shape may have changed."
        )
    return token


def _get_cached_token(gaia_id: str) -> str:
    token = _TOKEN_CACHE.get("token")
    if token:
        return token
    token = _bootstrap_token(gaia_id)
    _TOKEN_CACHE["token"] = token
    _TOKEN_CACHE["minted_at"] = time.time()
    return token


def _invalidate_cached_token() -> None:
    _TOKEN_CACHE["token"] = None
    _TOKEN_CACHE["minted_at"] = None


def _fetch_real_envelope(gaia_id: str, max_reviews: int) -> list:
    """Fetch the real profile+reviews envelope, re-bootstrapping the token
    once and retrying if the cached one has gone stale (status 3 on what
    should be a real request)."""
    token = _get_cached_token(gaia_id)
    pb = _REVIEWS_PB_TEMPLATE.format(gaia_id=gaia_id, token=token, max_reviews=int(max_reviews))
    data = _get_envelope(pb)
    status = data[15] if len(data) > 15 else None

    if status == _STATUS_OK:
        return data

    if status == _STATUS_EMPTY:
        # Cached token likely expired mid-session — re-bootstrap once and retry.
        _invalidate_cached_token()
        token = _get_cached_token(gaia_id)
        pb = _REVIEWS_PB_TEMPLATE.format(gaia_id=gaia_id, token=token, max_reviews=int(max_reviews))
        data = _get_envelope(pb)
        status = data[15] if len(data) > 15 else None
        if status == _STATUS_OK:
            return data
        raise GoogleOsintError(
            "Google Maps kept returning an empty/rejected envelope (status 3) "
            "even after re-bootstrapping the session token. This gaia id may "
            "not exist, or Google may be temporarily throttling this IP."
        )

    raise GoogleOsintError(f"Google Maps returned an unrecognized status ({status!r}).")


# ─────────────────────────────────────────────
# Parsing — profile block (verified against a real live response)
# ─────────────────────────────────────────────
def _find_photo_url(node) -> str | None:
    """Structural search for the profile photo URL: the only
    `googleusercontent.com` string anywhere inside the profile block.
    Deliberately not anchored to a fixed index — this project's own prior
    research found this response's array shape has shifted before."""
    if isinstance(node, str):
        return node if "googleusercontent.com" in node else None
    if isinstance(node, list):
        for item in node:
            found = _find_photo_url(item)
            if found:
                return found
    return None


def _extract_total_reviews(profile_block: list) -> int | None:
    """Find the "Reviews" stat section inside d[16][8][0] and return its
    count. Defensive: tolerates the stats list being absent, short, or
    reshaped, and falls back to parsing the leading integer out of the
    human-readable string (e.g. "212 reviews") if the count field itself
    is missing or not an int."""
    try:
        sections = profile_block[8][0]
    except (IndexError, TypeError, KeyError):
        return None
    if not isinstance(sections, list):
        return None

    for section in sections:
        if not isinstance(section, list) or len(section) < 7:
            continue
        name = section[6] if len(section) > 6 else None
        if name != "Reviews":
            continue
        count = section[7] if len(section) > 7 else None
        if isinstance(count, int):
            return count
        human = section[10] if len(section) > 10 else None
        if isinstance(human, str):
            match = re.search(r"\d+", human)
            if match:
                return int(match.group())
        return None
    return None


def _parse_profile(data: list) -> dict:
    try:
        profile_block = data[16]
    except (IndexError, TypeError):
        raise GoogleOsintError("Response had no profile block (d[16]) at all.")
    if not isinstance(profile_block, list):
        raise GoogleOsintError("Response's profile block (d[16]) was not a list as expected.")

    display_name = profile_block[0] if profile_block and isinstance(profile_block[0], str) else None
    if display_name:
        display_name = html.unescape(display_name)

    photo_url = None
    if len(profile_block) > 1:
        photo_url = _find_photo_url(profile_block[1])

    total_reviews = _extract_total_reviews(profile_block)

    return {
        "display_name": display_name,
        "photo_url": photo_url,
        "total_reviews": total_reviews,
    }


# ─────────────────────────────────────────────
# Parsing — per-review extraction
#
# UNVERIFIED against a live populated response — see the module docstring's
# "What was and was not verified" note. This is a best-reasoned
# reconstruction of GHunt's own dead/commented-out parser for this same
# endpoint. Every field access below is bounds-checked and wrapped so one
# malformed review cannot crash the rest of the parse.
# ─────────────────────────────────────────────
_DATA_ID_RE = re.compile(r"^0x[0-9a-f]+:0x[0-9a-f]+$")


def _safe_index(seq, idx):
    if not isinstance(seq, (list, tuple)):
        return None
    if idx < 0 or idx >= len(seq):
        return None
    return seq[idx]


def _maps_url_from_data_id(data_id: str) -> str | None:
    if not isinstance(data_id, str) or not _DATA_ID_RE.match(data_id):
        return None
    try:
        cid_hex = data_id.split(":", 1)[1]
        cid = int(cid_hex, 16)
    except (ValueError, IndexError):
        return None
    return f"https://www.google.com/maps?cid={cid}"


def _parse_review(review_data) -> dict | None:
    """Parse a single review entry. Returns None (skip, don't crash) if the
    entry doesn't look like a review at all."""
    if not isinstance(review_data, list):
        return None

    try:
        review_meta = _safe_index(review_data, 2)
        location = _safe_index(review_data, 4)

        comment = None
        rating = None
        date = None
        if isinstance(review_meta, list):
            ts_block = _safe_index(review_meta, 1)
            ts_micros = _safe_index(ts_block, 3)
            if isinstance(ts_micros, (int, float)):
                date = datetime.fromtimestamp(ts_micros / 1_000_000, tz=timezone.utc)

            content_block = _safe_index(review_meta, 2)
            if isinstance(content_block, list):
                rating_block = _safe_index(content_block, 0)
                rating = _safe_index(rating_block, 0)
                comment_block = _safe_index(content_block, 15)
                comment_text = _safe_index(_safe_index(comment_block, 0), 0)
                if isinstance(comment_text, str):
                    comment = html.unescape(comment_text)

        business_name = None
        business_address = None
        maps_url = None
        lat = None
        lon = None
        if isinstance(location, list):
            name = _safe_index(location, 2)
            if isinstance(name, str):
                business_name = html.unescape(name)
            address = _safe_index(location, 3)
            if isinstance(address, str):
                business_address = html.unescape(address)

            data_id_block = _safe_index(location, 14)
            data_id = _safe_index(data_id_block, 0)
            maps_url = _maps_url_from_data_id(data_id)

            position = _safe_index(location, 0)
            if isinstance(position, list):
                maybe_lat = _safe_index(position, 2)
                maybe_lon = _safe_index(position, 3)
                if isinstance(maybe_lat, (int, float)):
                    lat = float(maybe_lat)
                if isinstance(maybe_lon, (int, float)):
                    lon = float(maybe_lon)

        if not business_name and not comment:
            # Nothing usable extracted — likely not a review-shaped entry.
            return None

        return {
            "business_name": business_name,
            "business_address": business_address,
            "maps_url": maps_url,
            "date": date,
            "comment": comment or "",
            "rating": rating,
            "lat": lat,
            "lon": lon,
        }
    except Exception:
        # Never let one malformed review take down the whole parse.
        return None


def _extract_raw_reviews(data: list) -> list:
    """Locate the reviews collection. Google represents this response's
    high-numbered optional/repeated field 46 (0-indexed 45, matching
    GHunt's own `data[45]` access) either as a trailing `{"46": [...]}`
    object appended after the main positional array (observed live, always
    empty on the accounts exercised during development), or — per GHunt's
    own code, presumably valid for some other response shape — as a plain
    46th element of the positional array itself. Both are checked
    defensively; neither has been observed non-empty."""
    if len(data) > 45:
        candidate = data[45]
        if isinstance(candidate, list):
            return candidate

    for item in data:
        if isinstance(item, dict) and isinstance(item.get("46"), list):
            return item["46"]

    return []


def _parse_reviews(data: list) -> list:
    raw_reviews = _extract_raw_reviews(data)
    reviews = []
    for entry in raw_reviews:
        # Each entry has been observed (in related, unverified reasoning)
        # wrapped one level deeper, e.g. `[review_data]` or `review_data`
        # directly depending on field shape — try both defensively.
        candidate = entry
        parsed = _parse_review(candidate)
        if parsed is None and isinstance(entry, list) and len(entry) == 1:
            parsed = _parse_review(entry[0])
        if parsed is not None:
            reviews.append(parsed)

    reviews.sort(key=lambda r: r["date"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return reviews


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────
def fetch_profile_and_reviews(gaia_id: str, max_reviews: int = _DEFAULT_MAX_REVIEWS) -> dict:
    """Fetch a public Google Maps profile (display name, photo, total
    review count) and up to `max_reviews` of that profile's public Maps
    reviews, for the given GAIA id. Entirely unauthenticated.

    Returns:
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
                },
                ...
            ],
        }

    Raises `GoogleOsintError` on network failure, a malformed/unrecognized
    response, or repeated status-3 responses even after a
    re-bootstrap-and-retry. Never returns a silently-empty result to mean
    "couldn't fetch" — a profile that genuinely has zero public reviews
    returns normally with `reviews: []`; a fetch failure always raises.

    What was and was not verified (2026-09-05, live, against the public
    example account `111544054649252019208` referenced throughout this
    project's research):

      * VERIFIED live: the bootstrap-token flow, the `!2m3!1s<token>!7e81`
        token segment being required, `display_name`, `photo_url`, and
        `total_reviews` all round-tripped correctly against real
        `status == 0` responses across five separate live requests
        (bootstrap, a stats-shaped fetch, and three reviews-shaped fetches
        with `max_reviews` at 5, 50, and a world-spanning viewport
        variant).

      * NOT verified: the shape of an actual *populated* reviews list.
        Every one of those live requests returned a genuinely empty
        reviews collection (`{"46": []}`) despite the account's own stats
        block reporting "1 review, 1 rating" — plausibly because that
        single interaction is a bare star rating with no written text
        (Google's stats bucket may count it under "Reviews" without it
        ever appearing in the written-reviews feed this endpoint serves),
        or plausibly because of some other still-undiscovered request
        parameter. Varying the review count (5, 50) and the map viewport
        embedded in `pb` made no difference. `_parse_review` above is
        therefore a best-reasoned reconstruction from GHunt's own
        commented-out, never-completed parser for this exact endpoint —
        not a verified structure. It is written defensively (bounds-
        checked, wrapped in `try/except`, skips anything that doesn't look
        review-shaped) specifically because of this. A human should
        confirm it against a real account with visible written reviews
        before this ships.
    """
    gaia_id = (gaia_id or "").strip()
    if not gaia_id:
        raise ValueError("gaia_id is required")

    max_reviews = int(max_reviews)
    if max_reviews <= 0:
        raise ValueError("max_reviews must be a positive integer")

    data = _fetch_real_envelope(gaia_id, max_reviews)

    profile = _parse_profile(data)
    reviews = _parse_reviews(data)

    return {
        "display_name": profile["display_name"],
        "photo_url": profile["photo_url"],
        "total_reviews": profile["total_reviews"],
        "reviews": reviews,
    }

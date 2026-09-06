# Plan — Email Lookup Module (`email_lookup`)

**Status:** approved in shape 2026-09-04; step-B spike done, step A resolved 2026-09-04 —
working GHunt master token obtained; build direction is direct reimplementation (own
cookie-minting + SAPISIDHASH signing + People API call), not a dependency on GHunt's own
(buggy) parser. See `sentinel_modules/gaia_resolver.py` once built.
**Deliverable spec:** `/media/nyx/WD Black/Sentinel/email-output.pdf` — a competitor
("C-TRACE") E-Mail OSINT report. That PDF *is* the acceptance criterion.

## What the module actually is

**Google account OSINT, not a subscriber-database lookup.** An earlier draft of this plan
proposed reverse-lookup on `subscriber_records.email`; the reference report contains none
of that and the draft was discarded. Every section resolves a Gmail address to its Google
account and reports the public footprint.

| § | Section | Data | Source |
|---|---|---|---|
| 1 | Branded header + confidentiality note | static | `app_settings` |
| 2 | SUBJECT INFORMATION | email, report date, officer phone | request + `session["user_phone"]` |
| 3 | NAME's | names on the account | Google profile |
| 4 | Google Profile History | display name, last update, 21-digit GAIA ID, photo, `maps/contrib/<gaia>/reviews/` | Google profile |
| 5 | Google Reviews *(repeating)* | business, address, Maps hyperlink, date, comment | Maps contributions |
| 6 | Images | profile photo, full size | remote image fetch |
| 7 | Legal Disclaimer | static boilerplate | `app_settings` |

## Where the module will live

| Piece | Location |
|---|---|
| Runner branch | `run_tool_generic()`, `app.py:2434` — new `if code == "email_lookup"` |
| Credit/audit | `charge_for_lookup()`, `app.py:2381` — reuse verbatim |
| Catalog gate | `services.status`, flipped off `upcoming` by a new migration |
| Public tiles | `OSINT_TOOLS` `app.py:805`; `fallbackOsint` `templates/dashboard.html:151` |
| PDF | new builder; route `app.py:2759` becomes type-dispatched |
| Subprocess machinery | `_build_cli_argv()` / `_resolve_cli_binary()` `app.py:4345-4400`, `external_tool_jobs` |

The front-end needs almost nothing: `openTool()` already renders a generic query box for
any non-CDR tool and `runGenericTool()` posts to `/api/tools/run`.

## The pipeline splits into two halves of very different difficulty

### Step A — email → GAIA ID. Hard. **Blocked.**

No official or unauthenticated API exists. Every working technique, GHunt included, drives
Google's internal People endpoints with a credential from a **logged-in Google account**.

**Hard production constraint (stated 2026-09-04): no manual interference. Repeated
re-authentication is not acceptable.** This rules out raw browser cookies
(`__Secure-1PSID`, `__Secure-1PSIDTS`, `__Secure-1PSIDCC`) — they expire in weeks and
would need a human on every rotation.

**Be honest about the ceiling:** *no* Google-scraping approach is zero-touch in
perpetuity. Any credential Google issues can die from a password change, a security flag
or a ToS ban. The achievable target is **rare, alerted intervention** — months, not never.
Design for graceful degradation, not for a credential that lasts forever.

Two options survive the constraint:

1. **Android master token** (`aas_et/...`) instead of cookies. GHunt accepts one. It
   *mints fresh cookies on demand*, so it is self-renewing: one-time manual setup, then
   unattended until password change or ban. Free. This is the direct answer to the
   constraint.
2. **Commercial OSINT provider.** Turns an operational problem into a billing problem —
   the vendor maintains accounts and absorbs breakage. Genuinely hands-off. Costs money
   and carries onboarding lead time, same shape as the deferred UPI work.

Either way the credential lives in `integrations`, encrypted under `ENCRYPTION_KEY`, with
`last_status`/`last_error` surfacing "credential dead" to an admin instead of failing
silently at lookup time.

ToS note: this violates Google's terms and the hunter account may be banned. **Never a
personal or work account.** Target ≠ hunter — the target is just a string.

### The mitigation that shrinks all of this: cache the GAIA ID

**Step A runs once per email address, ever. Step B is credential-free and unlimited.**
Persist `email → gaia_id` on first resolution. A dead credential then degrades the module
rather than downing it: previously-seen addresses keep working, every existing report
stays re-printable, and only first-time lookups of *new* addresses fail. This is the
single highest-leverage design decision in the module and should not be deferred.

### Step B — GAIA ID → profile + reviews. **SOLVED. Plain HTTP, no credentials, no browser.**

**Headline: one unauthenticated `curl` with a User-Agent returns everything.** No cookies,
no headless Chrome, no browser in the container. This resolves the architecture question
in the cheapest possible direction.

Spike, 2026-09-04, against the GAIA ID visible in the reference PDF
(`111544054649252019208`):

- `curl` of `https://www.google.com/maps/contrib/<GAIA_ID>/reviews/` returns HTTP 200 and
  207 KB of **JS shell — zero data**. Plain HTML scraping is a dead end.
- Headless Chrome (`--headless=new --dump-dom --virtual-time-budget=20000`) renders it and
  contains **every field in the reference PDF**: the profile name, both review subjects
  ("Swaraj Tractors", "MMI Narayana Hospital") and the review comment ("Baderajpur").

This confirms the vendor behind the reference report is using exactly this source, and
that sections 3–6 are obtainable.

Net-log capture identified the underlying XHR, and replaying it with plain `curl` —
**no cookies, User-Agent only** — returns HTTP 200 and 12.8 KB of structured JSON:

```
https://www.google.com/locationhistory/preview/mas?authuser=0&hl=en&gl=in&pb=!1s<GAIA_ID>...
```

Response is a `)]}'`-prefixed JSON array. Everything the reference report needs is in it:

| Report field | Where it comes from |
|---|---|
| §3 NAME's, §4 Profile Name | `d[16][0]` — "Jitendra Kumar Markam" |
| §4 Profile ID | GAIA echoed back in `d[16]` |
| §4 photo, §6 Images | `lh3.googleusercontent.com/a/...=s120-c-rp-mo-br100` — swap `=s120` for full size |
| §4 Reviews link | `maps/contrib/<gaia>/reviews` returned directly |
| §5 business, address | per-review, e.g. "Swaraj Tractors - M/S Shiv Shakti Agro" + full address |
| §5 Maps hyperlink | **lat/lon returned** — we build the link, no scraping |
| §5 comment | e.g. "Baderajpur" |
| §5 review date | microsecond epoch timestamps |
| *(bonus, not in reference)* | star ratings, Local Guide level, contribution counts |

**Date accuracy note.** The reference PDF prints `08-02-2026` / `08-08-2021`, both at
exactly `05:30:00` — the IST offset, i.e. a lossy date-only conversion. The real
timestamps decode to Jan 2026 and Jul 2021. Our dates can be *more* accurate than
C-TRACE's. Confirm we want correctness rather than bug-compatibility.

**The `!2m3!1s<token>!7e81` session token is REQUIRED.** Tested and confirmed: a `pb`
carrying the full `!14m60!1m49...` field mask but *no* token returns the same 104-byte
empty envelope (status `3`) as a minimal `pb`. Only the token-bearing request returns
status `0` and data. (An earlier guess that the field mask was the differentiator was
wrong.) So the `pb` is **not** a fully static template.

Two things make this cheap to live with rather than a blocker:

1. **The token is not single-use or short-lived.** The working request used a token
   captured from a headless-Chrome run minutes earlier, and it was accepted.
2. **A tokenless request still mints a token.** Both empty 104-byte responses carried a
   fresh token at array index 12. That makes the tokenless call a **bootstrap**: one
   throwaway 104-byte request to harvest a token, then the real request.

If a harvested token is accepted (test queued), step B is **two stateless HTTP calls, no
browser, no cookies** — harvest, then fetch, with the token cached and reused across
lookups until it starts returning status `3`, at which point re-bootstrap. If a harvested
token is *rejected* and only browser-minted ones work, the fallback is a periodic headless
Chrome run purely to mint tokens — still not a browser in the request path.

## Open questions — answer before building

1. ~~**Does `locationhistory/preview/mas` replay over plain HTTP without cookies?**~~
   **ANSWERED 2026-09-04: yes.** No browser in the request path, no cookies.
   Remaining sub-question: the `!2m3!1s<token>!7e81` segment is **required** (confirmed),
   so is a token harvested from a cheap tokenless bootstrap call accepted, or must tokens
   be browser-minted? Decides one-call-plus-bootstrap vs. a periodic token-minting job.
   (Test queued.)
1b. **Pagination — RESOLVED 2026-09-04.** The review-count knob is `!41m14!1i<N>`, not
   `!4m1!3i<N>` (that segment is image dimensions, unrelated). Confirmed N=10→10,
   N=50→50 reviews returned; the default (no `!41m14` segment) silently truncates to 10,
   verified against a 212-review test account. Use `!41m14!1i20` per the 20-review cap
   decision below.
2. **Master token or commercial provider?** Cookies are out (see constraint above).
   The master token is free and self-renewing but still dies eventually; a provider is
   genuinely hands-off but costs money and has onboarding lead time. Build the Google
   client behind one interface so either implementation plugs in and the choice is
   reversible.
3. **Rate limiting and caching.** Google will throttle. Does a GAIA→reviews result get
   cached, and for how long? Bears on both cost and evidentiary freshness.

## The PDF is a rewrite, not an extension

`_build_mobile_lookup_pdf()` is a flat label/value table. This report needs a branded
header band, chevron section headers, inline hyperlinks (the red "Click Here to Open
Google Map"), embedded remote images, repeating review blocks and a full-page disclaimer.

- `reportlab.platypus.Image` is not imported today (`app.py:47-51`). Image embedding is new.
- **Fetching remote profile photos is an SSRF surface.** `_http_json()` has no scheme or
  host allowlist, no private-IP block and no size cap. The new fetch helper needs all
  three plus content-type validation.
- Hyperlinks mean `<link href>` inside a `Paragraph`. This **must not regress the Day-2
  XML-escaping fix** — URLs get attribute-escaped and scheme-validated separately from
  display text.

## Mandatory fix, independent of the rest

`mobile_lookup_report_pdf()` (`app.py:2759`) **never checks `search_type`.** It takes any
`search_log_id` the caller owns and queries `subscriber_records WHERE mobile_number =
<query_value>`. The dashboard renders the PDF button whenever `search_log_id` is present
(`dashboard.html:292`). The day `email_lookup` goes live, every email search shows a
button that 404s with a misleading *"Underlying subscriber record no longer exists."*
The route becomes type-dispatched.

## Build order

1. Resolve open question 1 (plain HTTP vs headless Chrome).
2. Step-A spike once cookies exist: prove `kushagr250@gmail.com` → GAIA ID.
3. Google client behind one seam, so step A's fragility stays isolated and step B stays
   cheap to test.
4. `migration_email_lookup.sql` — idempotent, flips `services.status='enabled'` for
   `email_lookup`. Register in `deploy/db-init/00-apply-schema.sh` **in order**; there is
   still no migration runner, so ordering is manual and load-bearing. Add to `CLAUDE.md`.
5. Runner branch: validate the email **before** billing; reuse `charge_for_lookup()`
   (charge on hit only, always write `search_logs`).
6. PDF builder + type-dispatched route.
7. Catalog metadata at `app.py:805` and `dashboard.html:151`.
8. Tests: `tests/test_email_lookup.py` mirroring `test_mobile_lookup_credits.py`
   (charge-on-hit, no-charge-on-miss, always-log, insufficient-credits, concurrent debit)
   and `test_mobile_lookup_pdf_report.py` (ownership scoping, cross-type guard), Google
   client mocked, plus explicit SSRF cases on the image fetcher.

## Note on the CLI-execution security debt

`CLAUDE.md` lists `/api/admin/tools/<id>/cli-test` as "admin-to-RCE". **That note predates
the fix** at `app.py:4345-4400`: templates are shlex-split *before* `{query}` substitution
(so a query can never be re-parsed into extra argv), and `_resolve_cli_binary()` enforces
an env-configured, **deny-by-default** allowlist resolved through symlinks on both sides.
The machinery is sound. The remaining work is that this path is admin-only today and needs
a vetted user-facing entry point. Update that CLAUDE.md entry when this lands.

## Explicitly out of scope

- **RBAC / `role_required` / admin seed** — deferred to the planned OAuth2 work.
- **Shared-store rate limiter** — its own piece of work.
- **`subscriber_records.email` reverse lookup** — we own that data and it would slot in as
  an extra section, but it is not in the reference report. Not widening scope unasked.
- GHunt is **AGPL-3.0**. Matters only if this is ever distributed rather than hosted.

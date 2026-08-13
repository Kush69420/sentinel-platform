# Day 2 — Security hardening (fail-fast secrets, CSRF, headers, and four smaller fixes)

Builds on Day 1 (`day1-selfserve-auth`, merged into `main` at `93eb4bb`) — nothing here
touches signup, LEA clearance, or credits/payments. Branch: `day2-security`, off `main`.

Everything below is committed on `day2-security`, one logical fix per commit, in the
priority order the work was scoped in (highest blast radius first):

1. Fail-fast secrets
2. CSRF protection
3. Session cookie hardening + security headers
4. `/api/admin/login` IP rate limit
5. `/uploads` path-traversal guard + `/api/events` auth and bounded connections
6. PDF report injection escaping
7. (documentation only — see "Known limitation, not fixed" below)

---

## 1. Fail-fast secrets

`app.py` used to fall back to a hardcoded `SECRET_KEY` (`"dev_secret_change_this"`) and
generate a throwaway `ENCRYPTION_KEY` at **every restart** if either was unset in the
environment — the first makes session cookies (including `is_admin=True`) forgeable, the
second silently and permanently bricks every previously-encrypted gov-ID upload, 2FA
secret, and stored API key the moment the app restarts without the original key.

Neither failure was visible until something else broke.

`FLASK_ENV` now gates both. An **unset** `FLASK_ENV` is treated as production-like (fail
closed, not open) — only `FLASK_ENV=development` keeps the old warn-and-fall-back
behavior for local dev. Outside dev, a missing `SECRET_KEY` or `ENCRYPTION_KEY` now
raises `RuntimeError` at import/startup with a message telling you exactly what to
generate and where to put it.

**This is why `CLAUDE.md`'s "Pending — must be done before deployment" checklist changed**:
step 2 (copy the new `.env.example` keys into `.env`) is no longer optional busywork —
outside `FLASK_ENV=development` the app will not start without real `SECRET_KEY` and
`ENCRYPTION_KEY` values.

`tests/__init__.py` sets `FLASK_ENV=development` before any test module imports `app`
(unittest discover imports the package first), since the suite never provides real
secrets and needs the same dev fallback local `flask run` gets.

## 2. CSRF protection

No CSRF protection existed anywhere: no tokens, no `SameSite` cookie config. Every
session-authenticated state-changing endpoint was forgeable by a page the victim's
browser merely had open while logged in — the browser attaches session cookies to
cross-site requests automatically, and Flask's default cookie config has no `SameSite`
restriction to stop that.

**Backend** (`app.py`): a random token (`secrets.token_urlsafe(32)`) is minted into the
session at login — `user_login()`, `admin_login()`, and `user_signup()` (signup
auto-logs the account in, so it needed one too) — and returned in the response JSON.
`_enforce_csrf()`, a `before_request` hook, requires that same token echoed back in the
`X-CSRF-Token` header on every `POST`/`PUT`/`DELETE` once a session is authenticated
(`is_user` or `is_admin`), compared with `hmac.compare_digest`. `GET`/`HEAD`/`OPTIONS`
are never checked. Unauthenticated requests (signup, login itself, password-reset
request/confirm) are deliberately exempt — there is no session yet to protect, and
standing up a pre-session anonymous CSRF cookie was judged unneeded complexity for this
threat model. `GET /api/csrf-token` issues (or returns) the current session's token.

A session that's authenticated but has no `csrf_token` yet (e.g. one predating this
change) fails closed on the next state-changing request rather than being waved through
— confirmed in `tests/test_csrf.py`.

**Frontend — a judgment call worth flagging explicitly:** the brief called for updating
all 54 individual `fetch()` call sites across 8 templates. Instead, the 3 templates that
actually issue an *authenticated* state-changing call — `admin.html` (40 calls),
`dashboard.html` (9), `pricing.html` (1, the `/api/payments/checkout` call, reachable by
a signed-in visitor from the public pricing page) — get a small IIFE that overrides
`window.fetch` to lazily fetch and cache the token, then attach it to every
`POST`/`PUT`/`DELETE` automatically. The other 5 templates with any `fetch()` call
(`index.html`, `login.html`, `register.html`, `reset_password.html`, `workspace.html`)
either have none that are state-changing, or their state-changing calls
(signup/login/password-reset) are pre-session and correctly exempt by design.

This covers all 54 call sites functionally (every one of them ends up sending the
header) with far less risk than 54 manual edits across large, largely-minified
templates — one missed or mistyped call site in a hand-edit would silently reintroduce
the hole on just that action. `tests/test_csrf.py`'s `FrontendCsrfSweepTest` is the
generic guard against regression here: it asserts the 3 wrapped templates install the
wrapper before any other script code, and that the 5 "exempt" templates truly have
nothing but GET/unauthenticated-POST `fetch()` calls — so a new authenticated
state-changing call added to one of the exempt templates later, without the wrapper,
fails the test rather than shipping silently broken.

`tests/test_mobile_lookup_credits.py` and `tests/test_user_auth.py` needed small updates
— both hit authenticated `POST` endpoints (a hand-crafted session in the former, a real
login in the latter) and now need to supply the token like any other caller.

## 3. Session cookie hardening + security headers

No `SESSION_COOKIE_SECURE`/`SAMESITE` config existed (confirmed `HTTPONLY` was already
just Flask's insecure default). Now: `SESSION_COOKIE_HTTPONLY=True` and
`SESSION_COOKIE_SAMESITE="Lax"` unconditionally; `SESSION_COOKIE_SECURE` defaults to
`True` (fail closed), relaxed to `False` only under `FLASK_ENV=development` so local
`http://localhost` still works.

No `after_request` hook existed at all. A new one sets `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and a `Content-Security-Policy`. HSTS is added only outside dev
**and** only when the request actually arrived over HTTPS (`request.is_secure`) —
sending it over plain HTTP would be pointless at best.

**CSP specifics, another judgment call:** the policy allows `'unsafe-inline'` for both
`script-src` and `style-src`. Every one of the 9 templates ships its CSS and JS inline
with no nonce plumbing at all — tightening that to a strict CSP means adding a
per-request nonce to every `<script>`/`<style>` tag across all 9 templates and wiring
`nonce="{{ csp_nonce }}"` through every render call, which is a real frontend change,
not a one-line header addition, and risks breaking rendering somewhere across 9 large
pages without much more thorough manual QA than this pass covers. `img-src` allows
`data:` for the base64 2FA QR codes generated in `setup_2fa()`. `frame-ancestors 'none'`
and `X-Frame-Options: DENY` both forbid framing (belt and suspenders — the CSP directive
is the modern one, the header covers older browsers). Tightening the CSP to drop
`'unsafe-inline'` is a good Day 3+ candidate but was not attempted here.

## 4. `/api/admin/login` IP rate limit

It already had the same 3-attempt/2-hour account lockout as `/api/user/login`, but
unlike user login (which has `@rate_limit(max_requests=10, window_seconds=300,
per="ip")` on top) admin login had no IP-based rate limit at all — so 3 requests with a
wrong password from any single source could lock out the one real admin for 2 hours.
Added the identical decorator, ahead of the existing lockout logic, which stays as the
outer safety net (not removed).

Worth noting: this brings admin login to parity with user login's existing protection
level, not a complete fix for the lockout-as-DoS-lever problem — a lockout policy at
3 failed attempts is trivially triggerable regardless of IP rate limiting once an
attacker knows a valid username, and that's true for user login too. That's an accepted
tradeoff in the existing design, not something this change was scoped to solve.

## 5. `/uploads` path-traversal guard + `/api/events` hardening

Two independent fixes:

- **`/uploads/<filename>`** built the filesystem path directly from the URL segment with
  no `secure_filename()`/basename guard. Admin-only already, so this was defense-in-depth
  rather than an open hole, but nothing stopped a traversal segment from being joined
  onto `UPLOAD_FOLDER`. Now runs the incoming filename through `secure_filename()` first
  — the same guard the write path (`lea_register()`) already applies when saving.

- **`/api/events`** was a fully unauthenticated SSE endpoint with an unbounded
  `while True` generator loop per connection — any client could open unlimited sockets
  that never terminated. Checked what the stream actually sends: a content-free sync
  heartbeat (`{"type":"sync","ts":...}`) consumed by both `dashboard.html` and
  `admin.html` to trigger a refresh of already-authorized data — no sensitive data in
  the payload itself. **Judgment call:** rather than `@admin_required` specifically
  (which would break the endpoint for `dashboard.html`, a user-facing page), added a new
  `session_required` decorator that accepts either `is_user` or `is_admin` — the content
  is identical for both callers, so the right gate is "some authenticated session," not
  one role specifically. Each connection also now self-closes after
  `EVENT_STREAM_MAX_SECONDS` (10 minutes); `EventSource` reconnects automatically once a
  stream ends, so a legitimate client sees no behavior change beyond a periodic
  reconnect a few times an hour.

## 6. PDF report injection

`_build_mobile_lookup_pdf()` interpolated `case_reference`/`query_value`/
`sources_queried` (from `search_logs`, user-supplied at search time) and session
`user_name`/`user_department` (from the signup form) raw into a `reportlab.Paragraph`,
which parses a mini XML-like markup (it's what makes the `<br/>` separators in that same
string work).

This turned out to be worse than the "could break rendering" framing in the original
scoping suggested: confirmed directly against reportlab that building a `Paragraph` from
a string containing something that looks like a malformed or unrecognized tag —
`"<img src=x onerror=alert(1)>"` — raises `ValueError: ...invalid attribute name
onerror...`, not just rendering oddly. That would 500 the whole report endpoint for any
search whose case reference happened to contain a `<`.

All five interpolated fields now go through `xml.sax.saxutils.escape()` before being
placed in the f-string (`app_name`/`disclaimer`, sourced from `get_setting()` and
therefore admin-controlled rather than attacker-controlled, are escaped too for
consistency — nothing in either is meant to carry real markup). The subscriber-record
table in the same PDF is untouched: those values come from `subscriber_records`/
`master_data_records` — admin-uploaded OSINT data, not attacker input — and are placed
as plain `Table` cell strings, which don't go through `Paragraph`'s markup parser at all.

`tests/test_mobile_lookup_pdf_report.py`'s `PdfInjectionTest` exercises both the route
and `_build_mobile_lookup_pdf()` directly with the payload that reproduces the
pre-fix crash, confirming report generation now succeeds.

## Known limitation, not fixed: in-process rate limiter has no shared store

`_rate_limiter` (`app.py`), backing the `rate_limit()` decorator used on login, signup,
LEA registration, mobile lookup, and several other routes, is a plain in-memory,
per-process sliding window (a `dict` of `collections.deque`, guarded by a
`threading.Lock`). Under gunicorn — or any server that runs more than one worker
process — **each worker gets its own counter**, so the effective rate limit becomes
`configured_limit × worker_count`, and every counter resets to zero on every
deploy/restart.

There is no `Procfile` or gunicorn config anywhere in this repo yet (that's Day 5
packaging scope, and `app.run(debug=True, host="0.0.0.0")` is still the only way the app
starts), so in the current single-process dev setup this limitation is invisible. It
will matter the moment a real deploy runs more than one worker process.

**This was explicitly scoped as document-don't-fix for Day 2.** The correct fix is a
shared store (Redis, or a table in the existing MySQL database) behind the same
`rate_limit()` call signature so none of the ~10 call sites need to change — but that's
new infrastructure and its own piece of work, not a Day 2 change. Do not add Redis (or
any other shared store) without that being scoped separately.

---

## Verification performed

**154/154 unit tests pass** (`.venv/bin/python -m unittest discover -s tests`) — 47 new
across `tests/test_failfast_secrets.py`, `tests/test_csrf.py`,
`tests/test_security_headers.py`, `tests/test_admin_login_rate_limit.py`,
`tests/test_uploads_and_events.py`, plus additions to
`tests/test_mobile_lookup_pdf_report.py` and edits to `tests/test_mobile_lookup_credits.py`
/ `tests/test_user_auth.py` to supply the CSRF header on the two authenticated `POST`
calls those files already made.

Every fix in this handover has a regression test — most as generic sweeps in the style
of `test_access_control.py`'s existing pattern (the CSRF frontend sweep, the security
headers checks) rather than one-off narrow assertions, per the same reasoning: these are
absence-of-a-pattern properties, and a sweep catches a third instance that a single
assertion would miss.

**End-to-end Day 1 flow re-verified against a throwaway MySQL 8 Docker container** with
CSRF now in effect: signup → LEA verify → admin approve → login → mobile lookup →
payment. See the Docker verification notes in the PR/commit history for the exact
container invocation and migration order (same pattern documented in
`DAY1_HANDOVER.md`/`CLAUDE.md`'s "Pending" section) — nothing in Day 1's flow broke; the
only change from a client's perspective is that every `POST`/`PUT`/`DELETE` after login
now needs the `X-CSRF-Token` header, which the frontend wrapper supplies automatically.

## Not done / next

- RBAC (`role_required` rollout) and the hardcoded `admin`/`admin123` seed — deferred,
  now explicitly tied to a planned OAuth2 implementation (see `CLAUDE.md`'s Decision
  note, updated 2026-08-14).
- `/api/admin/tools/<id>/cli-test` RBAC gap — same deferral, not touched.
- CSP still allows `'unsafe-inline'` for scripts/styles — tightening it needs a
  per-request nonce threaded through all 9 templates, a real frontend change.
- In-process rate limiter's multi-worker/restart behavior — documented above and in
  `CLAUDE.md`, intentionally not fixed this pass.
- Day 5 packaging untouched: no `wsgi.py`, no gunicorn config, `app.run(debug=True)`
  still at the bottom of `app.py`.

# SENTINEL Platform — AI Context

## ⚠️ Pending — must be done before deployment

**No MySQL instance is set up yet.** The Day-1 work (self-serve signup, LEA clearance
gate, credits/payments — see `docs/DAY1_HANDOVER.md`) is complete in code and was verified
against a throwaway MySQL 8 Docker container, but **none of it has been applied to a real
instance**. Until MySQL exists and these steps are run, the platform will not start
correctly.

Do these in order once the database server is provisioned:

1. **Apply the schema in dependency order, from empty.** This exact order is verified to
   apply cleanly and each file is idempotent:
   ```bash
   mysql -u sentinel_user1 -p sentinel_db < db_setup.sql
   mysql -u sentinel_user1 -p sentinel_db < migration_admin_customization.sql
   mysql -u sentinel_user1 -p sentinel_db < migration_fix_import_errors.sql
   mysql -u sentinel_user1 -p sentinel_db < migration_selfserve_auth.sql
   ```
   There is no migration runner and no version tracking — nothing records what a given
   database has had applied. Adding a `schema_migrations` table is a Day-4 item.

2. **Copy the new keys from `.env.example` into `.env`**:
   `TRUSTED_PROXY_COUNT`, `PAYMENTS_PROVIDER`, `PASSWORD_RESET_TTL_HOURS`.
   `DEV_USER_PASSWORD` has already been removed from `.env` and is no longer read by
   anything — do not reintroduce it.

3. **Set `TRUSTED_PROXY_COUNT=1` when nginx/Caddy goes in front.** It defaults to `0`,
   which means `X-Forwarded-For` is ignored entirely. That is correct when the app is
   reached directly, but wrong behind a reverse proxy: every client would appear to come
   from the proxy's IP, so they would all share a single login rate limit and lockout
   counter. The value must equal the number of proxy hops actually in front of the app —
   setting it higher than reality lets a client forge its own IP.

4. **Back up `ENCRYPTION_KEY` before going live.** It encrypts gov-ID uploads, 2FA secrets
   and stored API keys. If it is lost or regenerated, every encrypted value becomes
   permanently unrecoverable.

5. **Read `docs/DAY2_HANDOVER.md` before deploying.** Day 2 (fail-fast secrets, CSRF, session
   cookie hardening + security headers, admin login rate limit, upload/SSE hardening, PDF
   injection escaping) is complete in code on `day2-security` — see that file for what
   changed and, most importantly, the two things it did **not** do that affect the
   deploy steps above: `FLASK_ENV` now gates startup (step 2's `.env` keys are no longer
   optional in the way they used to be — see below) and `SESSION_COOKIE_SECURE` defaults
   to `True`, which will silently drop the session cookie if the app is ever reached
   over plain HTTP outside `FLASK_ENV=development`.

   **This changes step 2 above from "copy these in" to "these are now load-bearing":**
   outside `FLASK_ENV=development`, `app.py` now **refuses to start** (raises at import)
   if `SECRET_KEY` or `ENCRYPTION_KEY` is unset — the old silent-fallback/regenerate-at-
   restart behavior only remains for local dev. Set `FLASK_ENV=production` (or leave it
   unset — an unset value is treated as production-like) plus real `SECRET_KEY` and
   `ENCRYPTION_KEY` values before the app will boot at all.

Still open and *not* covered by the above: `admin`/`admin123` seed + `role_required`
rollout (intentionally deferred together, see the Decision note below — now tied to a
planned OAuth2 implementation), the CLI-execution-endpoint RBAC gap, and Day 5 packaging.
`app.run(debug=True, host="0.0.0.0")` is still the only way to start the app — the
Werkzeug interactive debugger is remote code execution, so **do not expose this as-is**.
The in-process rate limiter (`_rate_limiter` in `app.py`) also has a real deployment
caveat that isn't a bug to fix — see "Known Issues" below.

## Reminder (2026-08-10)

Follow up on the "Known Issues / Security Debt" list below. As of 2026-08-10,
two of the three original Critical items are fixed and shipped: the stored
XSS in the admin LEA verification queue, and the unauthenticated CDR/IPDR
workspace endpoint (both now require `@admin_required`). Only the hardcoded
default admin credential remains open, and it's intentionally deferred (see
Decision below), not forgotten.

**Decision (2026-08-10, updated 2026-08-14):** the hardcoded default admin
credential item is intentionally deferred, not skipped. It will be fixed
together with RBAC enforcement (the `role_required(*roles)` High item) as
one pass, done right before deployment rather than now — forcing
rotation/seed removal ahead of having roles enforced would just mean redoing
the admin-bootstrap flow twice. As of 2026-08-14 this pass is specifically
tied to a planned OAuth2 implementation: RBAC will be designed on top of
whatever role/claims model OAuth2 brings in, not bolted onto the current
session-based `admin_users.role` column. Concretely, that means don't apply
`@role_required` anywhere, don't touch the `admin_users` seed in
`db_setup.sql`, and don't gate `/api/admin/tools/<id>/cli-test` by role as a
one-off ahead of that pass — it will be redone once OAuth2 lands anyway.

**Reminder (2026-08-14):** Day 2 of the 5-day security hardening plan is
complete on `day2-security` (fail-fast secrets, CSRF protection, session
cookie hardening + security headers, `/api/admin/login` rate limit,
`/uploads` path-traversal guard, `/api/events` auth + bounded connections,
PDF injection escaping — see `docs/DAY2_HANDOVER.md`). Everything in the Critical/
High/Medium/Low lists below that Day 2 touched is marked fixed inline; the
RBAC-adjacent items (admin seed, `role_required` rollout, CLI-endpoint RBAC
gap) are unchanged and still deferred per the Decision above. `app.run(debug=
True, host="0.0.0.0")` is unchanged — still Day 5 packaging scope.

## Known Issues / Security Debt (pre-existing, not yet patched)

> **Provenance (updated after the `day1-selfserve-auth` merge):** this list was
> compiled 2026-08-09, *before* the self-serve signup / clearance-gate work. Items
> struck through below were fixed by that branch. Everything else is believed still
> open — **confirm against source before fixing**, since the sweep predates a large
> refactor of `app.py`. Two Day-2 items on the 5-day plan are already closed and are
> not repeated here: the unauthenticated public registration surface (now
> authenticated and rate-limited) and the spoofable `X-Forwarded-For` client IP
> (now `ProxyFix` + `TRUSTED_PROXY_COUNT`).

Found during a full-codebase security sweep (2026-08-09), after Day 1 (§3.1
mobile_lookup credit/audit) and the auth review were already fixed. Nothing
below overlaps with the credit-race, `/api/me` IDOR, `/dashboard` guard,
login-enumeration, stored-XSS-in-verification-queue, or CDR/IPDR-workspace-auth
fixes already shipped — those are done.

### Critical

- **Hardcoded default admin credential, no forced rotation**
  (`db_setup.sql`, `INSERT INTO admin_users ... ('admin', <hash of
  'admin123'>, 'super_admin')`). Runs on every fresh setup; only a comment
  says "CHANGE IMMEDIATELY," nothing enforces it. Fix: force a password
  change on first login for this seeded account, or drop the seed and
  require an explicit admin-creation step during deploy. **Deferred** —
  see Decision above; will be fixed together with RBAC enforcement.

### High

- ~~No CSRF protection anywhere~~ — **FIXED in `day2-security`.** A lightweight
  double-submit token is minted into the session at login and required (via
  a `before_request` hook) in the `X-CSRF-Token` header on every
  POST/PUT/DELETE once a session is authenticated. See `docs/DAY2_HANDOVER.md`.
- **RBAC modeled but never enforced** — `admin_users.role` is
  `ENUM('super_admin','manager','support')` and a `role_required(*roles)`
  decorator exists (`app.py`) but is never applied to any route. Every admin,
  regardless of role, gets full `@admin_required` super-admin power.
  **Deferred, tied to a planned OAuth2 implementation** — see the Decision
  note above. Not touched by Day 2, deliberately.
- **CLI execution endpoint = admin-to-RCE** (`/api/admin/tools/<id>/cli-test`,
  `app.py`) — any admin (not just `super_admin`, per the RBAC gap above) can
  run arbitrary shell commands via admin-configured `external_command`
  templates. `{query}` is substituted before `shlex.split`, so not
  shell-metacharacter injectable, but is argument-injectable into whatever
  binary is configured. Same deferral as RBAC above — not touched by Day 2.
- **`app.run(debug=True, host="0.0.0.0", port=5000)`** — Werkzeug's
  interactive debugger is RCE if reachable; bound to all interfaces. Day 5
  packaging scope, not touched by Day 2.
- ~~Insecure fallback `SECRET_KEY`~~ — **FIXED in `day2-security`.** Outside
  `FLASK_ENV=development`, a missing `SECRET_KEY` (or `ENCRYPTION_KEY`) now
  raises at startup instead of silently falling back. See `docs/DAY2_HANDOVER.md`.

### Medium

- ~~No rate limiting on `/api/admin/login`~~ — **FIXED in `day2-security`.**
  Same IP-scoped `@rate_limit` shape as `/api/user/login`, ahead of the
  existing account lockout (which stays as the outer safety net).
- ~~No security headers anywhere~~ — **FIXED in `day2-security`.** A new
  `after_request` hook sets CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and HSTS (outside dev, HTTPS only). The
  CSP still allows `'unsafe-inline'` for script-src/style-src — see
  `docs/DAY2_HANDOVER.md` for why that's a deliberate follow-up, not an oversight.
- ~~Session cookie not hardened~~ — **FIXED in `day2-security`.**
  `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"` always;
  `SESSION_COOKIE_SECURE` defaults `True`, relaxed only under
  `FLASK_ENV=development`.
- ~~Backdoor dev password (`app.py`, `user_password_change()`)~~ — **FIXED in
  `day1-selfserve-auth`.** Both the login and password-change fallbacks are gone
  and `DEV_USER_PASSWORD` has been removed from `app.py` and `.env`. An account
  with no `password_hash` now fails closed and needs an admin-issued reset code.
- ~~Ephemeral encryption key~~ — **FIXED in `day2-security`** (same fail-fast
  change as `SECRET_KEY` above): outside dev, a missing `ENCRYPTION_KEY` now
  refuses to start rather than silently generating a throwaway one.
- ~~PDF report injection~~ — **FIXED in `day2-security`.** Not part of the
  2026-08-09 sweep below (found separately during Day 2 planning).
  `_build_mobile_lookup_pdf()` interpolated `case_reference`/`query_value`/
  `sources_queried` (user input via `search_logs`) and session
  `user_name`/`user_department` raw into a `reportlab.Paragraph`, which
  parses XML-like markup — a value that looked like a malformed tag (e.g.
  `<img src=x onerror=alert(1)>`) crashed report generation with a
  `ValueError` (confirmed directly against reportlab), not just rendered
  oddly. All five fields (plus `app_name`/`disclaimer`, admin-controlled,
  escaped for consistency) now go through `xml.sax.saxutils.escape()` first.
- **In-process rate limiter has no shared store (documented, not fixed).**
  `_rate_limiter` in `app.py` (backing the `rate_limit()` decorator used on
  login, signup, LEA registration, mobile lookup, etc.) is a plain
  in-memory, per-process sliding window. Under gunicorn (or any multi-worker
  server) each worker process gets its **own** counter, so the effective
  limit is `configured_limit × worker_count`, and every counter resets on
  each deploy/restart. There is no `Procfile`/gunicorn config in this repo
  yet (Day 5 packaging), so this hasn't bitten anyone in practice, but it
  will the moment the app runs with more than one worker. Fixing it means a
  shared store (Redis, or the database) behind the same `rate_limit()`
  interface — deliberately out of scope for Day 2 (see `docs/DAY2_HANDOVER.md`);
  do not add Redis or any shared store without this being scoped as its own
  piece of work.

### Low

- ~~`/uploads/<filename>` builds the filesystem path directly from the URL
  segment~~ — **FIXED in `day2-security`.** Now runs the filename through
  `secure_filename()` before joining it onto `UPLOAD_FOLDER`, same as the
  write path already did.
- ~~`/api/events` is an unauthenticated SSE endpoint with an infinite
  per-connection generator loop~~ — **FIXED in `day2-security`.** Now
  requires a session (`session_required`: either `is_user` or `is_admin` —
  the payload is an identical content-free sync ping either way) and each
  connection self-closes after `EVENT_STREAM_MAX_SECONDS` (10 min);
  `EventSource` reconnects automatically once a stream ends.

## Future / Deferred Modules

### UPI / Financial Registry Verification (not scheduled — post Mobile-OSINT-go-live)
Adds VPA-to-account-holder-name resolution (the "Financial & UPI Registry Footprint"
section seen in reference reports) to the OSINT lookup output. Deferred out of the
Mobile OSINT go-live scope (Aug 2026) because of provider onboarding lead time, not
technical complexity.

- **Mechanism**: penny-drop verification — a nominal amount is sent to a VPA and the
  receiving bank returns the registered beneficiary name.
- **Candidate providers** (all require business KYC onboarding — registered entity,
  PAN/GST, signed agreement — typically days to weeks before API keys are issued, not
  self-serve same-day):
  - Setu — "Verify Customer VPA" API (docs.setu.co)
  - Cashfree — UPI Penny Drop, part of the Verification Suite (VRS)
  - Decentro — "Verifipay" UPI ID verification
- **Before building**: confirm with the provider/legal that LEA-authorized investigative
  use (not payee verification before a real payment) is covered under their ToS.
- **Integration shape**: once an account is provisioned, this fits the same
  `services` catalog + credit/audit pattern used by other lookup tools (see
  `run_tool_generic()` in `app.py`) — a new service row with `tool_type = 'API Based'`
  and `api_dependency` set to the chosen provider.

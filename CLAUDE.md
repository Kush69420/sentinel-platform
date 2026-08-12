# SENTINEL Platform — AI Context

## ⚠️ Pending — must be done before deployment

**No MySQL instance is set up yet.** The Day-1 work (self-serve signup, LEA clearance
gate, credits/payments — see `DAY1_HANDOVER.md`) is complete in code and was verified
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

Still open and *not* covered by the above: Day 2 security debt (CSRF, security headers,
`admin`/`admin123` seed, `role_required` rollout, fail-fast on missing secrets) and Day 5
packaging. `app.run(debug=True, host="0.0.0.0")` is still the only way to start the app —
the Werkzeug interactive debugger is remote code execution, so **do not expose this
as-is**.

## Reminder (2026-08-10)

Follow up on the "Known Issues / Security Debt" list below. As of 2026-08-10,
two of the three original Critical items are fixed and shipped: the stored
XSS in the admin LEA verification queue, and the unauthenticated CDR/IPDR
workspace endpoint (both now require `@admin_required`). Only the hardcoded
default admin credential remains open, and it's intentionally deferred (see
Decision below), not forgotten.

**Decision (2026-08-10):** the hardcoded default admin credential item is
intentionally deferred, not skipped. It will be fixed together with RBAC
enforcement (the `role_required(*roles)` High item) as one pass, done right
before deployment rather than now — forcing rotation/seed removal ahead of
having roles enforced would just mean redoing the admin-bootstrap flow twice.

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

- **No CSRF protection anywhere** — no tokens, no `SameSite` cookie config.
  Every session-authenticated state-changing endpoint is forgeable by a page
  the victim's browser visits while logged in.
- **RBAC modeled but never enforced** — `admin_users.role` is
  `ENUM('super_admin','manager','support')` and a `role_required(*roles)`
  decorator exists (`app.py`) but is never applied to any route. Every admin,
  regardless of role, gets full `@admin_required` super-admin power.
- **CLI execution endpoint = admin-to-RCE** (`/api/admin/tools/<id>/cli-test`,
  `app.py`) — any admin (not just `super_admin`, per the RBAC gap above) can
  run arbitrary shell commands via admin-configured `external_command`
  templates. `{query}` is substituted before `shlex.split`, so not
  shell-metacharacter injectable, but is argument-injectable into whatever
  binary is configured.
- **`app.run(debug=True, host="0.0.0.0", port=5000)`** — Werkzeug's
  interactive debugger is RCE if reachable; bound to all interfaces.
- **Insecure fallback `SECRET_KEY`**: `os.getenv("SECRET_KEY",
  "dev_secret_change_this")`. If unset in prod, session cookies (including
  `is_admin=True`) are forgeable.

### Medium

- No rate limiting on `/api/admin/login` (unlike `/api/user/login`). The
  3-attempt lockout also doubles as a DoS lever against the real admin.
- No security headers anywhere (no CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, HSTS).
- Session cookie not hardened — no `SESSION_COOKIE_SECURE` /
  `SESSION_COOKIE_SAMESITE` set, so Flask's insecure defaults apply.
- ~~Backdoor dev password (`app.py`, `user_password_change()`)~~ — **FIXED in
  `day1-selfserve-auth`.** Both the login and password-change fallbacks are gone
  and `DEV_USER_PASSWORD` has been removed from `app.py` and `.env`. An account
  with no `password_hash` now fails closed and needs an admin-issued reset code.
- Ephemeral encryption key: if `ENCRYPTION_KEY` isn't in `.env`, a new Fernet
  key is generated *every restart*, permanently bricking previously
  encrypted gov-ID uploads, 2FA secrets, integration API keys, SMTP
  passwords.

### Low

- `/uploads/<filename>` builds the filesystem path directly from the URL
  segment — admin-only, but no `secure_filename`/basename guard as
  defense-in-depth.
- `/api/events` is an unauthenticated SSE endpoint with an infinite
  per-connection generator loop — connection-exhaustion DoS vector, no data
  exposure.

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

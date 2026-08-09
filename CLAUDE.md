# SENTINEL Platform — AI Context

## Known Issues / Security Debt (pre-existing, not yet patched)

Found during a full-codebase security sweep (2026-08-09), after Day 1 (§3.1
mobile_lookup credit/audit) and the auth review were already fixed. Nothing
below overlaps with the credit-race, `/api/me` IDOR, `/dashboard` guard, or
login-enumeration fixes already shipped — those are done.

### Critical

- **Unauthenticated stored XSS → admin account takeover**
  (`templates/admin.html`, `loadVerification()`, the LEA verification queue
  renderer). It builds HTML via `innerHTML` from `full_name`, `department`,
  `designation`, `official_email`, `unit`, `jurisdiction` **without** the
  `esc()` helper the rest of the file uses consistently. Those fields come
  straight from the *public, unauthenticated* `/api/lea/register` form — so
  anyone can submit an application with a script payload as their name, and
  it fires in the admin's session the moment they open Admin → Verification.
  Fix: run every interpolated field through `esc()` in that function, same as
  the rest of admin.html already does.
- **Hardcoded default admin credential, no forced rotation**
  (`db_setup.sql`, `INSERT INTO admin_users ... ('admin', <hash of
  'admin123'>, 'super_admin')`). Runs on every fresh setup; only a comment
  says "CHANGE IMMEDIATELY," nothing enforces it. Fix: force a password
  change on first login for this seeded account, or drop the seed and
  require an explicit admin-creation step during deploy.
- **Broken access control on CDR/IPDR data** — `/api/analysis/workspace/
  <batch_id>` (`app.py`, `analysis_workspace_v2`) and its page route
  `/workspace/<batch_id>` (`workspace_page`) have **no auth check at all**,
  unlike every other data-bearing route in the file. Anyone unauthenticated
  can pull full CDR/IPDR call graphs (numbers, contact pairs, timestamps,
  tower/location data) for any batch by guessing a sequential integer ID.
  Fix: add `@admin_required` (or `@user_required` if analysts should see
  their own batches) to both routes.

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
- Backdoor dev password (`app.py`, `user_password_change()`): if a user's
  `password_hash` is empty, `DEV_USER_PASSWORD`/`"dev123"` is accepted as the
  "current password."
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

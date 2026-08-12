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

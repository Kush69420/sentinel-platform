# SENTINEL Platform — AI Context

## Known Issues / Security Debt (pre-existing, not yet patched)

Found during the Day 1 (§3.1 mobile_lookup credit/audit) security review — both
predate that work and are out of Mobile OSINT scope, but should be fixed before
their respective features go live.

- **`log_service_usage_internal()` (`app.py`, used by CDR/IPDR credit deduction)
  has a race condition**: it does a `SELECT credits` then a separate `UPDATE
  bot_users SET credits=credits-%s WHERE id=%s` with no `AND credits>=%s` guard
  and no rowcount check. Two concurrent requests can both pass the check and
  both deduct, driving a balance negative / letting a user overspend. The fix
  used for `mobile_lookup` (`run_tool_generic()`, same file) is the pattern to
  copy: atomic `UPDATE ... WHERE credits >= %s`, then check `cursor.rowcount`
  to detect a lost race. **Patch this before CDR/IPDR go-live.**
- **`/api/me` (`app.py`) has no authentication check** — it accepts a `phone`
  query param and returns that user's `credits`, `status`, and `plan_id` for
  *any* phone number, no session/login required. This is an IDOR: anyone who
  can guess or enumerate a phone number can read another user's account data.
  Needs a `@user_required` (or equivalent) check scoping it to the caller's own
  session, the same way `/api/user/profile` and `/api/user/credit-history` do.

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

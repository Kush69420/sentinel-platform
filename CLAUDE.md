# SENTINEL Platform — AI Context

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

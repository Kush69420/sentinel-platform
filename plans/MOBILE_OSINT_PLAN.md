# Plan — Mobile OSINT Module (go-live)

**Status:** in progress — this is the module currently being worked on.
Written 2026-08-19.

## Where the module actually lives

| Piece | Location |
|---|---|
| Live tool runner (all OSINT tools, incl. `mobile_lookup`) | `run_tool_generic()`, `app.py:2355` |
| The lookup itself | `app.py:2442` — reads `master_data_records` |
| Compliance/audit row | `search_logs` insert, `app.py:2327` |
| PDF report builder | `_build_mobile_lookup_pdf()`, `app.py:2606` |
| PDF download route | `mobile_lookup_report_pdf()`, `app.py:2680` |
| Service catalog row | `services.code = 'mobile_lookup'`, seeded `db_setup.sql:279`, 2 credits |

`services` carries the per-tool config that gates behaviour — `tool_type`,
`api_dependency`, `search_limit`, `status`, `visible_to_users`, `maintenance_mode`,
`external_command`, `timeout_seconds`, `allow_cli_execution` (columns added by
`migration_admin_customization.sql`; admin CRUD at `app.py:3275`/`3290`).

Live catalog state on the NAS: **1 service enabled, 19 `upcoming`** — `mobile_lookup`
is the one that is on. That matches the go-live scope.

## The blocker nobody has named yet

**Mobile OSINT has no data to look up, and the path that would supply it writes to a
different table than the one the lookup reads.**

- `mobile_lookup` reads `master_data_records WHERE source_type IN ('subscriber','custom')
  AND record_key=%s` (`app.py:2442`).
- `master_data_records` is written **only** by the legacy admin upload
  (`/api/admin/data/upload` → `app.py:2955`).
- The **v2 import pipeline** (`import_execute_v2`, `app.py:3397`) writes to the *typed*
  tables — `subscriber_records`, `cdr_records`, `bts_tower_records`, etc. — and **never
  touches `master_data_records`**.

So there are two divergent import paths, and the one that looks like the modern pipeline
does not feed the one enabled OSINT tool. All target tables are currently empty
(verified live). This must be resolved before go-live, and it is a *decision*, not a bug:

**Pick one.** Either
(a) point `mobile_lookup` at `subscriber_records` (typed columns, real indexes — the
better long-term answer, and where bulk data will land), or
(b) make the v2 pipeline also populate `master_data_records`.

Recommendation: **(a)**. See the performance note below — it makes the JSON-blob problem
go away rather than institutionalising it.

This is gated on [[../plans/DATA_POPULATION_PLAN.md]] — there is no bulk loader yet, so
no data can arrive by any path.

## Performance landmine in the PDF path

`mobile_lookup_report_pdf()` (`app.py:2700`) queries:

```sql
... WHERE record_key=%s OR data_json LIKE %s ...
```

`data_json` is an unindexed JSON blob column. The `LIKE` makes this an **unindexable full
table scan**, and the `OR` prevents the index on `record_key` from rescuing it. Today
that is invisible because the table is empty. At production volume it is a per-report
table scan. Fix alongside the (a)/(b) decision above — moving to typed columns removes it.

## Already done — do not redo

- **Credit/audit correctness** (§3.1) — fixed. `run_tool_generic()` now fails closed on
  an unknown service code; the old `if service and ...` shape let a missing `services`
  row skip every gate and run uncharged (that is how `subscriber_lookup` was once free).
  See the comment at `app.py:2375`.
- **`search_logs` is written whether or not the lookup returns anything** (`app.py:2306`)
  — the compliance record must not depend on a hit. Preserve this if the query changes.
- **PDF injection escaping** — all five user/session-controlled fields go through
  `xml.sax.saxutils.escape()` before reaching `reportlab.Paragraph`. Unescaped input
  crashed report generation outright, not just rendered oddly.

## Open questions — answer before building

1. **Which day's scope is this?** The 7-day Mobile OSINT plan is tracked in an external
   `QUERYING_PLAN.md` that is *not in this repo*. Ask Kush for the current day's scope
   rather than inferring it from the code.
2. **(a) or (b)** for the data-source split above.
3. **What does a "complete" mobile lookup return at go-live?** The reference reports show
   sections this module does not populate yet. Confirm which are in scope.

## Explicitly out of scope

- **UPI / Financial Registry footprint** — deferred post-go-live. Not technical
  difficulty; provider KYC onboarding (Setu / Cashfree / Decentro) runs days-to-weeks.
  Fits the same `services` + credit/audit pattern when it lands (`tool_type='API Based'`,
  `api_dependency` set).
- **RBAC / `role_required` / admin seed** — deferred to the planned OAuth2 work. Do not
  gate anything here by role as a one-off; it will be redone.
- **Cross-module findings.** Per standing guidance, anything found outside Mobile OSINT
  goes in the handover doc rather than being fixed opportunistically.

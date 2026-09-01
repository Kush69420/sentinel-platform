# Day 3 — Mobile OSINT only (session scoped to this module, nothing else)

Session started by re-verifying `5dayplan.md`'s Day 3 list against current source (same
"plan is stale, confirm before fixing" caveat as every prior day) — four of its five
listed items turned out to already be fixed in Day 1's credit-audit work:

- `creditBalance` hardcoded `248` — already wired live from `/api/user/session`
- Raw HTTP 402 discarded by the frontend — already surfaced with required/available + Buy Credits
- Raw `<pre>` JSON dump — already replaced with a formatted result card
- `master_data_records` `data_json LIKE '%query%'` substring match in the **charging**
  path (`run_tool_generic()`) — already tightened to exact `record_key=%s`

A broader route/decorator sweep also turned up a gap in the CDR/IPDR analyze endpoints
(`/api/tools/cdr/analyze`, `/api/tools/ipdr/analyze` bypass the `services.status`
"coming soon" gate and have no `@verified_required`) — **explicitly out of scope for
this session** per direct instruction to work on Mobile OSINT only. Left unfixed,
flagged here for whichever day picks up non-Mobile-OSINT modules.

## What was fixed this session

**The same substring-match bug Day 1 fixed in the charging path was still present in
the sibling PDF-report path.** `mobile_lookup_report_pdf()` (`/api/tools/run/report/pdf/
<search_log_id>`, `app.py`) re-fetches the underlying subscriber record to print into
the PDF. Its `master_data_records` fallback query still used
`(record_key=%s OR data_json LIKE %s)` with `f"%{query_value}%"` — exactly the pattern
Day 1 removed from `run_tool_generic()` a day earlier, for the same reason: a query
value that happens to be a substring of some unrelated record's `record_key` or JSON
blob would pull that record into a PDF report carrying a real case reference.

This wasn't caught before because the two fixes were commits a day apart
(`d10c710`, 2026-08-09, fixed the charging path; `10f6827`, 2026-08-10, added the PDF
endpoint with its own independent copy of the fallback query) — the PDF endpoint was
never updated to match.

Fix: same as the charging path — exact `record_key=%s`, no `LIKE`.

`tests/test_mobile_lookup_pdf_report.py` gained four tests covering the fallback
query's full `WHERE`/`ORDER BY` shape, not just the exact-vs-substring match: a
substring-only match now 404s (`test_master_data_fallback_rejects_substring_match`),
an exact `record_key` match still succeeds
(`test_master_data_fallback_accepts_exact_match`), a same-key match outside
`source_type IN ('subscriber','custom')` is ignored
(`test_master_data_fallback_ignores_other_source_types`), and the most recent of
several matches wins (`test_master_data_fallback_picks_most_recent_match`).

**Accepted consequence, not a bug to fix further:** since no MySQL instance exists yet
anywhere (see `CLAUDE.md`), there is no real database with historical `search_logs`
rows billed under the old substring-match logic to worry about — but for the record,
once real data exists, a `search_logs` row whose original hit only matched via the old
substring logic (not an exact `record_key`) will 404 on PDF regeneration after this fix
rather than reprint a possibly-wrong record. That's the correct trade-off, not a
regression: the alternative is knowingly keeping the substring-match hole open for
report regeneration.

## Verification

156/156 tests pass (154 baseline + 2 new).

## Not done / next

- CDR/IPDR `services.status`/`@verified_required` gap — see above, deliberately left
  for a session scoped to those modules.
- Everything else in `5dayplan.md`'s Day 3 section was already closed before this
  session started (see list above) — nothing further needed there.

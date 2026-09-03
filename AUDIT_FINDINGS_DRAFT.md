# SENTINEL Platform — Independent Security/Correctness Audit (in progress)

Run started 2026-09-01/02, resumed after a session-limit reset. Five audit passes
requested by the user, run sequentially (not in parallel) to avoid re-hitting the
rate limit. This file is a running scratchpad — not the final report. It will be
reconciled against `docs/REMEDIATION-PLAN.md` at the end, per the user's instruction
to scan independently first and only then compare against the docs.

Status:
- [x] 1. DB schema audit — DONE (below)
- [x] 2. OSINT module (mobile_lookup) audit — DONE (below)
- [x] 3. Auth / session / RBAC audit — DONE (below)
- [x] 4. Deployment / ops readiness audit — DONE (below)
- [x] 5. Input handling / frontend / XSS audit — DONE (below)
- [x] Final: reconcile against docs/REMEDIATION-PLAN.md and produce final report — DONE (below)

---

## 6. Reconciliation against `docs/REMEDIATION-PLAN.md`

Read after all 5 independent passes above were complete, per the user's instruction. That
document is itself a prior independent audit (dated 2026-08-26, against commit `5ac30d8`,
"4 parallel deep agents"). Comparing:

**Strong convergence — same defects found by both, independently, on different dates:**
hardcoded `admin`/`admin123` seed with no rotation path; `role_required` defined but applied to
zero routes; the CLI-exec argument-injection endpoint and its lack of role-gating; the
connection-leak pattern across dozens of `get_db()`/`conn.close()` sites with no try/finally;
the "custom" import module silently discarding rows while reporting success; `modify_credits`
non-atomic read-then-write (I did not re-verify this line-for-line myself this session — the
doc's finding 3.3 is more precise than anything my passes surfaced on this specific point, worth
trusting); migration-version tracking absent; `migration_activity_log_actor.sql` not applied by
the deploy script; backups not actually scheduled anywhere; unpinned `cloudflared:latest` image.

**I directly re-verified two things the doc's own dating made me suspicious of, since 6 days have
passed since 2026-08-26:**
- **RBAC still NOT applied**, despite a branch literally named `worktree-rbac-role-gate` having
  been merged into `main` since (`git show 0291d1a --stat`, merged 2026-09-01 23:38, present on
  `main` now). Checked directly: that PR's actual diff only "routes admin credentials from the
  unified login door to the admin panel" (its own merge message) — a login-flow change,
  touching `app.py`, `templates/admin.html`, `templates/login.html`,
  `tests/test_user_auth.py`. `grep -n "role_required" app.py` still returns exactly one line
  (the definition, line 300) — it is still applied to zero routes. **The branch name is
  misleading; RBAC enforcement did not ship.** Flagging this explicitly since it's the kind of
  thing that could cause someone to believe this item is closed when it isn't.
- **CI now exists and works** — `.github/workflows/test.yml` is present and (per the deployment
  pass, which ran it) actually executes `pytest` + `pip-audit` on push/PR to `main`. This
  **closes** the remediation plan's finding 2.1 ("the suite does not run from a clean clone")
  as of today — confirmed by direct source/command inspection, not by trusting either document.
  Branch protection is still genuinely absent though: `gh api repos/Kush69420/sentinel-platform/branches/main/protection`
  → `404 Branch not protected`, matching the doc's finding 2.3, independently re-confirmed
  right now, not stale.
- **Vulnerable dependencies (finding 4.3) have been bumped** — `git log --oneline -- requirements.txt`
  shows a commit titled "Bump vulnerable pinned dependencies (Phase 4.3)" after the 2026-08-26
  audit date. The deployment pass's live `pip-audit` run against the current pinned versions
  (`werkzeug 3.1.6`, `cryptography 50.0.1`, `flask 3.1.3`) returned "No known vulnerabilities
  found" — this item is genuinely closed, not just claimed closed.

**New findings from my 5 passes that the 2026-08-26 remediation plan does NOT mention:**
- The mobile_lookup credit/audit-log fallthrough bug (OSINT pass, Critical #1) — a "no match"
  result that silently falls through into a live external-integration call, which then succeeds
  for free and corrupts the compliance ledger for that row. This is the single highest-value new
  finding for tomorrow's go-live specifically, and it is not in the remediation plan at all —
  plausibly because the remediation plan's audit predates whatever integration-fallthrough code
  path currently exists, or because it was scoped away from the OSINT tool logic itself.
- Every non-`mobile_lookup` tool code (`vehicle_lookup`, `ip_lookup`, `email_lookup`, etc.)
  being reachable, unbilled, and unaudited from request one (OSINT pass, Critical #2).
- `master_data_records` hits being unable to produce a PDF on current `main` (OSINT pass, High
  #3) — note this supersedes the remediation plan's own "DOC-ONLY RISKS" item 2, which describes
  an *older* version of this bug (`WHERE record_key=%s OR data_json LIKE %s`, an unindexed
  substring scan) that is not what's on `main` today; the live gap today is narrower (can't
  print a paid report) not a data-leak/full-scan.
- Two admin-authenticated stored/reflected XSS holes (tool-package name, CSV/XLSX header
  preview) — frontend pass, High #1/#2 — explicitly out of scope for the remediation plan
  ("Frontend/UI excluded" per its own header).
- No `MAX_CONTENT_LENGTH` anywhere in the app (frontend pass, High #3) — not mentioned in the
  remediation plan.
- CD (`sentinel-deploy.sh` polling every 10 min) being fully decoupled from CI, so a merged
  commit ships regardless of test outcome (deployment pass, High #1) — not mentioned in the
  remediation plan (which predates CI existing at all, so this interaction couldn't have been
  observed on 2026-08-26).
- No structured logging/error tracking/alerting anywhere (deployment pass, Medium #5) — not
  mentioned in the remediation plan.

**Where the remediation plan found things my 5 passes did not surface as clearly (its own
"DOC-ONLY RISKS" section is itself an honest admission of this genre of gap, worth taking at
face value rather than re-deriving):** the ~400GB dataset vs. tiny MySQL buffer-pool-on-spinning-disk
mismatch; the CDR/IPDR mode-switch column-scrambling JS bug (3.2); the campus captive-portal
gateway as "the single most likely cause of any outage." I did not independently verify any of
these three — they require either production-scale data or a running browser session neither of
my passes had, and I'm reporting them here as "the prior audit found this, I have not
re-checked it" rather than re-asserting them as newly confirmed.


---

## 1. DB schema audit — findings (subagent run, sonnet-deep)

Scope covered: `db_setup.sql`, all 6 migration files, `deploy/db-init/00-apply-schema.sh`,
`deploy/docker-compose.yml`, all of `app.py` (4270/4270 lines), `sentinel_modules/identity.py`,
`sentinel_modules/checksums.py` (pure functions, no DB access, no findings), `tools/bulk_import.py`.

Note: the subagent flagged that CLAUDE.md was auto-injected into its context by the harness
on first file read in the directory (not opened deliberately, despite the instruction not to).
It says every claim below is anchored to source it read itself and where CLAUDE.md's content
overlapped, it re-verified against the .sql/.py source directly. Treat with normal skepticism —
will cross-check independently during reconciliation.

### Critical

**1. Hardcoded default admin credential ships in prod, no in-app rotation path.**
`db_setup.sql:26-29`:
```sql
-- Default admin: username=admin, password=admin123. CHANGE IMMEDIATELY.
INSERT INTO admin_users (name, username, password_hash, role)
VALUES ('Super Admin', 'admin', 'pbkdf2:sha256:600000$sentinelsalt1234$...', 'super_admin')
ON DUPLICATE KEY UPDATE username=username;
```
Confirmed: zero admin-password-change route anywhere in `app.py` — only way to rotate is a
direct DB `UPDATE`. `deploy/docker-compose.yml:167-169` allegedly documents this sitting behind
a public Cloudflare tunnel with the seed still live (unverified by me directly — recheck).
**Blocks go-live**: yes, until the admin password hash is manually rotated in the DB before
any tunnel/public exposure.

### High

**2. Deploy script never applies 2 of 6 migration files** — `deploy/db-init/00-apply-schema.sh`
allegedly runs `db_setup.sql`, `migration_admin_customization.sql`, `migration_fix_import_errors.sql`,
`migration_selfserve_auth.sql`, `migration_coming_soon.sql` but never `migration_activity_log_actor.sql`
or `migration_bulk_import.sql`. This contradicts CLAUDE.md's documented apply order (which lists
`migration_activity_log_actor.sql` as step 5 but doesn't mention `migration_coming_soon.sql` or
`migration_bulk_import.sql` at all). **Needs direct re-verification** — the two sources disagree
and I have not yet read `00-apply-schema.sh` myself.

**3. Connection leak on transient DB errors, ~49 endpoints** — `conn = get_db(); ...; conn.close()`
pattern with no `try/finally` in ~49 places vs. 15 uses of the safer `with db_conn()` context
manager (`app.py:190-200`). Cited examples: `app.py:846-882` (`dashboard_catalog`),
`app.py:929-936` (`get_site_content`), `app.py:1916-1930` (`admin_stats`). No connection pooling
(`get_db()` opens a fresh `mysql.connector.connect()` every call), so sustained DB errors could
exhaust `max_connections`. Not a go-live blocker for the happy path, but a real outage risk.

**4. CLI-execution job audit trail writes NULL user_id** — `app.py:3459-3467`,
`INSERT INTO external_tool_jobs (service_id,user_id,...) VALUES (...,session.get('user_id'),...)`
but admin sessions only ever set `session["admin_id"]`, never `session["user_id"]` — so every row
this RCE-adjacent endpoint writes has `user_id=NULL`, losing "which admin ran this" attribution
on the platform's highest-risk endpoint. Should be `session.get('admin_id')`.

**5. "Custom" import module silently drops rows while reporting success** — `app.py:3408-3414`
advertises a `custom` import module; the write path `import_execute_v2` (`app.py:3573-3584`)
branches `if module=='subscriber' ... elif vehicle ... elif bts ... elif cdr ... elif ipdr` with
no `elif module=='custom'`, yet `imported += 1` runs unconditionally — uploading via the
advertised "Custom Records" module returns `{"success": true, "imported": N}` while writing
zero rows anywhere. Not in Day-1/mobile-lookup scope but silently misleading.

### Medium

6. `password_reset_tokens.user_id` has no FK (unlike structurally identical `payment_orders.user_id`
which does) — inconsistent, unverified impact.
7. Per-actor audit query index (`idx_actor` from `migration_activity_log_actor.sql`) has no
current query in `app.py` that uses it (grepped, found none) — so today it has zero impact,
but exists for a query path not yet built.
8. **No migration-version tracking anywhere** — confirmed none of the 6 `.sql` files contain a
`schema_migrations` table. Each file is individually idempotent, but nothing records which of
the 6 files a given live database has actually had applied — directly enables findings #2 and
this point to go unnoticed.
9. Orphaned encrypted uploads on DB insert failure — `app.py:995-1023` (`lea_register`) writes
two Fernet-encrypted files to disk *before* the `INSERT INTO lea_applications`, with no
try/except around the insert — if the insert throws (e.g., a later transient DB error), the
encrypted files remain on disk with no DB row pointing to them.
10. No length validation before insert into narrow VARCHAR columns — e.g. `app.py:1852`
(`modify_credits`) builds `f"{reason} (by {admin_name})"` into `credit_transactions.reason
VARCHAR(150)` with no truncation.
11. (number skipped/garbled in subagent output — recheck)
12. `migration_fix_import_errors.sql` may be a no-op — claimed byte-for-byte duplicate of a
`CREATE TABLE IF NOT EXISTS` already in `migration_admin_customization.sql`. Unverified, recheck.
13. No explicit UTC pinning on MySQL — relied on implicitly. `mysql_dt_to_aware()`
(`app.py:211-216`) hardcodes `.replace(tzinfo=timezone.utc)` onto whatever naive datetime a
TIMESTAMP column returns — correct only if the server's session `time_zone` is actually UTC.
Nothing asserts this; stock `mysql:8.4` image defaults to UTC but it's unverified on the actual
deploy target.
14. Unindexable admin user search — `app.py:1781-1790`: `WHERE name LIKE %s OR phone LIKE %s`
with a leading `%` wildcard defeats any index. Low current impact, won't scale.

### Explicitly checked and found NOT a problem

- `credit_payment_order()` idempotency claim (`app.py:4053-4081`) verified TRUE as written:
  `UPDATE payment_orders SET status='paid', ... WHERE id=%s AND status<>'paid'` gated by
  `cursor.rowcount != 1: return False` before crediting `bot_users.credits` — a replayed webhook
  or double "Mark Paid" click is a genuine no-op.
- No SQL injection found — every query uses parameterized `%s` placeholders; the only
  string-built SQL interpolates fixed/hardcoded table names, not attacker-controlled ones
  (needs a second look at `analysis_workspace_v2`'s two-way `cdr_records`/`ipdr_records` choice
  specifically — flagged by subagent as "attacker-controlled?" but not resolved clearly in its
  output, recheck).
- Credit balance updates use `UPDATE ... WHERE` guards (`subscriber_records.mobile_number`
  UNIQUE, `master_data_records.record_key`) — reasoned race-safe by subagent, recheck directly.
- The previously-known bug (`activity_log.admin_id` FK'd `admin_users` while code passed
  `bot_users.id`) — subagent says this is now fixed by the actor_type/actor_id columns (matches
  what CLAUDE.md separately claims, so at least two sources agree — still, will verify directly).

### What the subagent could not verify
- Real runtime charset/collation actually negotiated by `mysql-connector-python==9.1.0` against
  a live `utf8mb4` server (no live DB to test against).
- Actual session `time_zone` of any deployed MySQL instance (finding #13 is reasoned from the
  stock image default, not observed).
- Did not audit `.claude/worktrees/*/` copies (separate git worktrees with their own copies of
  files) — treated top-level files as canonical. **I should check whether any of those worktrees
  contain unmerged fixes relevant to these findings.**
- No row-count/production-volume data exists to test — index-adequacy conclusions are from query
  shape alone, not measured cardinality.

---

## 2. OSINT / mobile-lookup audit — findings (subagent run, sonnet-deep)

Branch checked: `main`, HEAD clean, matches working tree.

**Tests actually run and observed to pass:**
```
.venv/bin/python -m pytest tests/test_mobile_lookup_credits.py tests/test_mobile_lookup_pdf_report.py -x -q
............... [100%]
15 passed, 1 warning in 0.84s
```
All 15 pass — but see Critical #1 below: the passing tests do not exercise the specific gap found.

### CRITICAL

**1. `mobile_lookup` gives away real results for free and corrupts its own compliance log
when the local DB misses but an external API integration is enabled.**
`app.py:2589-2705` (approx). When the number misses both `subscriber_records` and
`master_data_records`, the code does (line ~2592-2594):
```python
charge_for_lookup(cursor, user, service, code, query, case_reference, found=False, source="No match")
conn.commit()
```
There is **no `return` after this**. Execution falls through into the API-integration section
(lines 2631-2698). If a phone-category integration is enabled (e.g. Twilio/Numverify — the
tool's own 404 message literally tells the officer to "configure Twilio/Numverify API for
external phone intelligence", line ~2704), that call runs, and on success:
```python
# line ~2700-2701
if results:
    return jsonify({"success": True, "tool": code, "query": query, "results": results, "errors": errors})
```
The officer gets a real, successful phone-intelligence result — but `charge_for_lookup` is
never called again, no credit is deducted, and the `search_logs` row already committed still
reads `credits_used=0, sources_queried="No match"`.

Consequences:
- Real external lookups become free forever whenever the local DB misses.
- The compliance/audit ledger is now provably false for that row — a chain-of-custody problem
  for a product whose output is meant to support LEA casework.
- `mobile_lookup_report_pdf` explicitly rejects rows with `sources_queried == "no match"`
  (line ~2814), so the officer can never even print a report for the data they were shown.
- `tests/test_mobile_lookup_credits.py` does not catch this: it hardcodes
  `"SELECT * FROM integrations WHERE is_enabled=1" → []` (line ~77-78) for its "no match" test
  (line ~183), so the fallthrough-to-a-live-integration path is never exercised. This is an
  untested gap, not a covered-and-passing case.

**GO/NO-GO: NO-GO if any phone-category integration is enabled at launch.** If nothing is
configured in `integrations` for the `phone` category tomorrow, this is dormant — but it will
trigger instantly and silently the moment one is turned on, with no visible symptom (the
response looks correct to the officer).

**2. Every other lookup tool reachable through the same endpoint is charged $0 with zero audit
trail, the first time it's requested.** File-wide check confirms only two places ever debit
`bot_users.credits` for a lookup: `charge_for_lookup()` (line ~2435, called only from
`mobile_lookup`'s own two DB branches) and `log_service_usage_internal()` (line ~3390, separate
CDR/IPDR path). Every other branch of `run_tool_generic()` — `vehicle_lookup` (~2596-2602),
`tower_bts_lookup`/`tower_analysis` (~2604-2621), aadhaar (~2623-2626), and the generic
"API-based" branch (~2631-2705, e.g. ip-api.com ~2642-2648) — is neither charged nor logged on
its first hit against a live table, despite seed data (`db_setup.sql` line ~283,
`migration_admin_customization.sql` line ~400) defaulting `is_enabled=1`/`status='enabled'`
with a nonzero `credits_per_use`. **NO-GO on the expectation that all tool codes reachable at
launch are billed and audited — they are not.** Doesn't block `mobile_lookup` itself, but these
are reachable through the identical `/api/tools/run` endpoint, gated by the same
`@verified_required` decorator, so any verified LEA user can hit them today.

### HIGH

**3. Paid, logged `master_data_records` hits can never produce a PDF report on `main`.**
`app.py:2818-2828` — `mobile_lookup_report_pdf` only queries `subscriber_records`; the comment
there says "the old master_data_records fallback is gone." But `run_tool_generic()`'s
`master_data_records` fallback (~2561-2586) *does* charge credits and *does* write
`sources_queried="Uploaded Master Data"` on a hit. Any such row 404s when the officer tries to
print it — it was paid for, it's in the audit log as a real hit, but there is no way to get the
report. Already referenced in a `templates/dashboard.html:224-229` comment; no test exercises a
`sources_queried="Uploaded Master Data"` row through the PDF endpoint.

**Direct answer to the specific question this pass was asked to resolve:** the substring-match
bug (`data_json LIKE '%query%'`) is **NOT live on `main` today**. `grep -n "LIKE '%" app.py`
shows exactly two hits, both inside comments describing already-removed old code (lines ~2558,
~2822) — no live `LIKE` anywhere in the file. `run_tool_generic()`'s fallback already uses an
exact `record_key=%s` match (line ~2562). The two unmerged branches (`resolve-day3`,
`worktree-day3-mobile-osint-pdf-fallback`) restore a fallback in `mobile_lookup_report_pdf`
using that same exact `record_key=%s` match — i.e. **they fix Finding #3 above** (the missing
PDF for `master_data_records` hits), not a live substring/cross-subscriber-leak bug, because
that bug does not currently exist on `main`. **The cross-subscriber data-leak / full-table-scan
risk described in the task brief is not currently exploitable on `main`.** This directly
supersedes my own preliminary note (below, from before this subagent ran) — I had not yet
confirmed the substring bug was already fixed on `main`; it was, and independently, the
*present* main-branch gap is the narrower "can't print a paid report" issue (#3), not a data leak.

**4. No phone-number normalization anywhere in the pipeline.** `app.py:2481` — the entire input
processing before the DB lookup (line ~2535) is:
```python
query = (data.get("query") or "").strip()
```
No digit-stripping, no `+91`/leading-zero handling, client or server side. A format mismatch
(`+91 98765 43210` vs. stored `9876543210`) returns the exact same 404 "No subscriber record
found" as a genuinely absent number, and is billed identically ($0, logged "No match" per
Critical #1). An investigator cannot distinguish "not in database" from "typed it wrong" — a
real integrity risk for a legal-evidence-adjacent tool.

**5. Admin-only CLI execution is argument-injectable and not scoped to `super_admin`.**
`app.py:3459-3472`:
```python
cmd = (svc.get('external_command') or '').replace('{query}', str(q))
proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=..., cwd=BASE_DIR)
```
Confirmed no `shell=True`, so shell metacharacters in the query are inert. But the substituted
value still lands as literal argv text wherever `{query}` sits in the template, so it's
argument-injectable into whatever binary is configured. Gated by `@admin_required` only —
`role_required` exists in the codebase but is applied to zero routes, so this is reachable by
any admin account, not just `super_admin`. Not reachable by a normal verified LEA user, so
doesn't block the officer-facing `mobile_lookup` flow, but matches the known CLI-exec item.

### MEDIUM

**6. Single gunicorn worker + un-overridden 45s HTTP timeout can stall the whole app under a
handful of concurrent users.** `Dockerfile` CMD confirms `--workers 1 --threads 8` (deliberate,
per an in-code comment, to work around the in-process non-shared rate limiter). `_http_json()`
defaults to `timeout=45`; every provider call site in `run_tool_generic` (lines ~2659, 2663,
2668, 2677, 2682, 2686, 2693) uses that default, uncustomized. If 8 concurrent officers hit a
lookup that falls through to a slow/hung provider, all 8 threads in the single process can be
blocked simultaneously for up to 45s — nothing else (login, dashboard, another user's request)
can be served, because there is only one process. Plausible, not hypothetical, failure mode for
a small pilot deployment.

**7. Raw MySQL exception text returned to an authenticated caller.** `app.py:2627-2629`:
```python
except mysql.connector.Error as exc:
    conn.close()
    return jsonify({"error": f"Database lookup failed: {exc}"}), 500
```
Not a stack trace (Flask's generic 500 handler covers truly unhandled exceptions, confirmed
lines ~795-797), but a caught driver-level error string is passed straight to the client on
this specific path. Low real-world severity (requires an authenticated, LEA-verified session to
trigger) but avoidable info disclosure.

### LOW / informational

- `app.run(debug=True, host="0.0.0.0", port=5000)` at the bottom of `app.py` (~4269-4270) is
  real but guarded by `if __name__=="__main__"`; `wsgi.py` + `Dockerfile` + `deploy/sentinel.service`
  confirm the actual deploy path is `gunicorn wsgi:app`. Only a risk if someone manually runs
  `python app.py` on the production box.
- `DB_CONFIG` (`app.py:132-137`) has silent defaults (`localhost`/`root`/empty password/
  `sentinel_db`) with no startup validation, unlike `SECRET_KEY`/`ENCRYPTION_KEY` which fail
  fast. A missing/wrong DB env var means the app boots looking healthy and 500s on the first
  request that touches the DB. Already a known, tracked go-live item — not a new discovery.
- `/api/intelligence/summary` (`app.py:892-921`) returns hardcoded demo data (fake "recent
  searches", fake stats), not derived from real `search_logs`. Not a security bug, but the
  dashboard's "recent searches"/"live feed" widgets are decorative, not real telemetry — worth
  knowing so nobody mistakes it for a working audit view on launch day.
- PDF injection: verified fixed. `_build_mobile_lookup_pdf` escapes `case_reference`,
  `query_value`, and admin-set fields — confirmed non-issue, matches what CLAUDE.md separately
  claims was fixed in day2-security (independently verified here, not just taken on faith).
- Session/account-lock enforcement: a revoked/blocked account is locked out mid-session, not
  just at login (confirmed by the subagent, not independently re-verified by me yet).
- SSRF: outbound hosts for API-based lookups come from admin-configured `integrations.base_url`,
  not user input; `ip_lookup`'s host is a hardcoded literal, only a path segment is
  user-controlled and URL-quoted. No user-reachable SSRF found.

### What the subagent could not verify
- Whether a phone-category `mobile_lookup` integration (Twilio or otherwise) will actually be
  configured/enabled in the live/staging DB tomorrow — this determines whether Critical #1 fires
  on day one or stays dormant. No DB access in the sandbox to check the live `integrations` table.
- Whether `vehicle_lookup`/`ip_lookup`/etc. are intended to be reachable at launch, i.e. whether
  "Mobile OSINT go-live" means only `mobile_lookup` is exposed in the UI while others sit
  dormant. Seed defaults make them reachable via direct API call regardless of what the
  dashboard UI shows; can't confirm the deployed `services` table hasn't been hand-edited.
- Live behavior under real concurrency (Finding 6) — traced from code/config, not load-tested
  against a running instance (no live MySQL in the sandbox).
- Did not read `plans/MOBILE_OSINT_PLAN.md` (per the task's own instruction to work from source
  and tests, not the plan doc, as ground truth).

---

## 3. Auth / session / RBAC audit — findings (subagent run, sonnet-deep)

Same CLAUDE.md-auto-injection caveat as before — subagent reports it did not deliberately Read
it but it landed in context via a system reminder; says it independently re-verified anything
that overlapped against source/tests before relying on it. Also used the user's own memory note
("Sentinel runs a single admin account, RBAC route-matrix audit not urgent") to weigh — not
dismiss — the RBAC finding's go-live urgency.

**Tests actually run and observed to pass:**
```
$ .venv/bin/python -m pytest tests/test_access_control.py tests/test_csrf.py tests/test_user_auth.py tests/test_password_reset_flow.py -q
82 passed, 16 warnings, 6 subtests passed in 14.64s
```

### Critical

**1. Hardcoded default super_admin credential, no forced rotation** — `db_setup.sql:26-29`
(same finding as DB-schema pass, cross-confirmed independently here). Nothing in `app.py`
forces a password change on first login or refuses to boot with the seed row present.
**Blocks go-live**: yes, unless the password is rotated (or the row deleted and a real admin
created) before the database is reachable outside the deploy host.

### High

**2. `role_required` decorator exists but is applied to zero routes** — `app.py:300-312`
defines it; grep confirms it is referenced nowhere else. Every `@admin_required` route treats
`super_admin`, `manager`, `support` identically. Concrete blast radius if a non-super-admin
account is ever created: full access to `/api/admin/tools/<id>/cli-test` (command execution),
`/api/admin/payments/orders/<id>/mark-paid` (credit `bot_users` without a real payment),
`/api/admin/users/<id>/credits`, decrypted LEA gov-ID downloads via `/uploads/<filename>`, and
SMTP/integration credential rotation. Per the user's own memory note, only one admin account
currently exists in practice, so this subagent calls it a real defect to fix but **not a
go-live blocker today** given single-admin usage — flagging for the user to weigh, since that
usage fact is asserted, not independently verified by either subagent against a live DB.

**3. `/api/admin/tools/<int:service_id>/cli-test` = admin-tier command execution, no role
gate** — `app.py:3459-3472`. Cross-confirms the OSINT-pass finding #5: `{query}` substituted
into `external_command` before `shlex.split` (not shell-metacharacter injectable, but
argument-injectable), reachable by any admin per finding #2 above.

**4. Account lockout is a trivial unauthenticated, targeted DoS.** `app.py:1231-1270` (user),
`app.py:1463-1490` (admin). Lockout keys on the account row, not the source IP: 5 wrong-password
POSTs to `/api/user/login` (3 for `/api/admin/login`) lock the account for `LOCKOUT_HOURS`
(default 2h), and this fits comfortably inside the existing 10-attempts/5-min per-IP rate limit
— no valid credentials, no CAPTCHA, needed. An attacker who knows an LEA officer's phone/email
can lock them out repeatedly.

**5. `app.run(debug=True, host="0.0.0.0", port=5000)` at `app.py:4270`** — guarded by
`if __name__=="__main__"`, and the shipped path (`Dockerfile` CMD, `deploy/sentinel.service`)
runs `gunicorn wsgi:app`, not `python app.py`, so the debugger (RCE) is not reachable through
the prescribed deployment. Still recommends unconditionally gating `debug=True` on
`IS_DEV_ENV` before go-live as a cheap defense-in-depth fix, in case anyone ever runs it
manually on the production box.

### Medium

**6. Idle/inactivity timeout is client-side only.** `app.py:1560-1574` (`session_info()`) only
*reports* `inactivity_timeout_seconds`; nothing server-side enforces it — enforcement lives
entirely in `templates/dashboard.html:325` / `templates/admin.html:313` JS timers. Flask's
`SecureCookieSessionInterface` does enforce an absolute `permanent_session_lifetime` (default 60
min) server-side via itsdangerous `max_age`, bounding the exposure — but a stolen cookie
replayed directly (curl, no JS) stays valid up to 60 minutes regardless of idle time, not the
advertised 15.

**7. Login timing side-channel enables account enumeration.** `app.py:1224-1229` (user),
`app.py:1463-1466` (admin). An unknown identifier takes a fast-path 401 with no hashing; a known
identifier with a wrong password runs full `check_password_hash` (slow PBKDF2) before returning
the *same* 401 body. Response bodies are correctly identical (matches CLAUDE.md's claim that
login-enumeration was fixed at the body level), but the timing difference isn't addressed,
undermining that effort. Not benchmarked against a running server — code-structure observation.

**8. In-process rate limiter has unbounded growth and is single-worker-only.** `app.py:222-258`
— the `_windows` dict never evicts stale keys; `Dockerfile` pins `--workers 1` specifically to
work around this (per an in-code comment, confirmed). Matches the DB-pass/CLAUDE.md-documented
caveat; real deployment risk the moment worker count is ever raised without also fixing this.

### Low

**9. `templates/dashboard.html:325` calls `/api/admin/session-info` (`@admin_required`) from
the regular-user dashboard** — always 401s for a user session, so the idle-timer shown to
ordinary users is a hardcoded JS default, never the real configured value. Functional bug, not
independently exploitable.
**10. `/api/universal-search` (`app.py:3080`) has no auth guard at all** — flagged as a finding
in the appendix matrix; not further characterized by the subagent (impact unclear/unverified —
recheck directly what this endpoint returns).
**11. `/api/tools/cdr/analyze`, `/api/tools/ipdr/analyze` (`app.py:3169`, `3281`) are gated by
`@user_required` + rate_limit but NOT `@verified_required`** (LEA clearance), unlike
`/api/tools/run`. Unverified/unclear whether this is intentional (these may be a separate
tier) — recheck.

### Explicitly checked and found NOT a problem
- CSRF: double-submit scheme (`app.py:1521-1528`, `1307`), compared with `hmac.compare_digest`
  (`app.py:378`), correctly exempts only pre-session endpoints (`app.py:346-352`).
- Session fixation: `session.clear()` precedes issuing a new session on both `user_login()`
  (`1299`) and `_perform_admin_login()` (`1521`) — not vulnerable.
- Session cookie flags: `HTTPONLY=True`, `SAMESITE="Lax"` unconditionally; `SECURE` defaults
  `True` outside dev (`app.py:103-105`).
- Secrets fail-fast: `SECRET_KEY`/`ENCRYPTION_KEY` raise outside `FLASK_ENV=development`
  (`app.py:83-159`) — independently confirmed here, not just taken from CLAUDE.md's claim.
- `.env` is not git-tracked (`git ls-files .env` empty) and never appears in
  `git log --all --diff-filter=A --name-only` (only `.env.example` does).
- IDOR checks: `mobile_lookup_report_pdf` scopes by `user_id` (`app.py:2806`); `/api/me`,
  `/api/user/credit-history`, `/api/user/profile` all scope on `session['user_id']`/
  `session['user_phone']`, never a caller-supplied id.
- Razorpay webhook signature verified with `hmac.compare_digest` before crediting
  (`app.py:4017-4023`); crediting is idempotent (`credit_payment_order`, `app.py:4053`) —
  cross-confirms the DB-pass finding.
- No JWT, no CORS headers, no host-header-derived redirects/URLs found anywhere in `app.py`.

### Route/decorator matrix (appendix, abridged — see subagent's full pass for complete list)
Notable entries: `/api/universal-search` — no guard (finding #10). `/api/tools/cdr/analyze`,
`/api/tools/ipdr/analyze` — `@user_required` only, not `@verified_required` (finding #11).
`/api/payments/webhook/<provider>` — no session guard, correct pattern (HMAC-verified instead).
All `/api/admin/*` management routes — `@admin_required`, none role-scoped (finding #2/#3).
Public/intentionally-unauthenticated: `/`, `/login`, `/register`, `/pricing`, `/reset-password`,
static pages, `/api/dashboard/catalog`, `/api/services`, `/api/plans`, `/api/site-content`.

### What the subagent could not verify
- No live MySQL instance available — findings are from static source reading plus the test
  suite's mocked DB layer, not an end-to-end running system.
- Timing side-channel (finding #7) not benchmarked against a running server.
- Did not exhaustively read every template byte-for-byte (deferred to the frontend/input pass).
- Real-world blast radius of RBAC gap (#2) depends on whether a non-super_admin account is ever
  actually created in the live DB — asserted single-admin-only from the user's memory note, not
  independently confirmed against a live database by either subagent.

---

## 4. Deployment / ops readiness audit — findings (subagent run, sonnet-deep)

Note: this pass discovered `deploy/` contains real deploy tooling not previously read in this
session — `deploy/sentinel-deploy.sh`, `deploy/systemd/*`, `deploy/backup.sh`,
`deploy/DOCKER_DEPLOY.md`, a `docker-compose.yml`. Same CLAUDE.md-auto-injection caveat as prior
passes; subagent says it did not rely on it, only cites source/config/command output it ran
itself.

**Full test suite, actually run and observed:**
```
$ .venv/bin/python -m pytest -q
...
227 passed, 18 warnings, 18 subtests passed in 18.08s
```
0 failed, 0 errors, 0 skipped. Warnings are all `DeprecationWarning`s for
`datetime.datetime.utcnow()` (e.g. `app.py:1527`, `1306`, `1570`) plus one from a third-party
library (reportlab) — not failures. **Caveat explicitly flagged by the subagent: this ran
against the stale local `.venv` (last touched 2026-08-15), not the versions pinned in
`requirements.txt`/`requirements.lock.txt` (last touched 2026-08-31)** — see High finding #3
below. The test suite mocks the DB entirely (hand-rolled `FakeCursor`/fake-DB pattern across
~13 of ~24 test files) — no test exercises real MySQL, so real SQL syntax errors, FK behavior,
or migration-ordering issues (per the DB-schema pass's findings) are structurally invisible to
this suite. This is a ceiling-of-the-suite observation, not a claim that something currently
fails.

### Critical
None found that would block tomorrow's go-live via the documented deploy path, with one
caveat: GitHub branch-protection settings for `main` could not be checked (no local visibility),
which affects the severity of High finding #1 below.

### High

**1. Continuous "deploy" is fully decoupled from CI — a bad commit on `main` ships
automatically within ~10 minutes regardless of test results.** `deploy/systemd/sentinel-deploy.timer`
polls every 10 minutes (`OnBootSec=2min`/`OnUnitActiveSec=10min`); `deploy/sentinel-deploy.sh`
does `git fetch`, compares `origin/$BRANCH` to `HEAD`, and if different runs
`git pull --ff-only` then `docker compose up -d --build`. **Nothing in the script invokes
pytest, checks a CI status, or waits on `.github/workflows/test.yml`.** The CI workflow only
triggers on `push`/`pull_request`, entirely separate from the deploy poller. A post-hoc
health-check exists in the deploy script but only checks for a 200 response, so a logic bug
that still returns 200 will not trigger a rollback. **Not a go-live blocker by itself, but means
"the CI suite passed" is not a guarantee about what will actually be running tomorrow —
whatever is on `main` at poll time ships, tested or not.**

### Medium

**2. `.dockerignore`'s `.venv/` pattern does not exclude the 180MB `.venv.broken-stale-path/`
directory that exists in the working tree right now.** Verified: `git check-ignore -v
.venv.broken-stale-path` → no match (exit 1), vs `.venv` which matches. Not shipped via the
git-pull-based CD path since that only moves tracked/committed content (this directory is
untracked), but would bloat a build run directly against this checkout as-is.

**3. Local `.venv` used for `pytest`/dependency checks is stale and does not match the pinned
`requirements.txt`.** `.venv/pyvenv.cfg` dated 2026-08-15 vs `requirements.txt`/
`requirements.lock.txt` dated 2026-08-31. This means the 227-passed result above is evidence
about the code paths as tested locally, not proof about the exact library versions that will
ship (CI's own venv is built fresh from `requirements.txt` on every run, so CI itself is
testing the real pins — this is a "trust CI, not local repro" trap, not a current production
blocker).

**4. No automated, version-controlled backup schedule exists in the repo; `ENCRYPTION_KEY`
backup is 100% manual and unverifiable from source.** `deploy/backup.sh` exists and is
well-written (mysqldump + uploads tarball, `--single-transaction`, retention), and explicitly
documents that it does NOT back up `ENCRYPTION_KEY`: *"Uploads already Fernet-encrypted at
rest... but ENCRYPTION_KEY is NOT in here... Keep the key backed up separately off this box."*
`deploy/systemd/` contains timers for cert renewal, deploy, and a cloudflared watchdog, but
**no backup timer/service** — the only place backup scheduling is mentioned is
`deploy/DOCKER_DEPLOY.md` telling a human to configure it via OMV Scheduled Tasks/cron, a
manual, unversioned step. **Directly relevant to CLAUDE.md's item 4 ("back up ENCRYPTION_KEY
before going live") — there is no way to verify from the repo whether this has actually been
done on the real deploy host.**

**5. No structured logging, error tracking, or alerting anywhere in the app.** Grepped for
Sentry/Rollbar/Datadog/New Relic/`logging.handlers`/syslog across `app.py`, requirements, and
deploy configs — none found. The only error handling is a generic `@app.errorhandler(500)`
rendering `error.html`. Logs are container/journal stdout, capped at 30MB total in the Compose
path (`docker-compose.yml`, `max-size: 10m`, `max-file: 3`), with no rotation-aware retention
beyond that and nothing that proactively notifies anyone when an error occurs. **This is the
finding most directly relevant to "tomorrow's incident being undiagnosable"** — if the OSINT
critical bugs found in pass #2 fire in production, there is no alerting path that would surface
it.

**6. (Test suite mocking — folded into the intro note above, not a separate numbered High.)**

**7. `DB_CONFIG` has silent, dangerous defaults; unlike `SECRET_KEY`/`ENCRYPTION_KEY`, DB
credentials do not fail fast.** `app.py:132-137` — `DB_HOST` defaults `localhost`, `DB_USER`
defaults `root`, `DB_PASSWORD` defaults empty string. Cross-confirms the OSINT-pass's low-severity
note on the same lines: a typo'd or missing DB env var means the app boots looking healthy and
500s on the first real request, rather than refusing to start the way `SECRET_KEY`/
`ENCRYPTION_KEY` do.

**8-9. (Env var doc drift, folded here.)** `.env.example` declares `PASSWORD_RESET_TTL_HOURS`
and `RAZORPAY_WEBHOOK_SECRET`; diffing names only (no values read), the subagent found both
have safe code-level fallbacks (`app.py:516`, `3979`) and `active_payment_provider()` correctly
falls back to `ManualProvider` if Razorpay keys are absent — so not currently dangerous, but
worth closing before Razorpay is ever turned on.

**10. Stray large/backup files in the working tree — confirmed untracked, confirmed
dockerignored (except the stale venv, finding #2).** `output.pdf` (33.6M), `app.py.bak-20260808-231012`
(132K), `.venv.broken-stale-path/` (180M) are all untracked (`git ls-files --error-unmatch`
fails on each) and none will ship via the git-pull-based CD path. Also present, untracked, and
therefore also not shipping: this very `AUDIT_FINDINGS_DRAFT.md` file and `docs/REMEDIATION-PLAN.md`.

### Explicitly checked and found NOT a problem
- The shipped run path is confirmed `gunicorn` via `wsgi.py` + `Dockerfile` CMD +
  `deploy/sentinel.service` — the `app.run(debug=True, port=5000)` block at the bottom of
  `app.py` is dev-server-only and not reached by any of these paths.
- Compose network topology does not expose the app or DB directly — only `nginx` publishes a
  port, bound to `127.0.0.1:8080`, never `0.0.0.0`; `app` and `mysql` have no `ports:` mapping,
  reachable only over the internal Compose bridge network.
- `requirements.txt` and `requirements.lock.txt` agree (lock file is real `pip-compile` output
  of the same top-level pins).
- **`pip-audit` run against the actual pinned `requirements.txt` versions (installed into a
  fresh, gitignored venv for this check only — no tracked/shipped file touched) found nothing:**
  verbatim `No known vulnerabilities found`, confirmed with `-v` that it audited the pinned
  versions (`mysql-connector-python 9.1.0`, `Werkzeug 3.1.6`, `cryptography 50.0.1`), not the
  stale installed ones.
- Every third-party import in `app.py` (`mysql.connector`, `pyotp`, `qrcode`, `cryptography`,
  `dotenv`, `reportlab`, `flask`, `werkzeug`, `psutil`, `openpyxl`) is present in
  `requirements.txt` — no missing-dependency ImportError risk in a clean container.
- `.dockerignore` correctly excludes `.env`, `.git/`, `.claude/`, `uploads/`, `deploy/`,
  `output.pdf`, `app.py.bak-*` (only the stale-venv gap in finding #2 is missed).
- CI (`.github/workflows/test.yml`) runs the real test suite and a real `pip-audit` scan on
  every push/PR to `main` on Python 3.12.

### What the subagent could not verify
- GitHub branch-protection settings for `main` — no local visibility; determines whether High
  finding #1 (CD decoupled from CI) can actually let an untested commit reach `main` at all.
- Whether `deploy/backup.sh` is actually scheduled on the real deploy host, or whether
  `ENCRYPTION_KEY` has actually been backed up off-box — both are host-side operational facts
  not derivable from the repo.
- Real CVE data for the currently-*installed* (stale) `.venv` package set — only the pinned
  `requirements.txt` set (what will actually ship) was audited, deliberately, per instruction to
  quote real tool output rather than reconstruct CVE claims from memory.
- MySQL provisioning/schema state on any real target host — explicitly out of this pass's lane.
- Whether the `python:3.12-slim`/`nginx:1.27-alpine` base images are pinned by digest or have
  been refreshed recently.

---

## 5. Input handling / frontend / XSS audit — findings (subagent run, sonnet-deep)

Same CLAUDE.md auto-injection caveat as prior passes (disregarded its content; verified
independently). One explicit doc-vs-source disagreement found and resolved in source's favor:
`tools/bulk_import.py`'s own docstring claims "the only loader is a 20MB-capped HTTP admin
form" — subagent found no `MAX_CONTENT_LENGTH` or any size cap anywhere in `app.py`. The source
is authoritative; that comment is wrong.

**Tests run (the five assigned files), verbatim:**
```
35 passed, 1 warning, 12 subtests passed in 0.72s
```

### Critical
None found that are unconditionally exploitable pre-auth. The two XSS items below are scored
High rather than Critical because they require reaching an admin-authenticated endpoint first.

### High

**1. Stored/reflected XSS via "Upload Tool Package" (admin-authenticated).**
`templates/admin.html:273`, backend `app.py:3483-3499`. An uploaded JSON tool-package's `name`
field is stored to `services.name` and echoed back into `innerHTML` **unescaped**. A crafted
name executes JS in the admin's session immediately — and since it runs in-session, it can call
`/api/csrf-token` itself to mint its own token and drive arbitrary admin actions (e.g. enabling
CLI execution on a service, chaining into the RCE-adjacent CLI-test endpoint found in other
passes). CSP's `script-src 'unsafe-inline'` does not block this. **Should block go-live** —
described as a one-line fix (add `esc()`).

**2. Reflected XSS via CSV/XLSX header preview (admin-authenticated).**
`templates/admin.html:293`, backend `app.py:2995-3018`. Column headers from any previewed
import file are written into `innerHTML` unescaped — the row-*data* preview two lines later *is*
escaped, confirming this is an inconsistency/oversight, not a deliberate design choice. Any file
an admin is asked to "just preview" can pop JS in their session. **Should block go-live** —
same trivial-fix, meaningful-risk profile as #1.

**3. No request-size cap anywhere in the app.** No `MAX_CONTENT_LENGTH` set anywhere in `app.py`.
Every upload endpoint fully buffers the request into memory before checking size, including
`lea_register()` (`app.py:978-996`), reachable by any freely self-registered account — a
memory-exhaustion DoS vector open to any signed-up user, not just an admin. Subagent could not
verify whether a reverse proxy (nginx, out of this pass's scope) enforces a body-size cap that
would mitigate this — scored against `app.py` alone, which has none regardless. **Should block
go-live or be capped at the proxy layer before tomorrow.**

### Medium

**4. Public homepage renders admin-set CMS fields via `innerHTML` with zero sanitization.**
`templates/index.html:28`, `app.py`'s `save_site_content()`. Intentionally accepts raw HTML
(defaults contain `<br>`/`<span>`), so whoever can write that setting controls script execution
for every site visitor. The subagent explicitly connects this to the RBAC-enforcement gap found
in the auth pass (owned by a different pass, not re-audited here): this is the highest-blast-radius
sink that gap runs through, worth flagging even without re-auditing RBAC itself.
**5.** File-upload type validation is extension-only (`app.py:203-204`, `allowed_file`) — no
magic-byte check. Mitigated by being admin-only and by the read path forcing mimetype from the
extension, but a crafted PDF with embedded JS would still execute in a browser PDF-viewer sandbox.
**6.** `import_execute_v2()` (`app.py:3563-3584`) has no error handling around its insert loop —
a non-required numeric field with a bad value (e.g. `duration="N/A"`) crashes the row-insert with
an uncaught `ValueError`, and the DB connection is never closed on that path (a real connection
leak, cross-confirming the DB-schema pass's systemic finding). Atomicity itself is fine
(autocommit off, `commit()` only at the end) — inferred from documented connector defaults, not
observed against a live MySQL instance.
**7.** "Custom" import module silently discards all data while reporting success —
cross-confirms the DB-schema pass's identical finding (`app.py:3414` vs. `3573-3583`): no insert
branch for `module=='custom'`, but the row-count still increments and the UI reports success.
**8.** Import parsers silently drop non-UTF-8 bytes (`app.py:2998, 3007, 3153`, `errors="ignore"`)
— non-UTF-8 CSV/XLSX exports (common from legacy telecom/government tooling) get silently
corrupted with no warning.
**9.** CSV formula injection on client-side export — `static/cdr_analysis.js:413-427`'s
`exportCSV()` doesn't neutralize a leading `=`/`+`/`-`/`@`; a payload embedded in an untrusted
CDR/IPDR source file survives re-export and can execute if opened in Excel.

### Low
**10.** Unescaped error sink, not currently reachable — `templates/dashboard.html:218` —
`d.error` goes into `innerHTML` raw, but today's only possible value is a fixed string (latent
trap, not a live bug).
**11.** "Download PDF Report" doesn't produce a PDF — `app.py:3792-3795` returns a `.json`
attachment despite the route/button name. Cosmetic/functional, not security.
**12.** `app.run(debug=True, host="0.0.0.0")` still present at `app.py:4270` — cross-confirms
prior passes; subagent explicitly did not score this against go-live since actual reachability
is a deployment-config question (other passes have since confirmed it is NOT reachable via the
shipped gunicorn path).

### Explicitly checked and found NOT a problem
- Error handlers (`app.py:790-797`) return fixed, generic messages — confirmed no
  `render_template()` call anywhere passes exception content into a response.
- `/uploads/<filename>` path-traversal guard (`app.py:1749-1769`) correctly implemented
  (`secure_filename()` on both read and write) — confirmed by source reading AND by running
  `tests/test_uploads_and_events.py`.
- **CSRF coverage on the frontend is comprehensive**: a global `window.fetch` monkey-patch in
  `admin.html`/`dashboard.html`/`pricing.html` (each ~line 110-135) attaches `X-CSRF-Token` to
  every POST/PUT/DELETE/PATCH automatically — no call site can forget it, and no raw
  `XMLHttpRequest` usage exists anywhere. Resolves the "does every fetch send CSRF" question
  from the auth pass's scope with a clear yes.
- Client-side price/credit trust: the buy button only sends `plan_id`; price/credits are always
  re-looked-up server-side from `recharge_plans`, never trusted from the client.
- No SQL injection found in any reviewed query — all use `%s` placeholders.
- No zip/archive handling exists anywhere in the upload/import code.
- `sentinel_modules/checksums.py`/`identity.py` are pure, well-guarded functions, no injection
  surface.
- PDF report builder (`_build_mobile_lookup_pdf`, `app.py:2726-2795`) correctly `xml_escape()`s
  every interpolated field — cross-confirms the OSINT pass's identical finding.

### What the subagent could not verify
- Whether `app.run(debug=True)` is reachable in the real deployment — deployment-config
  question, and other passes have since resolved this: not reachable via the shipped path.
- Whether a reverse proxy enforces a body-size cap mitigating finding #3 — out of this pass's
  scope, not opened.
- Actual browser-level exploitation of the XSS findings — no running instance with a browser was
  available; findings are confirmed by direct source/template inspection of the literal
  unescaped-interpolation code, not dynamic testing.
- Whether the pinned `mysql-connector-python` version's `autocommit=False` default (used to
  reason about finding #6's atomicity) holds — inferred from documented connector defaults, not
  observed against a live MySQL instance (none available in this environment).

### My own notes from direct reading (before subagent dispatch, this session)
- Read `db_setup.sql` in full directly (364 lines) — matches subagent's schema summary.
- Read `app.py:4040-4199` (payment/webhook code) directly — `credit_payment_order()` idempotency
  logic confirmed by me independently, matches subagent finding.
- `app.py:186-209` (`get_db`, `db_conn`, `allowed_file`, `now_utc`) read directly.
- `DB_CONFIG` (`app.py:132-137`) read directly — no default password fallback beyond empty
  string, host/user/db all env-driven.
- Confirmed via `git branch --no-merged main`: `resolve-day3` and
  `worktree-day3-mobile-osint-pdf-fallback` are NOT merged into `main`. `resolve-day3` fixes a
  bug in `mobile_lookup_report_pdf` (app.py ~line 2818): the old `master_data_records` fallback
  used `data_json LIKE '%query%'` (unindexed full-table-scan AND defeated `record_key`'s index
  on the OR branch) and was a **substring match** — meaning a PDF report tied to one case
  reference could print an unrelated subscriber's data. The unmerged fix changes it to an exact
  `record_key=%s` match. **This is directly relevant to tomorrow's OSINT go-live and is currently
  NOT merged into main** — flag prominently in final report.

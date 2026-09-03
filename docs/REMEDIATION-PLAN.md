# Sentinel Platform — Remediation Plan (Fix Order)

**Target:** github.com/Kush69420/sentinel-platform @ `5ac30d8` (origin/main)
**Audit date:** 2026-08-26
**Scope:** backend, data layer, deploy/infra, tests, repo hygiene. Frontend/UI excluded.
**Method:** 4 parallel deep agents; every Critical/High finding independently re-verified against source.

Ordered by the sequence they should be fixed in. Each phase is independently shippable.
Do not reorder Phase 1 — items 1-3 form a single privilege-escalation chain and are only
fully closed together.

> **Before starting:** your local checkout is 4 merged PRs behind origin/main
> (local `967d5b2` vs remote `5ac30d8`). `git pull` first.


---

# WHAT IS ACTUALLY NEW

Every finding below is tagged against the project's existing docs (`CLAUDE.md`,
`DAY1/DAY2_HANDOVER.md`, `deploy/DOCKER_DEPLOY.md`, `plans/*.md`). The audit was run
*without* reading those files so it would be independent; this is the comparison.

| Tag | Count | Meaning |
|---|---|---|
| `[NEW]` | **23** | Nothing in any doc covers it. |
| `[ALREADY KNOWN]` | 6 | Docs describe the same defect, with the same severity. |
| `[KNOWN BUT MISDESCRIBED]` | 5 | Docs mention the area but get the mechanism or scope materially wrong. |
| `[MENTIONED IN PASSING]` | 1 | Docs reference the thing but never as a problem. |
| `[KNOWN BUT CLAIMED FIXED]` | **0** | No documented "fixed" claim was contradicted by the code. Nothing regressed. |

## Read this before Phase 1

**Findings 1.1, 1.2 and 1.3 were already known and were deliberately deferred** —
they are not a discovery. `CLAUDE.md:112-140` documents all three, with essentially the
same analysis the audit reached independently, including the precise mechanism:

> "**Hardcoded default admin credential, no forced rotation** ... only a comment says
> 'CHANGE IMMEDIATELY,' nothing enforces it. **Deferred** — will be fixed together with
> RBAC enforcement."
> "**RBAC modeled but never enforced** ... **Deferred, tied to a planned OAuth2
> implementation** — not touched by Day 2, deliberately."
> "**CLI execution endpoint = admin-to-RCE** ... `{query}` is substituted before
> `shlex.split`, so not shell-metacharacter injectable, but is argument-injectable into
> whatever binary is configured. Same deferral as RBAC above."

So the value of Phase 1 is **not** that these were found. It is that all three were
deferred *separately*, on the assumption each could wait for the OAuth2 work — and the
audit shows they compose into a single chain that is live the moment the tunnel opens.
The deferral decision was made per-item; it should be re-taken for the chain as a whole.

**1.4 (2FA disable needs no re-authentication) is genuinely new** and is the one Phase 1
item no doc anticipated.

## Where the real new value is

The densest clusters of genuinely new findings are **Phase 3 (correctness)** — 3.1, 3.2,
3.3 and 3.4 are all `[NEW]`, and none of the four appear in any doc — and **Phase 4.3**
(vulnerable pinned dependencies), which no document mentions at all.

---

# DOC-CONTRADICTS-CODE

Places the documentation asserts something the code contradicts. Fix the docs, not just the code.

**(a) The Cloudflare tunnel docs describe an architecture that is no longer deployed.**
`deploy/DOCKER_DEPLOY.md:169-172` states: *"Because it runs with `--token`, its ingress lives
in the Cloudflare Zero Trust dashboard, **not** in any file in this repo."*
`deploy/env.compose.example:36-39` repeats it. But `docker-compose.yml:148-183` actually runs
`--config /etc/cloudflared/config.yml`, with ingress in `deploy/cloudflared.sentinel.yml`,
in the repo. Commit `98a9c9d` ("Move the tunnel's ingress into the repo instead of the
dashboard") changed the mechanism and the docs were never updated. An operator following
`env.compose.example` would configure a dashboard tunnel the container never reads.
This is the root cause of finding 4.5's dead `CLOUDFLARE_TUNNEL_TOKEN`.

**(b) `DAY2_HANDOVER.md:240-241` is stale on packaging.** It says *"Day 5 packaging
untouched: no `wsgi.py`, no gunicorn config."* Both exist at `5ac30d8` (`wsgi.py`,
`Dockerfile:42` `CMD ["gunicorn", ...]`), landed by commit `b3c3efd`. This is why the
audit scores `app.run(debug=True)` as Low: gunicorn is the real entrypoint, so that line
is dead in production.

**(c) The docs describe the wrong failure mode for key loss.** `CLAUDE.md:36-38` and
`DOCKER_DEPLOY.md:119-122` say that if `ENCRYPTION_KEY` is lost *"every encrypted value
becomes permanently unrecoverable"* — i.e. it fails loudly. In fact `decrypt_text` returns
the **raw ciphertext** on `InvalidToken`, so a key rotation silently degrades every stored
secret to plaintext handling with no error. Quieter and worse than documented.

---

# DOC-ONLY RISKS — real risks the docs already knew and this audit did NOT cover

These are gaps in the audit, not in the docs. Do not read the audit's silence here as safety.

1. **Buffer pool vs. dataset size.** `DOCKER_DEPLOY.md:302-310`: the buffer pool caches
   *"well under 1% of the projected ~400 GB dataset, on spinning disks. Every query must
   stay an index-driven point lookup. Table scans, aggregate reporting and leading-wildcard
   `LIKE` will not perform acceptably."* The audit never assessed query patterns against
   this constraint.
2. **`master_data_records` fallback is an unindexed full-table-scan `LIKE`.**
   `plans/MOBILE_OSINT_PLAN.md:53-64` — `mobile_lookup_report_pdf()` runs
   `WHERE record_key=%s OR data_json LIKE %s`. Invisible today because the table is empty;
   a per-report table scan at production volume.
3. **No bulk-import path exists at all.** `plans/DATA_POPULATION_PLAN.md:1-24`: the only
   loader is a 20MB HTTP form; full materialisation defeats `read_only=True` (peak RAM ~3x
   file inside a 1GiB cap), N+1 BTS lookup per row, a single commit at the end, and
   `gunicorn --timeout 630` kills any real import at 10.5 minutes. Finding 3.1 fixes error
   handling in `import_execute_v2` but does not touch this scalability cluster.
4. **`mobile_lookup` has no data to query.** `plans/MOBILE_OSINT_PLAN.md:25-51`: the v2
   pipeline writes typed tables while `mobile_lookup` reads `master_data_records`, populated
   only by the legacy path. Two divergent import paths; all target tables currently empty.
   A functional dead end rather than a security bug — which is why the audit missed it.
5. **Campus captive-portal gateway.** `DOCKER_DEPLOY.md:66-98, 317-318` calls this
   *"the single most likely cause of any outage,"* masquerading as TLS cert errors, pip
   failures and cloudflared timeouts. Out of the audit's remit entirely.

---

# PHASE 1 — Deploy blockers (do first; hours of work)

These three combine into one exploit chain: known default credentials -> any admin ->
OS command execution inside the app container. Fixing any one alone leaves the chain intact.

## 1.1 Remove the seeded default super-admin  
**`[ALREADY KNOWN — deliberately deferred]`**
**Severity:** Critical · **File:** `db_setup.sql:25-27`

```sql
-- Default admin: username=admin, password=admin123. CHANGE IMMEDIATELY.
INSERT INTO admin_users (name, username, password_hash, role)
VALUES ('Super Admin', 'admin', 'pbkdf2:sha256:600000$sentinelsalt1234$759d...', 'super_admin')
ON DUPLICATE KEY UPDATE username=username;
```

Static salt `sentinelsalt1234`. Unchanged since initial commit `70f9987`. Executed
unconditionally by `deploy/db-init/00-apply-schema.sh:30` on first container init.
Verified: no forced-change logic exists anywhere (`must_change_password|force.*password`
returns no matches in `app.py`). The only safeguard is the SQL comment itself.
`docker-compose.yml:167-169` concedes the tunnel goes live with this seed active while
Cloudflare Access is not enabled.

**Fix:** seed with `is_active=0`, OR generate a random password at provision time and print
it once to the operator. Add a first-login forced-reset gate in `app.py`. Make the deploy
health check fail until the default credential is no longer valid.

## 1.2 Enforce the RBAC role gate  
**`[ALREADY KNOWN — deliberately deferred]`**
**Severity:** High · **File:** `app.py:300` (definition), `db_setup.sql:15` (schema)

`role_required(*roles)` is fully implemented and **never applied to a single route** —
verified, line 300 is its only occurrence in the entire file. The schema defines
`role ENUM('super_admin','manager','support') DEFAULT 'support'` but every admin endpoint
uses only the coarse `admin_required`, which accepts any row in `admin_users`. A
`support`-tier admin — the intended lowest privilege — has full `super_admin` reach.

**Fix:** apply `@role_required('super_admin')` to `cli-test`, `tool_package_upload_v2`, and
the `services` create/edit/delete routes at minimum. Then audit all ~40 admin routes against
the intended role matrix.

## 1.3 Harden the CLI-execution endpoint  
**`[ALREADY KNOWN — deliberately deferred]`**
**Severity:** Critical (as a chain) · **File:** `app.py:3398`

```python
cmd=(svc.get('external_command') or '').replace('{query}',str(q))
proc=subprocess.run(shlex.split(cmd),capture_output=True,text=True,timeout=...,cwd=BASE_DIR)
```

`/api/admin/tools/<id>/cli-test` splices an admin-supplied `query` into a stored command
template via plain `str.replace` **before** `shlex.split`. Not classic shell injection
(no `shell=True`) but full **argument injection** into whatever binary the service points at.
An admin can also create the service row first via `POST /api/admin/services` (also only
`admin_required`), choosing both the binary and the flags.

**Fix:** pass `query` as a discrete list element to `subprocess.run` rather than splicing it
into a template string. Allow-list permitted binaries. Combine with 1.2.

## 1.4 Require re-authentication to disable 2FA  
**`[NEW]`**
**Severity:** High · **File:** `app.py:1576-1591`

Verified: `disable_2fa()` reads `session["admin_id"]` and immediately runs
`UPDATE admin_users SET twofa_enabled=0, twofa_secret=NULL, recovery_codes_hash=NULL`.
No password, no current OTP, no recovery code. Any session compromise (stolen cookie,
unattended terminal, XSS) becomes permanent 2FA removal.

**Fix:** require the current password or a fresh OTP in the request body and verify before
clearing. `/api/user/password-change` already implements this pattern correctly — mirror it.

---

# PHASE 2 — Make changes verifiable (do before any refactor)

Without this, nothing in Phase 3+ can be safely confirmed.

## 2.1 Add CI — the suite does not run from a clean clone  
**`[PARTLY KNOWN — gap planned, specifics NEW]`**
**Severity:** High · **Files:** `.github/workflows/` (does not exist — verified)

`python3 -m unittest discover` -> **130 tests, 50 errors, 5 failures.** All 50 errors trace to
`app.py:39: import mysql.connector` -> `ModuleNotFoundError`. Every file doing
`import app as app_module` dies. Only `test_checksums.py` and `test_identity.py` genuinely pass.

The 5 `test_failfast_secrets.py` failures are that same import error surfacing inside a
subprocess — so that test currently passes/fails on a false premise, not on the `SECRET_KEY`
fail-fast behaviour it claims to verify.

**Fix:** add `.github/workflows/test.yml` — fresh venv, `pip install -r requirements.txt`,
`pytest tests/ -q`, plus `pip-audit`. Until this exists, "tests pass" is unverifiable by anyone.

## 2.2 Replace the fake access-control tests with real ones  
**`[KNOWN BUT MISDESCRIBED]`**
**Severity:** High · **File:** `tests/test_access_control.py` (all 285 lines)

Every assertion is a substring match against `APP_SOURCE`, the raw **text** of `app.py`.
It never calls `test_client()` and passes with zero dependencies installed. The webhook test
only asserts that `"verify_webhook("` appears at a lower string **index** than
`"credit_payment_order("` — satisfied by an empty guard body, or by dead code containing the
tokens in that order. This file is the **only** coverage claiming to guard payments, LEA
approval, and IDOR.

**Fix:** keep it as a static regression tripwire, but stop counting it as functional coverage.
Add real `test_client()` tests for: `/api/payments/webhook/<provider>` (valid + forged
signature + replay), `/api/admin/lea/applications/<id>/approve`, and the password-reset
token issue/consume flow.

## 2.3 Enable branch protection  
**`[NEW]`**
**Severity:** High

`gh api repos/Kush69420/sentinel-platform/branches/main/protection` -> `404 Branch not protected`.
Combined with 2.1, there is currently **zero** merge gate ahead of production.

**Fix:** `gh api -X PUT .../branches/main/protection` with `required_pull_request_reviews`,
then add the 2.1 workflow as a required status check.

## 2.4 Fix assertions that let a crash pass  
**`[NEW]`**
**Severity:** Medium · **Files:** `tests/test_csrf.py:130,204,209,218`,
`tests/test_uploads_and_events.py:82,90`

`assertNotEqual(resp.status_code, 403)` / `assertNotEqual(..., 200)` — a 500 satisfies these
just as well as correct behaviour, silently masking regressions.
**Fix:** assert the exact expected code (401/404/400) at each of the 6 sites.

---

# PHASE 3 — Correctness bugs

## 3.1 `import_execute_v2` has no error handling and duplicates CDR/IPDR rows  
**`[NEW]`**
**Severity:** High · **Route:** `POST /api/admin/import/execute`

Verified: **zero** `try`/`except` in the entire function. Any bad row (bad datatype, string
too long, connection blip) raises an unhandled 500, `conn.close()` never runs (connection
leak), and the admin gets no partial-success report. `admin_data_upload()` elsewhere in the
same file does this correctly per-row — follow that pattern.

Separately: `cdr_records` and `ipdr_records` have **no unique constraint** (only non-unique
`INDEX idx_lac_cell`) and **no** `ON DUPLICATE KEY UPDATE`. Re-running or double-submitting
the same import silently duplicates every row, skewing the call-frequency and contact-graph
analytics investigators rely on. `subscriber`, `vehicle`, `bts` are correctly upserted.

**Fix:** per-row `try`/`except` writing to the existing `import_errors` table instead of
aborting; use `db_conn()`. Then decide intent for CDR/IPDR re-import: add a natural-key
unique constraint + upsert, or guard against re-running the same batch.

## 3.2 CDR/IPDR mode switch scrambles columns  
**`[NEW]`**
**Severity:** High · **File:** `static/cdr_analysis.js` (mode-toggle handler in `bind()`;
grep `state.mode = b.dataset.mode`)

Switching CDR <-> IPDR after a file is loaded rebuilds rows using the **outgoing** schema's
column order, then hands them to `ingest()` with the **original** raw headers — where
`buildColumns()` recomputes `rawIdx` against original header positions. Two unrelated index
spaces. Traced concretely: the IPDR `lac` column (rawIdx=7) reads `r[7]`, which holds the old
CDR schema's `imsi`. Silent — no error, no warning — and produces investigator-facing data
that is simply wrong.

**Fix:** cache the original parsed 2D row array at load time (`state.rawRows`) and on mode
switch call `ingest(state.rawHeaders, state.rawRows)` directly.

*(Traced by code-path analysis, not executed in a browser.)*

## 3.3 `modify_credits` lost-update race  
**`[NEW]`**
**Severity:** Medium · **Route:** `POST /api/admin/users/<int:user_id>/credits`

Verified non-atomic: `SELECT * FROM bot_users WHERE id=%s` then
`UPDATE bot_users SET credits=%s`. Concurrent admin adjustments, or an adjustment racing a
user spend, lose an update. This is the **one** exception — `charge_for_lookup`,
`log_service_usage_internal` and `credit_payment_order` all correctly use
`SET credits = credits ± %s WHERE credits >= %s` + `rowcount` check.

Also in the same handler: `int(data.get("amount", 0))` is unguarded — `"abc"` gives a 500
instead of a 400.

**Fix:** `UPDATE bot_users SET credits = credits + %s WHERE id=%s`; derive the transaction-log
delta from `rowcount`/a follow-up SELECT, not the pre-read value.

## 3.4 Connection leaks in the logging helpers  
**`[NEW]`**
**Severity:** Medium · **Functions:** `table_has_column`, `log_audit`, `log_activity`

All three open a raw `get_db()` and call `conn.close()` only on the success path. Any
exception — precisely the case these functions exist to tolerate — leaks the connection.
`table_has_column` runs on **every** `log_audit` call. There is no pooling anywhere
(`get_db()` is a bare `mysql.connector.connect`), so sustained DB errors exhaust
`max_connections` under gunicorn and take down unrelated requests.

**Fix:** `try/finally: conn.close()`, or migrate onto the existing `db_conn()` context manager.

## 3.5 Remaining lower-severity items
- `[KNOWN BUT MISDESCRIBED]` **Medium** — `official_email` uniqueness exists only if `migration_selfserve_auth.sql` was
  applied; without it, signup's SELECT-then-INSERT is a real TOCTOU. (`phone` is safe —
  UNIQUE in `db_setup.sql` itself.)
- `[ALREADY KNOWN]` **Medium** — In-process rate limiter is per-gunicorn-worker and resets on restart: a
  10-per-5-min login limit becomes `10 x worker_count`. Partly mitigated by the DB-backed
  lockout (`failed_login_limit=3`, `lockout_hours=2`). Fix: shared store (Redis/DB), or
  document `workers=1` as intentional.
- `[ALREADY KNOWN]` **Low** — `app.py:4199`: `app.run(debug=True, host="0.0.0.0", port=5000)`. Werkzeug debugger
  RCE if ever run directly. Gate on an env var defaulting to `False`.
- `[NEW]` **Low** — `decrypt_text` returns the raw ciphertext on `InvalidToken`. An `ENCRYPTION_KEY`
  rotation without a re-encryption migration silently degrades every stored secret to
  plaintext handling with no error surfaced. At minimum log a warning (never the value).
- `[ALREADY KNOWN]` **Low** — CSP ships `'unsafe-inline'` for both `script-src` and `style-src`
  (`app.py:411-412`). Not currently load-bearing (templates escape correctly) but it neuters
  CSP as XSS defence-in-depth. Nonce-based CSP is a 9-template refactor — track, don't rush.
- `[NEW]` **Low** — Dead code: `... if False else None` in AI provider model selection, plus a
  redundant double-parse of `config_json`.
- `[NEW]` **Low** — 4 user routes use inline session checks instead of `@user_required`
  (`user_profile`, `user_password_change`, `user_2fa_setup`, `user_2fa_enable`). All present
  and correct, but not grep-able or lint-able.
- `[NEW]` **Confirm intent** — `/api/tools/cdr/analyze` and `/api/tools/ipdr/analyze` require
  `user_required` but not `verified_required`, unlike every other tool. May be deliberate
  (user's own uploaded file vs. the subscriber database). Decide and make it explicit.

---

# PHASE 4 — Operational readiness

## 4.1 Backups do not run  
**`[MENTIONED IN PASSING — never flagged as a defect]`**
**Severity:** High · **File:** `deploy/backup.sh:2` ("Nightly backup: ...")

Verified across `deploy/systemd/*`, `install-cd.sh`, `sentinel-deploy.sh`, `prepare-host.sh`:
there is **no** `backup.service` / `backup.timer`, and nothing installs or schedules
`backup.sh`. `sentinel-deploy.timer:9` even references "the backup job" in a comment as
though it exists. As shipped: zero automated backups of the database or the irreplaceable
encrypted gov-ID uploads.

**Fix:** ship `deploy/systemd/sentinel-backup.service` + `.timer` (oneshot, `OnCalendar=daily`,
`Persistent=true`) and install them from `install-cd.sh` like every other unit.

## 4.2 No restore path or dump-integrity check  
**`[KNOWN BUT MISDESCRIBED]`**
**Severity:** High

`backup.sh` produces `mysqldump | gzip` but never verifies the result, and no restore script
exists anywhere in `deploy/`. `set -euo pipefail` catches command failure but not a truncated
or empty dump.

**Fix:** add `gzip -t` + non-zero-size check after the dump, failing loudly. Add a restore
script and a periodic restore drill. Untested backups are not backups.

## 4.3 Bump vulnerable dependencies  
**`[NEW]`**
**Severity:** High · **File:** `requirements.txt:1-15`

- `werkzeug==3.0.1` — CVE-2024-34069 (debugger RCE, CVSS 7.5, exploited in the wild; fixed
  3.0.3), CVE-2024-49767, CVE-2024-49766. Needs >=3.1.4 to clear all known issues.
- `cryptography==42.0.5` — multiple major versions behind (current line 50.x), several
  post-42.x CVEs apply.
- `flask==3.0.0`.

No lockfile pins transitive deps; no Dependabot/CI to catch drift.
**Fix:** bump, pin transitives with `pip-compile`/`uv pip compile`, wire `pip-audit` into 2.1.

## 4.4 Migration runner and version tracking  
**`[NEW — but see note]`**
**Severity:** Medium

`migration_activity_log_actor.sql` is mounted **nowhere** and run **nowhere** in the Docker
init path (`00-apply-schema.sh:30-40` runs five files; this is the sixth) and is unapplied on
the live DB — see open PR #6. Its composite `idx_actor` index on
`activity_log(actor_type, actor_id)` therefore never gets created, making "show me everything
user 2 did" a full table scan.

More broadly: 5 ad-hoc `migration_*.sql` applied by hand with no ordering enforcement and no
`schema_migrations` table. One (`migration_fix_import_errors.sql`) is *conditional on another
having failed*. "Have I run this yet?" is tribal knowledge.

> **Note on `[NEW]`:** the repo owner independently found this the same day — commit
> `07c5cde` on the unmerged branch `worktree-claudemd-migration-note` (open PR #6)
> describes it almost verbatim. It is absent from `CLAUDE.md` as checked out at `5ac30d8`,
> so it was new to the docs a reader would see, but it is not an independent discovery in spirit.

**Fix:** add the missing migration to the compose mounts and the run list now. Then introduce
a `schema_migrations` tracking table and an idempotent runner that `sentinel-deploy.sh` calls
on every tick.

## 4.5 Smaller infra items
- `[NEW]` **Medium** — MySQL root password is baked into `docker-compose.yml:52`'s healthcheck
  exec-array; Compose interpolates at parse time, so it lands in `docker inspect` output.
- `[KNOWN BUT MISDESCRIBED]` **Medium** — `CLOUDFLARE_TUNNEL_TOKEN` is dead config. `env.compose.example:36-45` describes
  dashboard-managed token ingress, but the container is hardwired to
  `--config /etc/cloudflared/config.yml`. An operator following the example would configure a
  tunnel the container never uses.
- `[NEW]` **Medium** — nginx `location /` has no explicit proxy timeout, inheriting the 60s default,
  while gunicorn is deliberately set to `--timeout 630`. Long PDF exports and bulk imports get
  a silent 504 while gunicorn is still working.
- `[NEW]` **High** — `cloudflare/cloudflared:latest` is unpinned, on the one component carrying all
  internet traffic. Other images are tag-pinned (though not digest-pinned).
- `[NEW]` **Low** — `.dockerignore` omits `*.md`, `plans/`, `tests/`, so internal docs and the full
  test suite ship inside the production image.
- `[NEW]` **Low** — No `HEALTHCHECK` in the Dockerfile (compose-level only). `caa-renew.sh` omits `-e`
  unlike its sibling scripts. `realip.*.conf` trusts the whole `172.28.0.0/16` subnet rather
  than the specific peer container.

---

# PHASE 5 — Structural (only after Phases 1-4)

**`[ALL ITEMS IN THIS PHASE ARE NEW]`**

The highest-leverage single change: migrate the ~61 raw `get_db()` call sites onto
`db_conn()` (or a `mysql.connector.pooling.MySQLConnectionPool`). That one change would have
prevented or narrowed most of the leak findings in Phase 3.

Then split `app.py` (4,199 lines) into blueprints in this order — each independently
shippable and testable before the next:

1. **`payments`** — provider classes plus all `/api/*payment*` and `/api/admin/*order*`
   routes. Most self-contained, smallest shared-state surface.
2. **`imports`** — `_parse_import_file`, `validate_import_rows`, `import_execute_v2`,
   `admin_data_upload`, `rollback_import`, CDR/IPDR analysis. Fix 3.1 while the code is
   already being moved.
3. **`auth`** — user + admin signup/login/logout/2FA/password-reset. 3.5's constraint
   dependency and the admin/user login asymmetry are easiest to fix once these sit together
   instead of scattered across ~1000 lines.
4. **Last:** lookup-tool dispatch, `charge_for_lookup`, OSINT integrations, admin settings —
   most interdependent. Extract shared `db.py` / `audit.py` first so every blueprint imports
   from one place.

**Housekeeping:** delete `package-lock.json` (empty, no `package.json` ever existed). Delete
merged branches `worktree-csrf-lockout-bugfixes`, `worktree-frontend-prod-hygiene`,
`worktree-sentinel-open-issues-1-4`, and the superseded
`worktree-day3-mobile-osint-pdf-fallback` (obsoleted by `2b142a7`). Move the ~70KB of
handover/plan docs out of the repo root.

---

# VERIFIED CLEAN — do not spend time here

- **No secrets were ever committed.** Full-history scan: no `.env`, `*.pem`, `*.key`,
  `credentials.json`, no AWS-shaped keys, no private-key blocks, no live connection strings.
  `.env.example` is a genuine template. Total pack size 362 KiB.
- **SQL injection: exhaustively absent.** All user-influenced queries parameterised; the only
  two f-string identifiers draw from hardcoded tuples.
- **IDOR:** user endpoints correctly scope to session `user_id`/`user_phone`
  (`WHERE id=%s AND user_id=%s`).
- **Upload traversal:** `secure_filename()` on both write **and** serve; `.enc` files served
  only after Fernet decryption with a fixed extension->mimetype map.
- **CSRF:** session-bound double-submit token, `hmac.compare_digest`; exemptions limited to
  genuinely pre-auth endpoints.
- **Payments:** webhook HMAC-SHA256 via `compare_digest`; crediting idempotent
  (`WHERE status<>'paid'` + rowcount). No double-spend or negative-balance race found.
- **Passwords/tokens:** PBKDF2-SHA256 600k; reset tokens hashed, single-use, TTL-bound,
  invalidated on reissue; generic responses (no user enumeration).
- **Secrets fail closed:** `SECRET_KEY` and `ENCRYPTION_KEY` refuse to start outside dev.
- **Proxy chain:** `TRUSTED_PROXY_COUNT=1` matches nginx emitting exactly one XFF hop;
  `CF-Connecting-IP` used. No client IP spoofing while nginx stays loopback-only.
- **Container posture:** DB publishes no ports; nginx binds `127.0.0.1:8080` only; app runs as
  non-root UID 10001; mem limits + log rotation on all 4 services; healthchecks chained via
  `service_healthy`; deploy has a real health-gated rollback; gunicorn graceful shutdown.
- **`checksums.py`** verified by execution — Verhoeff, Luhn, GSTIN correct against known vectors.
- **Good tests** (calibration): `test_checksums`, `test_identity`, `test_mobile_lookup_credits`,
  `test_service_usage_race`, `test_import_rollback`, `test_mobile_lookup_pdf_report`,
  `test_user_auth`, `test_admin_login_session_fixation`.
- **Commit hygiene:** 61 commits, consistently descriptive. No wip/filler commits.

---

# NOT COVERED — not a clean bill of health

- No live MySQL available: schema and migrations were never validated end-to-end, and the
  suite's hermetic design is unproven by execution.
- No dependency CVE scan actually run against `requirements.txt`.
- **Unresolved, worth a follow-up:** whether an admin-supplied integration `base_url` can be
  pointed at an internal address. URLs use `quote()` rather than concatenation, but no
  private-IP / DNS-rebinding guard was seen in `_test_integration()` or `call_ai_provider()`.
- `cdr_analysis.js` CSV parser quote-toggle (`inQ` flips on any `"`, not only at field
  boundaries) was noticed but not traced to a failing case.
- No exhaustive naive-vs-aware datetime sweep. Session uses `datetime.utcnow().isoformat()`
  (naive) while `now_utc()` is aware; only login/session paths were spot-checked.
- No exhaustive duplicate-`def` / dead-import sweep; no full input-validation sweep.
- systemd hardening directives for the root-running units not fully assessed.
- Templates `index/login/register/reset_password/error` not read; 4 `migration_*.sql` grepped
  but not read in full.
- Frontend/UI excluded from scope entirely by request.

---

# APPENDIX — Coverage numbers

- `app.py`: 4,199 lines, **90 routes** (verified count), all registered directly on `app`
  (no blueprints).
- Only **~21 URL paths (~23%)** receive any `test_client()` execution.
- Untested categories: the **entire** payments/billing surface
  (`/api/payments/checkout`, `/api/payments/webhook/<provider>`, all `/api/admin/payments/*`);
  `/api/admin/import/execute` (the live writer, despite rollback tests existing to undo it);
  a ~30-route admin CRUD surface (users, credits, integrations, AI providers, SMTP, services,
  plans); `/api/tools/run` for every tool code except `mobile_lookup`; `/api/lea/register`
  (public encrypted gov-ID upload); CDR/IPDR analyze; universal search; AI chat.
- No `conftest.py` exists. `_rate_limiter._windows` is process-global, cleared ad hoc by only
  4 test files — a latent order-dependence hazard under `pytest-xdist`.
- No lint, type-check, or formatting config anywhere (`pyproject.toml`, `setup.cfg`,
  `.flake8`, `mypy.ini` — none exist).

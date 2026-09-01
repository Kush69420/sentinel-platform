# Plan — Bulk Data Population (~200 GB xlsx → MySQL)

**Status:** not started. Written 2026-08-19.
**Blocking:** all data population. Nothing else on the roadmap blocks it.

## The problem in one line

There is no bulk import path. The only loader is a 20 MB-capped HTTP admin form that
buffers whole files in RAM and cannot resume after a failure.

## Evidence (verified by reading the code, not inferred)

| Finding | Location |
|---|---|
| `client_max_body_size 20m` — sized in-comment for gov-ID scans | `deploy/nginx.conf:10`, `deploy/nginx.docker.conf:34` |
| Only xlsx parser; reachable *only* from 4 HTTP routes | `_parse_import_file`, `app.py:2878` |
| `read_only=True` defeated by `list(ws.iter_rows(...))` + second list of dicts → peak RAM ~3x file, inside a **1 GiB** container cap | `app.py:2885-2889` |
| `_bts_lookup2` SELECT **per row** for `cdr`/`ipdr` (N+1) | `app.py:3414`, `app.py:3417` |
| One `conn.commit()` at the very end; no `executemany`, no chunking | `app.py:3418` |
| `import_batches` written `status='imported'` *before* the loop; never tracks progress | `app.py:3405` |
| `gunicorn --timeout 630` kills any import at 10.5 min | `Dockerfile` |
| `local_infile = 0` live → `LOAD DATA LOCAL INFILE` unavailable | verified on NAS |

Raising the nginx cap alone fixes none of rows 3–7.

## Verified fine — do not re-investigate

- **Schema: zero drift.** Live `SHOW CREATE TABLE` matches `db_setup.sql` + all four
  `migration_*.sql` across 10 tables. All target tables empty.
- **Capacity: ample.** MySQL data is on the `blue` pool (1.8 T, 4% used), *not* docker
  root (28 G). ~200 GB xlsx → ~340–440 GB expanded fits with huge headroom.
- **MySQL tuning: live** as of 2026-08-19 (buffer pool 2 G, redo 2 G, `io_capacity` 100,
  `max_connections` 32).

## Open questions — answer before building

1. **Row counts, and how the 200 GB splits across `IMPORT_MODULES`**
   (`cdr` / `ipdr` / `subscriber` / `vehicle` / `bts` / `custom`). Per-row cost differs
   sharply: `cdr` carries 5 secondary indexes + the BTS lookup; `subscriber` is a plain
   upsert. This drives every time estimate below, so none are given until it is answered.
2. **One-shot load or recurring?** A recurring feed justifies more investment in the
   resume/progress machinery than a single historical backfill does.
3. **Where do the source files physically live**, and can they be staged onto the `blue`
   pool? They must not land on the 28 G docker root.

## Design

A standalone CLI loader run **inside the app container**, bypassing nginx and gunicorn
entirely. Reuses `validate_import_rows` and the existing `IMPORT_MODULES` table mappings
so validation semantics stay identical to the UI path.

```
python -m tools.bulk_import --module cdr --path /data/incoming/*.xlsx \
    --batch-size 5000 [--case-reference REF] [--resume] [--dry-run]
```

### 1. Stream the parse
Replace the `list(ws.iter_rows(...))` materialisation with a generator yielding row dicts.
Memory becomes O(batch), not O(file). This is the change that makes multi-GB files
possible at all.

### 2. Batch the writes
`executemany` in `--batch-size` chunks, one `conn.commit()` per chunk. Chunk size is a
tunable, not a constant — 5000 is a starting point to measure, not a conclusion.

### 3. Kill the N+1
Pre-load `bts_tower_records` into an in-memory `{(lac, cell_id): row}` dict once at
startup, replacing the per-row `_bts_lookup2`. The table is small relative to CDR volume
(it is a reference table with a `UNIQUE KEY (lac, cell_id)`), so this is a bounded cost.

### 4. Make it resumable
Extend `import_batches` with `rows_committed`, `source_file`, `file_checksum`, and a
`status='in_progress'` value. Commit the counter in the *same transaction* as each chunk
so it can never drift from reality. `--resume` skips to `rows_committed` for a matching
`file_checksum`.

This needs a migration. Add it as `migration_bulk_import.sql` **and** register it in
`deploy/db-init/00-apply-schema.sh` in order — there is still no migration runner, so
order is manual and load-bearing.

### 5. Import-window-only tuning
Wrap in the loader, revert in a `finally` so a crash cannot leave the box unsafe:

- `SET GLOBAL innodb_flush_log_at_trx_commit = 2` — safe *only* because step 4 makes the
  load resumable; the box has no UPS, so this **must** be reverted to `1` after.
- Drop the 5 secondary indexes on `cdr_records`, rebuild after load. On HDD with
  `innodb_io_capacity=100` this is expected to dominate total runtime; measure before
  assuming.
- Leave `innodb_doublewrite` alone.

### 6. Observability
Log rows/sec and ETA per chunk. Without this there is no way to distinguish "slow" from
"wedged" during a multi-hour run.

## Sequencing

1. Answer the three open questions.
2. Build steps 1–3 and measure real throughput on **one representative file** per module.
3. Only then size the full run and decide whether step 5's index-drop is worth it.
4. Add step 4 (resume) before any run long enough that losing it would hurt.
5. Full load, monitored.

## Watch during the run

- **`sentinel-mysql` RSS against its 3 GiB cap.** Buffer pool is 2 G and fills lazily —
  it was 611 MiB at rest. If it approaches the cap, raise the limit or drop the pool to
  1536M. This is the most likely operational surprise.
- Redo log pressure: 2 G capacity with chunked commits should be fine, but confirm.
- Free space on the `blue` pool as it grows.

## Explicitly out of scope

Not touching the RBAC / `role_required` / admin-seed cluster — deferred to the planned
OAuth2 work. The loader runs as an operator CLI, not through an authenticated route, so
it does not depend on that decision.

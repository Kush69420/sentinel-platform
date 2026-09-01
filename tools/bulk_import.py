"""Standalone bulk data loader — plans/DATA_POPULATION_PLAN.md.

Runs *inside the app container*, bypassing nginx and gunicorn entirely (there is no
bulk ingest path today: the only loader is a 20 MB-capped HTTP admin form). It reuses
`validate_import_rows` and the `IMPORT_MODULES` table mappings from app.py unchanged,
so validation semantics stay identical to the existing UI import path
(`/api/admin/import/execute`) — this module does not fork or reimplement that logic.

Usage:
    python -m tools.bulk_import --module cdr --path '/data/incoming/*.xlsx' \
        --batch-size 5000 [--case-reference REF] [--resume] [--dry-run]

What this implements (see plans/DATA_POPULATION_PLAN.md steps 1, 2 and 4):
  1. Streaming parse    — iter_xlsx_rows() never materialises the sheet; memory is
                           O(batch), not O(file).
  2. Batched writes     — executemany() in --batch-size chunks, one commit per chunk.
  4. Resumability       — progress is recorded in import_batches.rows_committed in the
                           *same transaction* as each chunk's inserts, so a hard kill
                           mid-batch cannot leave the counter out of sync with what was
                           actually committed. --resume skips rows already committed.

Deliberately NOT implemented here — see DATA_POPULATION_PLAN.md's open questions and
CLAUDE.md's scope note for why:
  - Step 3 (the bts_tower_records N+1 kill) — cdr/ipdr rows still do one
    _bts_lookup2() SELECT per row, exactly as /api/admin/import/execute does today.
  - Step 5 (import-window-only tuning: innodb_flush_log_at_trx_commit, index
    drop/rebuild) and any throughput/ETA sizing — gated on the plan's unanswered
    row-count/recurrence/staging questions.
"""
import argparse
import glob
import hashlib
import itertools
import json
import os
import sys
import time


# ─────────────────────────────────────────────
# Step 1: streaming parse
# ─────────────────────────────────────────────
def _rows_from_worksheet(ws):
    """Generator: yields one header-keyed dict per data row.

    Takes anything duck-typing openpyxl's worksheet (`.iter_rows(values_only=True)`
    returning an iterator) so it can be unit-tested without a real workbook. Never
    calls list() on the row iterator — that's the whole point.
    """
    row_iter = ws.iter_rows(values_only=True)
    try:
        header_row = next(row_iter)
    except StopIteration:
        return
    headers = [str(h or "").strip() for h in header_row]
    for row in row_iter:
        yield dict(zip(headers, row))


def iter_xlsx_rows(path):
    """Stream rows out of an .xlsx file at `path` as header-keyed dicts.

    Mirrors app._parse_import_file's xlsx branch (headers from row 1, dict-per-row via
    zip(headers, row)) so output is byte-for-byte comparable to the existing parser —
    see tests/test_bulk_import.py. The difference is that app._parse_import_file does
    `rows = list(ws.iter_rows(values_only=True))` (the whole sheet, in RAM, before
    doing anything else); this function forwards openpyxl's own read-only row iterator
    one row at a time and never wraps it in list(), so memory stays O(1) rows rather
    than O(file). That's the change the plan calls "the one that makes multi-GB files
    possible at all."
    """
    import openpyxl

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        ws = wb.active
        yield from _rows_from_worksheet(ws)
    finally:
        wb.close()


def _chunked(iterable, size):
    """Yield successive lists of up to `size` items from a (possibly huge) iterable.

    Only ever holds one chunk in memory at a time — the source iterable is consumed
    lazily via itertools.islice.
    """
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            return
        yield chunk


# ─────────────────────────────────────────────
# Resumability bookkeeping
# ─────────────────────────────────────────────
def file_fingerprint(path):
    """A cheap stand-in for `import_batches.file_checksum`.

    The plan names this column `file_checksum` without specifying how it's computed.
    Hashing the full bytes of a multi-GB file on every --resume invocation would
    itself take minutes — defeating the point of a quick resume after a crash — so
    this hashes (absolute path, size, mtime_ns) instead of file content. That is
    sufficient to detect "is this the same file as last run" for the resume-matching
    use case, but it is NOT a content-addressed hash: touching the file's mtime
    without changing its bytes changes the fingerprint too. Flagged as an assumption
    in the task report; a real content hash is a one-line swap here if that turns out
    to matter for the actual staging setup (open question #3 in the plan).
    """
    st = os.stat(path)
    basis = f"{os.path.abspath(path)}:{st.st_size}:{st.st_mtime_ns}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────
# Step 2: per-module INSERT statements
#
# Copied verbatim from app.py's import_execute_v2() (not re-derived) so the write
# semantics — including the lack of ON DUPLICATE KEY UPDATE for cdr/ipdr, and the
# pre-existing gap that IMPORT_MODULES declares a "custom" module with no INSERT
# branch here or in import_execute_v2 — match the existing UI import path exactly.
# ─────────────────────────────────────────────
_INSERT_SQL = {
    "subscriber": (
        "INSERT INTO subscriber_records (mobile_number,subscriber_name,father_name,"
        "address,district,state,operator,sim_type,activation_date,status,"
        "alternate_number,email,id_type,id_number,import_batch_id,raw_json) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE subscriber_name=VALUES(subscriber_name),"
        "address=VALUES(address),raw_json=VALUES(raw_json)"
    ),
    "vehicle": (
        "INSERT INTO vehicle_records (registration_number,owner_name,father_name,"
        "address,vehicle_class,manufacturer,model,engine_number,chassis_number,"
        "fuel_type,registration_date,fitness_validity,insurance_validity,district,"
        "import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE owner_name=VALUES(owner_name),address=VALUES(address),"
        "raw_json=VALUES(raw_json)"
    ),
    "bts": (
        "INSERT INTO bts_tower_records (lac,cell_id,operator,tower_id,tower_name,"
        "latitude,longitude,full_address,district,state,technology,azimuth,"
        "import_batch_id,raw_json) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE full_address=VALUES(full_address),"
        "latitude=VALUES(latitude),longitude=VALUES(longitude),"
        "district=VALUES(district),state=VALUES(state),raw_json=VALUES(raw_json)"
    ),
    "cdr": (
        "INSERT INTO cdr_records (case_reference,calling_number,called_number,"
        "start_time,end_time,duration,imei,imsi,lac,cell_id,tower_address,"
        "tower_latitude,tower_longitude,tower_district,import_batch_id,raw_json) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    ),
    "ipdr": (
        "INSERT INTO ipdr_records (case_reference,subscriber_number,source_ip,"
        "destination_ip,timestamp,session_duration,lac,cell_id,tower_address,"
        "tower_coordinates,import_batch_id,raw_json) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    ),
    # "custom" -> custom_records_v2 is intentionally absent: import_execute_v2 has no
    # branch for it either (rows are counted as "imported" but never written). Not
    # fixed here — that would be a behaviour change to the existing import path.
}


def _raw_payload(row):
    """The value import_execute_v2 puts in `raw_json` for one row: `row.get('_raw',
    row)`.

    validate_import_rows() does `row = raw` (not a copy) when called with an empty
    mapping — which the CLI always does; there's no --mapping flag per the plan's
    design — and then sets `row['_raw'] = raw` on that same object, so `row['_raw']`
    ends up being `row` itself. json.dumps() on that is a circular reference
    (confirmed: this test file hit `ValueError: Circular reference detected` before
    this guard existed). import_execute_v2 has the identical `row.get('_raw', row)`
    call and would hit the same crash the moment it's invoked with an empty mapping —
    this isn't a bug introduced here, it's latent in the existing helper, and it's not
    fixed there (see task report / CLAUDE.md scope: don't touch the existing import
    route's behaviour). This just avoids feeding it to json.dumps() from this loader.
    """
    raw = row.get("_raw")
    if raw is row:
        return {k: v for k, v in row.items() if k != "_raw"}
    return raw if raw is not None else row


def _row_params(app_module, module, row, batch_id, case_ref, cur):
    """Build the executemany() param tuple for one validated row.

    Column order matches _INSERT_SQL[module] above exactly (copied from
    import_execute_v2). Returns None for modules with no INSERT statement (see the
    "custom" note above) so the caller can filter those rows out.
    """
    if module == "subscriber":
        return (
            row.get("mobile_number"), row.get("subscriber_name"), row.get("father_name"),
            row.get("address"), row.get("district"), row.get("state"), row.get("operator"),
            row.get("sim_type"), app_module._parse_date_or_none(row.get("activation_date")),
            row.get("status"), row.get("alternate_number"), row.get("email"),
            row.get("id_type"), row.get("id_number"), batch_id,
            json.dumps(_raw_payload(row), default=str),
        )
    if module == "vehicle":
        return (
            row.get("registration_number"), row.get("owner_name"), row.get("father_name"),
            row.get("address"), row.get("vehicle_class"), row.get("manufacturer"),
            row.get("model"), row.get("engine_number"), row.get("chassis_number"),
            row.get("fuel_type"), app_module._parse_date_or_none(row.get("registration_date")),
            app_module._parse_date_or_none(row.get("fitness_validity")),
            app_module._parse_date_or_none(row.get("insurance_validity")),
            row.get("district"), batch_id, json.dumps(_raw_payload(row), default=str),
        )
    if module == "bts":
        return (
            row.get("lac"), row.get("cell_id"), row.get("operator"), row.get("tower_id"),
            row.get("tower_name"), row.get("latitude") or None, row.get("longitude") or None,
            row.get("full_address"), row.get("district"), row.get("state"),
            row.get("technology"), row.get("azimuth") or None, batch_id,
            json.dumps(_raw_payload(row), default=str),
        )
    if module == "cdr":
        b = app_module._bts_lookup2(cur, row.get("lac"), row.get("cell_id"))
        return (
            case_ref, row.get("calling_number"), row.get("called_number"),
            app_module._parse_date_or_none(row.get("start_time")),
            app_module._parse_date_or_none(row.get("end_time")),
            int(row.get("duration") or 0), row.get("imei"), row.get("imsi"),
            row.get("lac"), row.get("cell_id"),
            b.get("full_address") if b else None, b.get("latitude") if b else None,
            b.get("longitude") if b else None, b.get("district") if b else None,
            batch_id, json.dumps(_raw_payload(row), default=str),
        )
    if module == "ipdr":
        b = app_module._bts_lookup2(cur, row.get("lac"), row.get("cell_id"))
        coords = f"{b.get('latitude')},{b.get('longitude')}" if b and b.get("latitude") else None
        return (
            case_ref, row.get("subscriber_number"), row.get("source_ip"),
            row.get("destination_ip"), app_module._parse_date_or_none(row.get("timestamp")),
            int(row.get("session_duration") or 0), row.get("lac"), row.get("cell_id"),
            b.get("full_address") if b else None, coords, batch_id,
            json.dumps(_raw_payload(row), default=str),
        )
    return None


def _process_batch(app_module, cur, module, case_ref, batch_id, raw_rows, dry_run):
    """Validate one batch through the shared validate_import_rows(), then (unless
    dry_run) executemany() it as a single round trip.

    Batch-level abort, not row-level or whole-file-level: if any row in the batch
    fails required-field validation, the *whole batch* is rejected and nothing from it
    is written (matching the spirit of import_execute_v2's whole-file "reject before
    any write" behaviour, at chunk granularity instead of file granularity — see the
    task report for why whole-file validation doesn't compose with streaming/batched
    commits).

    Returns (rows_written, summary_dict) where summary_dict is validate_import_rows's
    own summary for this batch.
    """
    rows, issues, summary = app_module.validate_import_rows(module, raw_rows, {})
    if summary["error_count"] > 0:
        return 0, summary
    if dry_run:
        return len(rows), summary
    sql = _INSERT_SQL.get(module)
    if sql:
        params = [_row_params(app_module, module, row, batch_id, case_ref, cur) for row in rows]
        params = [p for p in params if p is not None]
        if params:
            cur.executemany(sql, params)
    return len(rows), summary


# ─────────────────────────────────────────────
# import_batches bookkeeping (step 4: resumability)
# ─────────────────────────────────────────────
def _find_existing_batch(cur, module, path, checksum):
    cur.execute(
        "SELECT * FROM import_batches WHERE source_type=%s AND source_file=%s "
        "AND file_checksum=%s ORDER BY id DESC LIMIT 1",
        (module, path, checksum),
    )
    return cur.fetchone()


def _create_batch(cur, module, path, checksum):
    cur.execute(
        "INSERT INTO import_batches (source_type, original_filename, total_rows, "
        "imported_by, status, rows_committed, source_file, file_checksum) "
        "VALUES (%s,%s,%s,%s,'in_progress',0,%s,%s)",
        (module, os.path.basename(path), 0, "bulk_import_cli", path, checksum),
    )
    return cur.lastrowid


def import_file(app_module, conn, module, path, batch_size, case_ref, resume, dry_run, log=print):
    """Import one file. Returns a summary dict. Raises on a resume conflict (an
    in-progress batch matches this file but --resume wasn't passed) so the operator
    doesn't silently start a duplicate load.
    """
    # dry-run touches the DB not at all — no cursor, no queries, no connection
    # dependency beyond what the caller already opened.
    cur = conn.cursor(dictionary=True) if not dry_run else None
    checksum = file_fingerprint(path)

    batch_id = None
    rows_to_skip = 0
    if not dry_run:
        existing = _find_existing_batch(cur, module, path, checksum)
        if existing and existing.get("status") == "in_progress":
            if not resume:
                raise RuntimeError(
                    f"{path}: an in-progress import batch (id={existing['id']}, "
                    f"rows_committed={existing.get('rows_committed') or 0}) already "
                    "matches this file+size+mtime. Pass --resume to continue it."
                )
            batch_id = existing["id"]
            rows_to_skip = existing.get("rows_committed") or 0
        else:
            batch_id = _create_batch(cur, module, path, checksum)
            conn.commit()

    total_seen = rows_to_skip
    total_committed = rows_to_skip
    total_error_rows = 0
    total_dup_rows = 0
    batches_rejected = 0

    row_source = iter_xlsx_rows(path)
    if rows_to_skip:
        row_source = itertools.islice(row_source, rows_to_skip, None)

    start = time.monotonic()
    for chunk in _chunked(row_source, batch_size):
        total_seen += len(chunk)
        written, summary = _process_batch(app_module, cur, module, case_ref, batch_id, chunk, dry_run)
        total_error_rows += summary["error_count"]
        total_dup_rows += summary["duplicate_count"]
        if summary["error_count"] > 0:
            batches_rejected += 1
            log(f"{path}: batch rejected ({summary['error_count']} invalid rows in this "
                f"chunk) — no rows from this chunk were written")
            continue
        total_committed += written
        if not dry_run:
            cur.execute(
                "UPDATE import_batches SET rows_committed=%s WHERE id=%s",
                (total_committed, batch_id),
            )
            conn.commit()
        elapsed = time.monotonic() - start
        rate = total_committed / elapsed if elapsed > 0 else 0.0
        log(f"{path}: {total_committed} rows committed ({rate:.0f} rows/sec)")

    if not dry_run:
        status = "failed" if (batches_rejected and total_committed == rows_to_skip) else "imported"
        cur.execute(
            "UPDATE import_batches SET status=%s, total_rows=%s WHERE id=%s",
            (status, total_seen, batch_id),
        )
        conn.commit()

    return {
        "path": path,
        "batch_id": batch_id,
        "rows_seen": total_seen,
        "rows_committed": total_committed,
        "rows_skipped_via_resume": rows_to_skip,
        "error_rows": total_error_rows,
        "duplicate_rows": total_dup_rows,
        "batches_rejected": batches_rejected,
        "dry_run": dry_run,
    }


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="python -m tools.bulk_import",
        description="Bulk-load xlsx files into a SENTINEL data table, bypassing the "
                     "20MB HTTP import form. See plans/DATA_POPULATION_PLAN.md.",
    )
    parser.add_argument("--module", required=True, help="one of IMPORT_MODULES (app.py)")
    parser.add_argument("--path", required=True, help="a file path or glob, e.g. /data/incoming/*.xlsx")
    parser.add_argument("--batch-size", type=int, default=5000,
                         help="rows per executemany()/commit chunk (default 5000 — a "
                              "starting point to measure, not a tuned value)")
    parser.add_argument("--case-reference", default=None)
    parser.add_argument("--resume", action="store_true",
                         help="continue a matching in-progress batch instead of erroring out")
    parser.add_argument("--dry-run", action="store_true",
                         help="validate and report; write nothing")
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    import app as app_module  # deferred: importing app.py triggers its fail-fast
                               # secrets check and DB config load, which only makes
                               # sense once real CLI args have already parsed cleanly.

    if args.module not in app_module.IMPORT_MODULES:
        parser.error(f"--module must be one of {sorted(app_module.IMPORT_MODULES)}")

    paths = sorted(glob.glob(args.path))
    if not paths:
        parser.error(f"no files matched --path {args.path!r}")

    conn = app_module.get_db()
    results = []
    try:
        for path in paths:
            print(f"=== {path} ===", file=sys.stderr)
            result = import_file(
                app_module, conn, args.module, path, args.batch_size,
                args.case_reference, args.resume, args.dry_run,
            )
            results.append(result)
            print(json.dumps(result, indent=2))
    finally:
        conn.close()
    return results


if __name__ == "__main__":
    main()

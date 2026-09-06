#!/bin/bash
# Applies the SENTINEL schema to a FRESH database, in dependency order.
#
# MySQL's entrypoint runs everything in /docker-entrypoint-initdb.d exactly once, on
# first initialisation of an empty datadir — which matches CLAUDE.md's requirement to
# "apply the schema in dependency order, from empty".
#
# This is a script rather than four mounted .sql files because the entrypoint sorts
# by filename, and the required order is NOT alphabetical. Relying on that coincidence
# would break silently the moment a file is renamed.
#
# There is still no migration runner and no version tracking (a `schema_migrations`
# table is a Day-4 item) — this only handles the from-empty case.
set -euo pipefail

SQL_DIR=/sentinel-sql
DB_NAME="${MYSQL_DATABASE:-sentinel_db}"

# Pass the database on the command line rather than relying on the .sql file to select
# it. The canonical four each carry their own CREATE DATABASE/USE, but a file that does
# not (migration_coming_soon.sql) otherwise dies with "ERROR 1046: No database selected"
# — and because the entrypoint only runs this once, on an empty datadir, that failure is
# easy to miss and annoying to recover from. -D is harmless for files that USE anyway.
run() {
    echo "==> applying $1"
    mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" -D "${DB_NAME}" < "${SQL_DIR}/$1"
}

# Order per CLAUDE.md. Each file is idempotent; the order is not optional.
run db_setup.sql
run migration_admin_customization.sql
run migration_fix_import_errors.sql
run migration_selfserve_auth.sql

# Neutralizes the old seeded admin/admin123 row IF this datadir was ever
# initialised by an older db_setup.sql that still inserted it. On a truly
# fresh datadir (the case this script exists for) db_setup.sql above no
# longer seeds anything, so this matches zero rows and is a harmless no-op —
# it stays in the run list anyway so a rebuilt image is safe to run against
# a datadir that predates this fix. tools/bootstrap_admin.py is what actually
# creates the first admin; run it after this script finishes.
run migration_remove_default_admin.sql

# Adds admin_users.google_email — the allow-list column backing "Sign in with
# Google" on /admin. Harmless on a deployment that has not configured Google
# sign-in: the column simply stays NULL everywhere and password login is used.
run migration_google_admin_oauth.sql

# Not part of CLAUDE.md's canonical four — this one is data, not schema. It marks every
# catalog service except mobile_lookup as "upcoming" so the dashboard shows a COMING
# SOON badge rather than letting users click into a dead tool, which matches the
# documented Day-1 go-live scope. To bring a module live later:
#   UPDATE services SET status='enabled' WHERE code='<code>';
run migration_coming_soon.sql

# Must run AFTER migration_coming_soon.sql, not before: that file
# unconditionally marks every catalog service except mobile_lookup as
# "upcoming", so if this ran first, migration_coming_soon.sql would
# immediately re-mark email_lookup upcoming again, silently undoing the
# catalog flip below. Adds the email_gaia_cache/serpapi_usage_quota tables
# and flips services.status='enabled' for code='email_lookup'.
run migration_email_lookup.sql

echo "==> schema applied"

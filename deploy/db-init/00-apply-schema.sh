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

run() {
    echo "==> applying $1"
    mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" < "${SQL_DIR}/$1"
}

# Order per CLAUDE.md. Each file is idempotent; the order is not optional.
run db_setup.sql
run migration_admin_customization.sql
run migration_fix_import_errors.sql
run migration_selfserve_auth.sql

# Not part of CLAUDE.md's canonical four — this one is data, not schema. It marks every
# catalog service except mobile_lookup as "upcoming" so the dashboard shows a COMING
# SOON badge rather than letting users click into a dead tool, which matches the
# documented Day-1 go-live scope. To bring a module live later:
#   UPDATE services SET status='enabled' WHERE code='<code>';
run migration_coming_soon.sql

echo "==> schema applied"

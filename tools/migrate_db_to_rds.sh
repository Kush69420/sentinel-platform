#!/usr/bin/env bash
# Dumps the live sentinel_db database from the NAS's sentinel-mysql container
# and restores it into an AWS RDS MySQL instance, for the NAS -> AWS
# migration. Uses `docker` on both ends (the NAS's own mysqldump inside its
# container, and a throwaway `mysql:8.4` container locally) so neither box
# needs a native mysql client installed.
#
# No credential is ever hardcoded here or placed on a command line that a
# `ps aux` on the NAS could see: the NAS's MySQL root password is piped in
# over the SSH session's stdin and read inside the container by `sh -c
# 'read -r P; ...'`, never passed as a `docker exec` argument.
#
# Required env vars (prompted interactively if left unset):
#   NAS_SSH_HOST             e.g. root@172.16.141.62
#   NAS_MYSQL_CONTAINER      default: sentinel-mysql
#   NAS_MYSQL_ROOT_PASSWORD  root password for the NAS's MySQL container
#   RDS_HOST                 RDS endpoint, e.g. sentinel.xxxxx.<region>.rds.amazonaws.com
#   RDS_PORT                 default: 3306
#   RDS_USER                 RDS master/admin user with CREATE privileges
#   RDS_PASSWORD             that user's password
#
# The dump uses `--databases sentinel_db`, so it carries its own
# `CREATE DATABASE IF NOT EXISTS` — no `RDS_DB_NAME` needed, and it will not
# silently overwrite an existing schema on the target (no --add-drop-database
# / --add-drop-table): if sentinel_db already has tables on the RDS side,
# this will fail loudly on the first CREATE TABLE conflict rather than
# clobbering anything.
#
# Usage:
#   NAS_SSH_HOST=root@172.16.141.62 RDS_HOST=... RDS_USER=... \
#     ./tools/migrate_db_to_rds.sh

set -euo pipefail

NAS_SSH_HOST="${NAS_SSH_HOST:?set NAS_SSH_HOST, e.g. root@172.16.141.62}"
NAS_MYSQL_CONTAINER="${NAS_MYSQL_CONTAINER:-sentinel-mysql}"
RDS_HOST="${RDS_HOST:?set RDS_HOST to the RDS endpoint}"
RDS_PORT="${RDS_PORT:-3306}"
RDS_USER="${RDS_USER:?set RDS_USER}"

if [ -z "${NAS_MYSQL_ROOT_PASSWORD:-}" ]; then
  read -rsp "NAS MySQL root password: " NAS_MYSQL_ROOT_PASSWORD
  echo
fi
if [ -z "${RDS_PASSWORD:-}" ]; then
  read -rsp "RDS password for user '$RDS_USER': " RDS_PASSWORD
  echo
fi

WORKDIR="$(mktemp -d)"
DUMP_LOCAL="$WORKDIR/sentinel_db_dump.sql"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> Dumping sentinel_db from NAS ($NAS_SSH_HOST, container $NAS_MYSQL_CONTAINER)..."
printf '%s\n' "$NAS_MYSQL_ROOT_PASSWORD" | ssh "$NAS_SSH_HOST" \
  "docker exec -i '$NAS_MYSQL_CONTAINER' sh -c 'read -r P; MYSQL_PWD=\"\$P\" mysqldump -u root --databases sentinel_db --single-transaction --routines --triggers --events'" \
  > "$DUMP_LOCAL"

if [ ! -s "$DUMP_LOCAL" ]; then
  echo "!! Dump came back empty — aborting before touching RDS." >&2
  exit 1
fi
SIZE=$(du -h "$DUMP_LOCAL" | cut -f1)
echo "==> Dump complete: $SIZE"

echo "==> Restoring into RDS ($RDS_HOST:$RDS_PORT)..."
docker run --rm -i \
  -e MYSQL_PWD="$RDS_PASSWORD" \
  mysql:8.4 \
  mysql --host="$RDS_HOST" --port="$RDS_PORT" --user="$RDS_USER" --ssl-mode=REQUIRED \
  < "$DUMP_LOCAL"

echo "==> Done. sentinel_db restored to RDS at $RDS_HOST."

#!/bin/bash
# Creates and permissions the bind-mount directories for the SENTINEL stack.
# Idempotent — safe to re-run. Must run as root on the NAS.
#
# Docker will happily create a missing bind-mount source as root-owned, which then
# leaves the non-root app container unable to write uploads. This script gets the
# ownership right up front instead of debugging a permission error later.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (bind-mount dirs live outside your homedir)" >&2
    exit 1
fi

cd "$(dirname "$0")"
if [[ ! -f .env ]]; then
    echo "deploy/.env not found — copy env.compose.example to .env and fill it in first" >&2
    exit 1
fi
set -a; . ./.env; set +a

# UIDs are fixed, not looked up: 999 is the mysql user inside mysql:8.4, and 10001 is
# the sentinel user created in the Dockerfile. Both are pinned there for this reason.
MYSQL_UID=999
APP_UID=10001

mkdir -p "$SENTINEL_MYSQL_DIR" "$SENTINEL_UPLOADS_DIR" "$SENTINEL_BACKUPS_DIR"

chown "$MYSQL_UID:$MYSQL_UID" "$SENTINEL_MYSQL_DIR"
chmod 700 "$SENTINEL_MYSQL_DIR"

chown "$APP_UID:$APP_UID" "$SENTINEL_UPLOADS_DIR"
chmod 700 "$SENTINEL_UPLOADS_DIR"

# Backups contain a full dump of the database — same sensitivity as the datadir.
chown root:root "$SENTINEL_BACKUPS_DIR"
chmod 700 "$SENTINEL_BACKUPS_DIR"

# Secrets files, in case they were created with a lax umask.
[[ -f .env ]]     && chmod 600 .env
[[ -f app.env ]]  && chmod 600 app.env

echo "prepared:"
printf '  %-10s %s\n' mysql "$SENTINEL_MYSQL_DIR" uploads "$SENTINEL_UPLOADS_DIR" backups "$SENTINEL_BACKUPS_DIR"

# The datadir lands on `blue` (ext4) by design. Warn loudly if it has been pointed at
# the btrfs pool without disabling copy-on-write, which fragments InnoDB badly.
if [[ "$(stat -f -c %T "$SENTINEL_MYSQL_DIR")" == "btrfs" ]]; then
    echo
    echo "WARNING: the MySQL datadir is on btrfs. If this is deliberate, run"
    echo "         'chattr +C \"$SENTINEL_MYSQL_DIR\"' NOW, while it is still empty —"
    echo "         it has no effect on files that already exist."
fi

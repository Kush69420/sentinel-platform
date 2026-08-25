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

# 999 is fixed: it's the mysql user inside mysql:8.4, pinned there by that image.
# APP_UID/APP_GID are NOT hardcoded — they follow SENTINEL_APP_UID/SENTINEL_APP_GID
# from .env (docker-compose.yml passes the same two vars as `user:` on the app
# service), because the right value depends on what SENTINEL_UPLOADS_DIR actually is:
#   - a plain directory: 10001:10001 (the `sentinel` user baked into the Dockerfile,
#     matching the image's own `chown -R sentinel:sentinel /app/uploads`) is correct,
#     and the chown below is durable.
#   - an OMV shared folder (true on this NAS — reed/sentinel/uploads): OMV shared
#     folders carry a POSIX ACL whose mask strips rwx from every named-user/group
#     entry except the folder's actual owner (confirmed via getfacl: mask::-w- guts
#     `user:10001:rwx` down to `-w-`, so `chown 10001:10001` alone leaves the app
#     unable to open() the directory even though it "owns" it). The chown/chmod below
#     are then only a best-effort convenience for the fresh-directory case and do NOT
#     survive OMV re-applying the shared folder's ACL from its web UI, which resets
#     ownership back to whatever the share is configured for (kush:users on this NAS),
#     undoing this script's chmod along with it. The actual fix in that case is
#     SENTINEL_APP_UID/SENTINEL_APP_GID matching the shared folder's real owner (`stat
#     -c '%u %g' "$SENTINEL_UPLOADS_DIR"`) so the app container's uid lands on the
#     ACL's owner entry instead of a named entry — see DOCKER_DEPLOY.md and the `user:`
#     comment in docker-compose.yml.
MYSQL_UID=999
APP_UID="${SENTINEL_APP_UID:-10001}"
APP_GID="${SENTINEL_APP_GID:-10001}"

mkdir -p "$SENTINEL_MYSQL_DIR" "$SENTINEL_UPLOADS_DIR" "$SENTINEL_BACKUPS_DIR"

chown "$MYSQL_UID:$MYSQL_UID" "$SENTINEL_MYSQL_DIR"
chmod 700 "$SENTINEL_MYSQL_DIR"

chown "$APP_UID:$APP_GID" "$SENTINEL_UPLOADS_DIR"
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

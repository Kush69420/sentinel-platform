#!/bin/bash
# Nightly backup: mysqldump + encrypted uploads, onto the btrfs RAID1 pool.
#
# This is where the redundancy for this deployment actually lives. The datadir sits on
# a single non-mirrored ext4 disk (chosen for InnoDB write performance), so a disk
# failure there is recovered from these dumps — which is acceptable precisely because
# the bulk lookup data is reconstructible from the source xlsx, while the gov-ID
# uploads and the accounts/audit tables are not.
set -euo pipefail

cd "$(dirname "$0")"
set -a; . ./.env; set +a

STAMP=$(date +%Y%m%d-%H%M%S)
DEST="$SENTINEL_BACKUPS_DIR"
KEEP_DAYS=${SENTINEL_BACKUP_KEEP_DAYS:-14}

mkdir -p "$DEST"

# --single-transaction keeps this non-blocking against InnoDB; without it the dump
# would lock the whole database for however long ~400 GB takes to read off a HDD.
docker exec sentinel-mysql \
    mysqldump --single-transaction --quick --routines --events \
    -u root -p"$MYSQL_ROOT_PASSWORD" sentinel_db \
    | gzip -1 > "$DEST/sentinel_db-$STAMP.sql.gz"

# Uploads are already Fernet-encrypted at rest by the app, so a plain copy is fine —
# but ENCRYPTION_KEY is NOT in here, and without it these files are unrecoverable.
# Keep that key backed up separately and off this box.
tar -C "$SENTINEL_UPLOADS_DIR" -czf "$DEST/uploads-$STAMP.tar.gz" .

find "$DEST" -name 'sentinel_db-*.sql.gz' -mtime "+$KEEP_DAYS" -delete
find "$DEST" -name 'uploads-*.tar.gz'     -mtime "+$KEEP_DAYS" -delete

echo "backup complete: $DEST/sentinel_db-$STAMP.sql.gz"
ls -lh "$DEST" | tail -5

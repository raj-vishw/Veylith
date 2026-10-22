#!/usr/bin/env bash
# Veylith backup: a PostgreSQL custom-format dump plus an archive of the private evidence/report storage.
#
#   ./backup.sh                     # uses docker-compose.prod.yml next to this script's parent directory
#   COMPOSE_FILE=... BACKUP_DIR=... KEEP=14 ./backup.sh
#
# Run it from cron (see docs/operations.md). A backup is only proven once verify-restore.sh has restored it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$HERE/../docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$HERE/../.env}"
BACKUP_DIR="${BACKUP_DIR:-$HERE/../backups}"
KEEP="${KEEP:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

mkdir -p "$BACKUP_DIR"
umask 077

echo "[backup] dumping database"
compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner' > "$BACKUP_DIR/db-$STAMP.dump"

echo "[backup] archiving evidence and report storage"
compose exec -T worker tar -C /data -czf - storage > "$BACKUP_DIR/storage-$STAMP.tar.gz"

# Integrity record so a truncated or altered backup is noticed before it is needed.
( cd "$BACKUP_DIR" && sha256sum "db-$STAMP.dump" "storage-$STAMP.tar.gz" > "SHA256SUMS-$STAMP" )

# A dump that is empty or unreadable is a failed backup, not a quiet success.
test -s "$BACKUP_DIR/db-$STAMP.dump" || { echo "[backup] ERROR: empty database dump" >&2; exit 1; }
compose exec -T db pg_restore --list < "$BACKUP_DIR/db-$STAMP.dump" > /dev/null || { echo "[backup] ERROR: dump is not readable" >&2; exit 1; }

echo "[backup] pruning to the newest $KEEP backups"
for prefix in db storage SHA256SUMS; do
  ls -1t "$BACKUP_DIR"/"$prefix"-* 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f --
done

echo "[backup] done: $BACKUP_DIR/db-$STAMP.dump ($(du -h "$BACKUP_DIR/db-$STAMP.dump" | cut -f1))"

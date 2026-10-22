#!/usr/bin/env bash
# Disaster recovery: replace the live database and storage with a backup.
# DESTRUCTIVE. Stops the application, drops the live database, restores, then runs migrations.
#
#   ./restore.sh backups/db-20261022T031500Z.dump backups/storage-20261022T031500Z.tar.gz
set -euo pipefail

if [ $# -ne 2 ]; then echo "usage: $0 <db.dump> <storage.tar.gz>" >&2; exit 2; fi
DUMP="$1"; STORAGE="$2"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$HERE/../docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$HERE/../.env}"
compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

( cd "$(dirname "$DUMP")" && sha256sum --check --ignore-missing "SHA256SUMS-$(basename "$DUMP" | sed 's/^db-//; s/\.dump$//')" ) \
  || { echo "checksum verification failed; refusing to restore" >&2; exit 1; }

read -r -p "This DELETES the current Veylith data and restores $DUMP. Type RESTORE to continue: " answer
[ "$answer" = "RESTORE" ] || { echo "aborted"; exit 1; }

echo "[restore] stopping application services"
for svc in web api worker beat reporter caddy; do compose stop "$svc" 2>/dev/null || true; done  # one by one: a missing service must not stop the rest

echo "[restore] recreating the database"
compose exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS \"$POSTGRES_DB\" WITH (FORCE)" -c "CREATE DATABASE \"$POSTGRES_DB\""'
compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --exit-on-error' < "$DUMP"
compose exec -T db sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "GRANT CONNECT ON DATABASE \"$POSTGRES_DB\" TO veylith_app"'

echo "[restore] restoring evidence and report storage"
compose run --rm --no-deps -T worker sh -c 'rm -rf /data/storage && tar -C /data -xzf -' < "$STORAGE"

echo "[restore] applying migrations and starting services"
compose run --rm migrate
compose up -d
echo "[restore] done. Run ops/verify-restore.sh and spot-check the application."

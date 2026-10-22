#!/usr/bin/env bash
# Restores a backup into a throw-away database and checks that the data is consistent.
# A backup that has never been restored is a hope, not a backup: run this on a schedule.
#
#   ./verify-restore.sh [path/to/db-YYYYMMDDTHHMMSSZ.dump]   # defaults to the newest dump
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$HERE/../docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$HERE/../.env}"
BACKUP_DIR="${BACKUP_DIR:-$HERE/../backups}"
DUMP="${1:-$(ls -1t "$BACKUP_DIR"/db-*.dump | head -n1)}"
CHECK_DB="veylith_restore_check"

compose() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }
psql_admin() { compose exec -T db sh -c "psql -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d postgres $*"; }
psql_check() { compose exec -T db sh -c "psql -v ON_ERROR_STOP=1 -At -U \"\$POSTGRES_USER\" -d $CHECK_DB -c \"$1\""; }

echo "[verify] restoring $DUMP into $CHECK_DB"
psql_admin "-c 'DROP DATABASE IF EXISTS $CHECK_DB'" > /dev/null
psql_admin "-c 'CREATE DATABASE $CHECK_DB'" > /dev/null
compose exec -T db sh -c "pg_restore -U \"\$POSTGRES_USER\" -d $CHECK_DB --no-owner --exit-on-error" < "$DUMP"

fail=0
check() {  # check <description> <sql returning a single number> <expected: "zero" | "positive">
  local value; value="$(psql_check "$2")"
  if { [ "$3" = zero ] && [ "$value" = 0 ]; } || { [ "$3" = positive ] && [ "$value" -gt 0 ]; }; then
    echo "  ok   $1 ($value)"
  else
    echo "  FAIL $1 (got $value, expected $3)"; fail=1
  fi
}

echo "[verify] consistency checks"
check "migrations present"                     "select count(*) from alembic_version" positive
check "organizations restored"                 "select count(*) from organizations" positive
check "audit events restored"                  "select count(*) from audit_events" positive
check "cases without an organization"          "select count(*) from cases c left join organizations o on o.id = c.organization_id where o.id is null" zero
check "assessments without an advisory"        "select count(*) from impact_assessments a left join advisories d on d.id = a.advisory_id where d.id is null" zero
check "assessments without a product"          "select count(*) from impact_assessments a left join products p on p.id = a.product_id where p.id is null" zero
check "relationships crossing organizations"   "select count(*) from relationships r join clients c on r.source_type = 'client' and c.id = r.source_id where c.organization_id <> r.organization_id" zero
check "case events without a case"             "select count(*) from case_events e left join cases c on c.id = e.case_id where c.id is null" zero
check "evidence without a case"                "select count(*) from evidence e left join cases c on c.id = e.case_id where c.id is null" zero
check "reports without a case"                 "select count(*) from reports r left join cases c on c.id = r.case_id where c.id is null" zero
check "ready reports missing a storage key"    "select count(*) from reports where status = 'ready' and storage_key = ''" zero
check "row-level security still enabled"       "select count(*) from pg_class where relname = 'cases' and relrowsecurity" positive

psql_admin "-c 'DROP DATABASE $CHECK_DB'" > /dev/null
if [ "$fail" -ne 0 ]; then echo "[verify] FAILED"; exit 1; fi
echo "[verify] backup restored and consistent"

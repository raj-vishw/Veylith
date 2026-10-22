#!/bin/sh
# Creates the restricted runtime role. It is not a superuser and cannot bypass row-level security.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE veylith_app LOGIN PASSWORD '${APP_DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO veylith_app;
SQL

#!/bin/bash
# Runs once, on first initialisation of an empty data volume.
# Creates the least-privilege runtime role and Keycloak's own database.
# Passwords are passed as psql variables (never interpolated by the shell into SQL).
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_pw="$APP_DB_PASSWORD" -v kc_pw="$KEYCLOAK_DB_PASSWORD" -v dbname="$POSTGRES_DB" <<'SQL'
-- Runtime role: no superuser, no BYPASSRLS, not the table owner => row-level security applies to it.
CREATE ROLE eai_app LOGIN PASSWORD :'app_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO eai_app;

-- Keycloak keeps its own database and credentials, separate from business data.
CREATE ROLE keycloak LOGIN PASSWORD :'kc_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE DATABASE keycloak OWNER keycloak;
SQL

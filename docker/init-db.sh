#!/bin/sh
# docker/init-db.sh
# Creates cluster-level roles and all fixture databases needed by local test suites.
# Runs once at first container startup as the postgres superuser.
# Never touches production credentials or real data.

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  -- Cluster-level roles expected by schema.sql, workbench SQL, and evidence SQL.
  -- Created here so all fixture databases share them without per-DB bootstrap.
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
      CREATE ROLE anon NOLOGIN NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
      CREATE ROLE authenticated NOLOGIN NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN
      CREATE ROLE service_role NOLOGIN BYPASSRLS;
    END IF;
  END
  \$\$;

  -- Fixture databases (prefix-named per each test suite's safety guard)
  CREATE DATABASE prawn_evidence_fixture_pg;
  CREATE DATABASE prawn_evidence_fixture_rows;
  CREATE DATABASE prawn_evidence_fixture_http;
  CREATE DATABASE notification_outbox_test;
  CREATE DATABASE workbench_search_fixture_local;
  CREATE DATABASE workbench_capacity_fixture_local;
  CREATE DATABASE workbench_review_fixture_local;
EOSQL

echo "Fixture databases and roles created."

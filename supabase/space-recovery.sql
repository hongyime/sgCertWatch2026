-- Space recovery for the paused SGCertWatch database.
--
-- Goal: reduce database bytes toward the 500 MB Free allowance without
-- deleting or altering any row in findings, finding_sources, audit or
-- source-run tables. Applies only lossless storage reclaims:
--
--   1. Drop two write-only indexes on public.finding_sources that no
--      application query reads. The scanner is the sole writer and never
--      filters finding_sources by "source" or "observed_at"; only the
--      composite primary key (finding_id, source, source_ref) is used for
--      upserts and cascades.
--        - finding_sources_source_idx        (btree on source)
--        - finding_sources_observed_at_idx   (btree on observed_at desc)
--      With ~605k sightings, each btree consumes tens of MB.
--
--   2. VACUUM FULL findings, finding_sources, ct_source_runs to reclaim
--      dead-tuple bloat accumulated by earlier scanner upserts (source /
--      enrichment / details jsonb columns are updated in place).
--
--   3. REINDEX the retained indexes on findings and finding_sources so the
--      index heap footprint tracks the compacted table.
--
-- Rollback: space-recovery-rollback.sql recreates the two dropped indexes
-- with the exact original definitions.
--
-- Safety notes:
--   * The index drops run inside a single transaction with short lock and
--     statement timeouts, and abort the transaction if the on-disk
--     definition differs from the reviewed one or if any dependency exists.
--   * VACUUM FULL cannot run inside a transaction; it takes an ACCESS
--     EXCLUSIVE lock on each table. Collection is paused (2026-09-14 owner
--     directive), so no writer will contend.
--   * No table, column, constraint, RLS policy, grant, sequence, function,
--     view or record is modified.
--
-- Apply order:
--   psql "$SUPABASE_DB_URL" -f supabase/space-recovery.sql
--
-- Measure before/after with:
--   select pg_size_pretty(pg_database_size(current_database())) as db_size;
--   select pg_size_pretty(pg_total_relation_size('public.findings'));
--   select pg_size_pretty(pg_total_relation_size('public.finding_sources'));

-- Section 1: guarded, transactional index drops.

begin;
set local lock_timeout = '2s';
set local statement_timeout = '15s';

do $$
declare
  candidate oid := to_regclass('public.finding_sources_source_idx');
begin
  if candidate is null then
    raise notice 'finding_sources_source_idx already absent; skipping';
  else
    if pg_get_indexdef(candidate) is distinct from
        'CREATE INDEX finding_sources_source_idx ON public.finding_sources USING btree (source)'
      or not exists (
        select 1 from pg_index where indexrelid = candidate
          and indrelid = 'public.finding_sources'::regclass
          and indisvalid and not indisprimary and not indisunique and not indisreplident
      )
      or exists (select 1 from pg_constraint where conindid = candidate)
      or exists (select 1 from pg_depend where refclassid = 'pg_class'::regclass and refobjid = candidate)
    then
      raise exception 'finding_sources_source_idx differs from the reviewed definition; no change made';
    end if;
    drop index public.finding_sources_source_idx restrict;
  end if;
end;
$$;

do $$
declare
  candidate oid := to_regclass('public.finding_sources_observed_at_idx');
begin
  if candidate is null then
    raise notice 'finding_sources_observed_at_idx already absent; skipping';
  else
    if pg_get_indexdef(candidate) is distinct from
        'CREATE INDEX finding_sources_observed_at_idx ON public.finding_sources USING btree (observed_at DESC)'
      or not exists (
        select 1 from pg_index where indexrelid = candidate
          and indrelid = 'public.finding_sources'::regclass
          and indisvalid and not indisprimary and not indisunique and not indisreplident
      )
      or exists (select 1 from pg_constraint where conindid = candidate)
      or exists (select 1 from pg_depend where refclassid = 'pg_class'::regclass and refobjid = candidate)
    then
      raise exception 'finding_sources_observed_at_idx differs from the reviewed definition; no change made';
    end if;
    drop index public.finding_sources_observed_at_idx restrict;
  end if;
end;
$$;

commit;

-- Section 2: reclaim bloat. VACUUM FULL cannot be transactional and locks
-- the table exclusively for the duration. Order smallest -> largest so
-- disk free space accumulates for the largest rewrite last.

vacuum (full, analyze) public.ct_source_runs;
vacuum (full, analyze) public.findings;
vacuum (full, analyze) public.finding_sources;

-- Section 3: rebuild retained indexes so on-disk pages are compact.
-- REINDEX CONCURRENTLY would avoid the ACCESS EXCLUSIVE lock, but with
-- collection paused a plain REINDEX is faster and simpler. The primary key
-- and public-read indexes are rebuilt in place; no query surface changes.

reindex table public.findings;
reindex table public.finding_sources;

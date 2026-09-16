-- Rollback for supabase/space-recovery.sql.
--
-- Restores the two write-only indexes dropped by the space-recovery
-- migration to their exact original definitions from supabase/schema.sql.
-- VACUUM FULL and REINDEX are one-way physical operations; they do not
-- need rollback because they preserve every row and every index
-- definition, only reclaiming free space. Reversing them (adding bloat
-- back) is neither possible nor desirable.

begin;
set local lock_timeout = '2s';
set local statement_timeout = '30s';

create index if not exists finding_sources_source_idx
  on public.finding_sources (source);

create index if not exists finding_sources_observed_at_idx
  on public.finding_sources (observed_at desc);

commit;

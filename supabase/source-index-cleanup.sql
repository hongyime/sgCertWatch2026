-- The source primary key also supports equality lookups by finding_id.
-- Remove only its reviewed overlapping index; preserve every sighting and field.
begin;
set local lock_timeout = '1s';
set local statement_timeout = '5s';

do $$
declare
  candidate oid := to_regclass('public.finding_sources_finding_id_idx');
  replacement oid;
begin
  if candidate is null then return; end if;
  -- Freeze table/index definitions while checking the replacement and dropping.
  lock table public.finding_sources in access exclusive mode;
  candidate := to_regclass('public.finding_sources_finding_id_idx');
  if candidate is null then return; end if;
  replacement := to_regclass('public.finding_sources_pkey');
  if pg_get_indexdef(candidate) is distinct from
      'CREATE INDEX finding_sources_finding_id_idx ON public.finding_sources USING btree (finding_id)'
    or not exists (
      select 1 from pg_index where indexrelid = candidate
        and indrelid = 'public.finding_sources'::regclass
        and indisvalid and indisready and not indisprimary and not indisunique and not indisreplident
    )
    or exists (select 1 from pg_constraint where conindid = candidate)
    or exists (select 1 from pg_depend where refclassid = 'pg_class'::regclass and refobjid = candidate)
  then
    raise exception 'Source lookup index differs from the reviewed definition; no change made';
  end if;
  if pg_get_indexdef(replacement) is distinct from
      'CREATE UNIQUE INDEX finding_sources_pkey ON public.finding_sources USING btree (finding_id, source, source_ref)'
    or not exists (
      select 1 from pg_index where indexrelid = replacement
        and indrelid = 'public.finding_sources'::regclass
        and indisvalid and indisready and indisprimary and indisunique
    )
    or not exists (
      select 1 from pg_constraint where conindid = replacement
        and conrelid = 'public.finding_sources'::regclass and contype = 'p'
    )
  then
    raise exception 'Source primary key cannot replace this lookup index; no change made';
  end if;
  drop index public.finding_sources_finding_id_idx restrict;
end;
$$;
commit;

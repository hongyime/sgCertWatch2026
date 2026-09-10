-- Remove only the reviewed, unused certificate-identity lookup index.
-- This changes no table data, constraints, permissions or retention policy.
-- A busy database aborts this transaction instead of waiting indefinitely.
begin;
set local lock_timeout = '1s';
set local statement_timeout = '5s';

do $$
declare
  candidate oid := to_regclass('public.findings_cert_identity_idx');
begin
  if candidate is null then
    return;
  end if;
  if pg_get_indexdef(candidate) is distinct from
      'CREATE INDEX findings_cert_identity_idx ON public.findings USING btree (cert_issuer_dn_sha256, cert_serial)'
    or not exists (
      select 1 from pg_index where indexrelid = candidate
        and indrelid = 'public.findings'::regclass
        and indisvalid and not indisprimary and not indisunique and not indisreplident
    )
    or exists (select 1 from pg_constraint where conindid = candidate)
    or exists (select 1 from pg_depend where refclassid = 'pg_class'::regclass and refobjid = candidate)
  then
    raise exception 'Certificate identity index differs from the reviewed definition; no change made';
  end if;
  -- RESTRICT is deliberate: never remove dependent database objects.
  drop index public.findings_cert_identity_idx restrict;
end;
$$;
commit;

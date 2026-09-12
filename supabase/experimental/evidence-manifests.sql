-- EXPERIMENTAL: test manually in an isolated database only. This is not a
-- production migration or a complete capacity solution. Existing row bodies
-- remain in public.findings until all reader/writer contracts are migrated.
begin;
set local lock_timeout = '2s';
set local statement_timeout = '15s';

create function public.evidence_pointer_valid(pointer jsonb)
returns boolean language sql immutable set search_path = ''
as $$
  select coalesce(
    jsonb_typeof(pointer) = 'object'
    and jsonb_typeof(pointer->'object') = 'string'
    and pointer->>'object' ~ '^[a-f0-9]{64}$'
    and jsonb_typeof(pointer->'offset') = 'number'
    and jsonb_typeof(pointer->'length') = 'number'
    and (pointer->>'offset')::numeric = trunc((pointer->>'offset')::numeric)
    and (pointer->>'length')::numeric = trunc((pointer->>'length')::numeric)
    and (pointer->>'offset')::numeric >= 0
    and (pointer->>'length')::numeric >= 46
    and (pointer->>'offset')::numeric + (pointer->>'length')::numeric <= 4194304,
    false);
$$;
revoke all on function public.evidence_pointer_valid(jsonb) from public;
grant execute on function public.evidence_pointer_valid(jsonb) to service_role;

create table public.evidence_object_manifests (
  finding_id text primary key references public.findings(id) on delete restrict,
  revision bigint not null check (revision between 1 and 9007199254740991),
  finding_pointer jsonb not null check (public.evidence_pointer_valid(finding_pointer)),
  sources_pointer jsonb check (sources_pointer is null or public.evidence_pointer_valid(sources_pointer))
);
alter table public.evidence_object_manifests enable row level security;
revoke all on table public.evidence_object_manifests from public, anon, authenticated;
grant select (finding_id, revision, finding_pointer) on public.evidence_object_manifests to anon;
grant select, insert, update on public.evidence_object_manifests to service_role;
create policy evidence_manifest_public_read on public.evidence_object_manifests
  for select to anon using (exists (
    select 1 from public.findings f
    where f.id = finding_id and f.suppressed = false
  ));

create function public.publish_evidence_manifest(
  p_finding_id text, p_expected_revision bigint, p_suppressed boolean,
  p_finding_pointer jsonb, p_sources_pointer jsonb
) returns boolean language plpgsql security invoker set search_path = ''
as $$
declare current_suppressed boolean; changed integer;
begin
  if p_expected_revision is null or p_expected_revision < 0 or p_expected_revision >= 9007199254740991
     or p_suppressed is null then
    raise exception 'Invalid evidence publication revision/visibility';
  end if;
  -- The body and metadata visibility must agree at publication. This short lock
  -- occurs after upload/verification; it never spans an external Storage call.
  select f.suppressed into current_suppressed from public.findings f
    where f.id = p_finding_id for share;
  if not found or current_suppressed is distinct from p_suppressed then
    raise exception 'Finding visibility changed or finding absent';
  end if;
  if p_expected_revision = 0 then
    insert into public.evidence_object_manifests
      (finding_id, revision, finding_pointer, sources_pointer)
    values (p_finding_id, 1, p_finding_pointer, p_sources_pointer)
    on conflict (finding_id) do nothing;
  else
    update public.evidence_object_manifests
      set revision = p_expected_revision + 1,
          finding_pointer = p_finding_pointer, sources_pointer = p_sources_pointer
      where finding_id = p_finding_id and revision = p_expected_revision;
  end if;
  get diagnostics changed = row_count;
  return changed = 1;
end;
$$;
revoke all on function public.publish_evidence_manifest(text,bigint,boolean,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.publish_evidence_manifest(text,bigint,boolean,jsonb,jsonb) to service_role;

create function public.read_evidence_manifests(p_ids text[])
returns table (finding_id text, revision bigint, finding_pointer jsonb)
language sql stable security invoker set search_path = ''
as $$
  select m.finding_id, m.revision, m.finding_pointer
  from public.evidence_object_manifests m
  where cardinality(p_ids) between 1 and 100 and m.finding_id = any(p_ids)
  order by array_position(p_ids, m.finding_id);
$$;
revoke all on function public.read_evidence_manifests(text[]) from public, authenticated;
grant execute on function public.read_evidence_manifests(text[]) to anon;
commit;

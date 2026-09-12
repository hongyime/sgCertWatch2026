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
    and pointer - array['object','offset','length'] = '{}'::jsonb
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

-- Forty bytes: the full SHA-256 digest, then unsigned big-endian offset and
-- length. Preserve all digest bits; do not truncate hashes or finding IDs.
create function public.evidence_binary_pointer_valid(pointer bytea)
returns boolean language plpgsql immutable set search_path = ''
as $$
declare frame_offset bigint; frame_length bigint;
begin
  if pointer is null or octet_length(pointer) <> 40 then return false; end if;
  frame_offset := get_byte(pointer,32)::bigint * 16777216 + get_byte(pointer,33) * 65536
    + get_byte(pointer,34) * 256 + get_byte(pointer,35);
  frame_length := get_byte(pointer,36)::bigint * 16777216 + get_byte(pointer,37) * 65536
    + get_byte(pointer,38) * 256 + get_byte(pointer,39);
  return frame_length >= 46 and frame_offset + frame_length <= 4194304;
end;
$$;
revoke all on function public.evidence_binary_pointer_valid(bytea) from public;
grant execute on function public.evidence_binary_pointer_valid(bytea) to anon, service_role;

create function public.pack_evidence_pointer(pointer jsonb)
returns bytea language plpgsql immutable strict set search_path = ''
as $$
begin
  if not public.evidence_pointer_valid(pointer) then
    raise exception 'Invalid evidence pointer' using errcode = '22023';
  end if;
  return decode(pointer->>'object','hex')
    || int4send((pointer->>'offset')::numeric::integer)
    || int4send((pointer->>'length')::numeric::integer);
end;
$$;
revoke all on function public.pack_evidence_pointer(jsonb) from public;
grant execute on function public.pack_evidence_pointer(jsonb) to service_role;

create function public.unpack_evidence_pointer(pointer bytea)
returns jsonb language plpgsql immutable strict set search_path = ''
as $$
begin
  if not public.evidence_binary_pointer_valid(pointer) then
    raise exception 'Invalid binary evidence pointer' using errcode = '22023';
  end if;
  return jsonb_build_object('object',encode(substring(pointer from 1 for 32),'hex'),
    'offset',get_byte(pointer,32)::bigint * 16777216 + get_byte(pointer,33) * 65536
      + get_byte(pointer,34) * 256 + get_byte(pointer,35),
    'length',get_byte(pointer,36)::bigint * 16777216 + get_byte(pointer,37) * 65536
      + get_byte(pointer,38) * 256 + get_byte(pointer,39));
end;
$$;
revoke all on function public.unpack_evidence_pointer(bytea) from public;
grant execute on function public.unpack_evidence_pointer(bytea) to anon, service_role;

create table public.evidence_object_manifests (
  finding_id text primary key references public.findings(id) on delete restrict,
  revision bigint not null check (revision between 1 and 9007199254740991),
  finding_pointer bytea not null check (public.evidence_binary_pointer_valid(finding_pointer)),
  sources_pointer bytea check (sources_pointer is null or public.evidence_binary_pointer_valid(sources_pointer))
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
    values (p_finding_id, 1, public.pack_evidence_pointer(p_finding_pointer),
      public.pack_evidence_pointer(p_sources_pointer))
    on conflict (finding_id) do nothing;
  else
    update public.evidence_object_manifests
      set revision = p_expected_revision + 1,
          finding_pointer = public.pack_evidence_pointer(p_finding_pointer),
          sources_pointer = public.pack_evidence_pointer(p_sources_pointer)
      where finding_id = p_finding_id and revision = p_expected_revision;
  end if;
  get diagnostics changed = row_count;
  return changed = 1;
end;
$$;
revoke all on function public.publish_evidence_manifest(text,bigint,boolean,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.publish_evidence_manifest(text,bigint,boolean,jsonb,jsonb) to service_role;

create function public.publish_evidence_manifests(p_publications jsonb)
returns table(finding_id text, saved boolean)
language plpgsql security invoker set search_path = ''
as $$
declare item jsonb; seen text[] := '{}'; expected numeric;
begin
  if jsonb_typeof(p_publications) is distinct from 'array'
     or jsonb_array_length(p_publications) not between 1 and 200 then
    raise exception 'Invalid publication batch' using errcode = '22023';
  end if;
  -- Stable lock order for overlapping batches. Any validation/visibility error
  -- rolls back this entire RPC; revision conflicts return saved=false per row.
  for item in select value from jsonb_array_elements(p_publications) order by value->>'id' loop
    if jsonb_typeof(item->'id') is distinct from 'string' or octet_length(item->>'id') not between 1 and 8192
       or jsonb_typeof(item->'expected_revision') is distinct from 'number'
       or jsonb_typeof(item->'suppressed') is distinct from 'boolean'
       or not (item ? 'sources_pointer') then
      raise exception 'Invalid publication entry' using errcode = '22023';
    end if;
    finding_id := item->>'id';
    if finding_id = any(seen) then raise exception 'Duplicate publication identity' using errcode = '22023'; end if;
    seen := array_append(seen,finding_id);
    expected := (item->>'expected_revision')::numeric;
    if expected <> trunc(expected) or expected < 0 or expected >= 9007199254740991 then
      raise exception 'Invalid publication revision' using errcode = '22023';
    end if;
    saved := public.publish_evidence_manifest(finding_id,expected::bigint,(item->>'suppressed')::boolean,
      item->'finding_pointer',nullif(item->'sources_pointer','null'::jsonb));
    return next;
  end loop;
end;
$$;
revoke all on function public.publish_evidence_manifests(jsonb) from public, anon, authenticated;
grant execute on function public.publish_evidence_manifests(jsonb) to service_role;

create function public.read_evidence_manifests(p_ids text[])
returns table (finding_id text, revision bigint, finding_pointer jsonb)
language sql stable security invoker set search_path = ''
as $$
  select m.finding_id, m.revision, public.unpack_evidence_pointer(m.finding_pointer)
  from public.evidence_object_manifests m
  where cardinality(p_ids) between 1 and 100 and m.finding_id = any(p_ids)
  order by array_position(p_ids, m.finding_id);
$$;
revoke all on function public.read_evidence_manifests(text[]) from public, authenticated;
grant execute on function public.read_evidence_manifests(text[]) to anon;
commit;

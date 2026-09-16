-- Experimental coexistence contract only. Relational sources remain authoritative
-- while their complete snapshots are published to private objects.
begin;
create function public.read_evidence_source_context(p_ids text[])
returns table(id text, row_text text, revision bigint, finding_pointer jsonb,
  sources_pointer jsonb, source_rows text[])
language plpgsql stable security definer set search_path = '' set timezone = 'UTC'
as $$
declare item record; total_bytes bigint := 0; total_sources integer := 0;
begin
  if p_ids is null or cardinality(p_ids) not between 1 and 200
     or exists(select 1 from unnest(p_ids) v where v is null or octet_length(v) not between 1 and 8192)
     or cardinality(p_ids) <> (select count(distinct v) from unnest(p_ids) v) then
    raise exception 'Invalid source context batch' using errcode = '22023';
  end if;
  for item in
    select wanted.id, to_jsonb(f)::text as row_text, coalesce(m.revision,0) as revision,
      public.unpack_evidence_pointer(m.finding_pointer) as finding_pointer,
      public.unpack_evidence_pointer(m.sources_pointer) as sources_pointer,
      array(select to_jsonb(s)::text from public.finding_sources s where s.finding_id = wanted.id
        order by s.source,s.source_ref limit 10001) as source_rows
    from unnest(p_ids) with ordinality wanted(id,position)
    left join public.findings f on f.id = wanted.id
    left join public.evidence_object_manifests m on m.finding_id = wanted.id order by wanted.position
  loop
    if item.row_text is null then raise exception 'Source finding is absent' using errcode = '23503'; end if;
    total_sources := total_sources + cardinality(item.source_rows);
    total_bytes := total_bytes + octet_length(item.row_text)
      + coalesce((select sum(octet_length(v)) from unnest(item.source_rows) v),0);
    if total_sources > 10000 or total_bytes > 4194304 then
      raise exception 'Source context exceeds byte or row budget' using errcode = '22023';
    end if;
    id := item.id; row_text := item.row_text; revision := item.revision;
    finding_pointer := item.finding_pointer; sources_pointer := item.sources_pointer; source_rows := item.source_rows;
    return next;
  end loop;
end;
$$;
revoke all on function public.read_evidence_source_context(text[]) from public, anon, authenticated;
grant execute on function public.read_evidence_source_context(text[]) to service_role;

create function public.commit_evidence_sources(p_entries jsonb, p_lock_name text, p_owner_id uuid)
returns table(finding_id text, saved boolean)
language plpgsql security definer set search_path = '' set timezone = 'UTC' set lock_timeout = '2s'
as $$
declare item jsonb; seen text[] := '{}'; expected numeric; parent_row jsonb;
  current_manifest public.evidence_object_manifests; actual_sources jsonb; expected_sources jsonb;
  incoming_sources jsonb; next_sources jsonb; merged_sources jsonb; value jsonb;
  typed public.finding_sources; columns_sql text; packed_finding bytea; packed_sources bytea;
  total_incoming integer := 0;
begin
  perform public.assert_evidence_lease(p_lock_name,p_owner_id);
  if jsonb_typeof(p_entries) is distinct from 'array' or jsonb_array_length(p_entries) not between 1 and 200
     or octet_length(p_entries::text) > 4194304 then
    raise exception 'Invalid source commit batch' using errcode = '22023';
  end if;
  if exists(select 1 from pg_catalog.pg_attribute where attrelid='public.finding_sources'::regclass
      and attnum>0 and not attisdropped and (attgenerated<>'' or attidentity<>'')) then
    raise exception 'Source schema requires explicit generated-column review';
  end if;
  select string_agg(format('%I',attname),',' order by attnum) into columns_sql
    from pg_catalog.pg_attribute where attrelid='public.finding_sources'::regclass
      and attnum>0 and not attisdropped and attname not in ('finding_id','source','source_ref');
  for item in select v from jsonb_array_elements(p_entries) v order by v->>'id' loop
    if jsonb_typeof(item->'id') is distinct from 'string' or octet_length(item->>'id') not between 1 and 8192
       or jsonb_typeof(item->'expected_revision') is distinct from 'number'
       or jsonb_typeof(item->'expected_row') is distinct from 'string'
       or jsonb_typeof(item->'expected_source_rows') is distinct from 'array'
       or jsonb_typeof(item->'source_rows') is distinct from 'array'
       or jsonb_typeof(item->'incoming_rows') is distinct from 'array' then
      raise exception 'Invalid source commit entry' using errcode = '22023';
    end if;
    finding_id := item->>'id'; saved := false; expected := (item->>'expected_revision')::numeric;
    if finding_id = any(seen) or expected < 0 or expected >= 9007199254740991 or trunc(expected) <> expected then
      raise exception 'Invalid source commit identity/revision' using errcode = '22023';
    end if;
    seen := array_append(seen,finding_id);
    total_incoming := total_incoming + jsonb_array_length(item->'incoming_rows');
    if jsonb_array_length(item->'incoming_rows') < 1 or total_incoming > 200
       or jsonb_array_length(item->'expected_source_rows') > 10000 or jsonb_array_length(item->'source_rows') > 10000
       or exists(select 1 from jsonb_array_elements((item->'incoming_rows')||(item->'expected_source_rows')||(item->'source_rows')) v
         where jsonb_typeof(v) <> 'string') then
      raise exception 'Source commit exceeds row budget' using errcode = '22023';
    end if;
    select jsonb_agg((v #>> '{}')::jsonb) into incoming_sources from jsonb_array_elements(item->'incoming_rows') v;
    for value in select v from jsonb_array_elements(incoming_sources) v loop
      typed := jsonb_populate_record(null::public.finding_sources,value);
      if to_jsonb(typed) is distinct from value or typed.finding_id is distinct from finding_id
         or typed.source is null or typed.source_ref is null then
        raise exception 'Expected complete canonical source row' using errcode = '22023';
      end if;
    end loop;
    if (select count(*) <> count(distinct jsonb_build_array(v->'finding_id',v->'source',v->'source_ref')) from jsonb_array_elements(incoming_sources) v) then
      raise exception 'Duplicate source upsert identity' using errcode = '22023';
    end if;
    select coalesce(jsonb_agg((v #>> '{}')::jsonb order by ((v #>> '{}')::jsonb)->>'source',((v #>> '{}')::jsonb)->>'source_ref'),'[]'::jsonb)
      into expected_sources from jsonb_array_elements(item->'expected_source_rows') v;
    select coalesce(jsonb_agg((v #>> '{}')::jsonb order by ((v #>> '{}')::jsonb)->>'source',((v #>> '{}')::jsonb)->>'source_ref'),'[]'::jsonb)
      into next_sources from jsonb_array_elements(item->'source_rows') v;
    select coalesce(jsonb_agg(v order by v->>'source',v->>'source_ref'),'[]'::jsonb) into merged_sources from (
      select distinct on (v->>'source',v->>'source_ref') v
      from (select v,0 as priority from jsonb_array_elements(expected_sources) v
        union all select v,1 from jsonb_array_elements(incoming_sources) v) candidates
      order by v->>'source',v->>'source_ref',priority desc
    ) merged;
    if next_sources is distinct from merged_sources then raise exception 'Source merge dropped or changed evidence' using errcode = '22023'; end if;
    packed_finding := public.pack_evidence_pointer(item->'finding_pointer');
    packed_sources := public.pack_evidence_pointer(item->'sources_pointer');
    if packed_finding is null or packed_sources is null then raise exception 'Source publication pointers are required'; end if;
    -- No external calls under locks. Parent locks fence FK inserts and manifest
    -- updates; ordered child locks detect concurrent native edits and deletes.
    select to_jsonb(f) into parent_row from public.findings f where f.id=finding_id for update;
    if parent_row is null then raise exception 'Source finding is absent' using errcode = '23503'; end if;
    select m.* into current_manifest from public.evidence_object_manifests m where m.finding_id=commit_evidence_sources.finding_id;
    if parent_row is distinct from (item->>'expected_row')::jsonb or coalesce(current_manifest.revision,0) <> expected then
      return next; continue;
    end if;
    perform 1 from public.finding_sources s where s.finding_id=commit_evidence_sources.finding_id order by s.source,s.source_ref for update;
    select coalesce(jsonb_agg(to_jsonb(s) order by s.source,s.source_ref),'[]'::jsonb) into actual_sources
      from public.finding_sources s where s.finding_id=commit_evidence_sources.finding_id;
    if actual_sources is distinct from expected_sources then return next; continue; end if;
    if actual_sources = next_sources and packed_finding = current_manifest.finding_pointer and packed_sources = current_manifest.sources_pointer then
      saved := true; return next; continue;
    end if;
    execute format('insert into public.finding_sources as existing select * from jsonb_populate_recordset(null::public.finding_sources,$1)
      on conflict (finding_id,source,source_ref) do update set (%s) = (select %s from jsonb_populate_record(null::public.finding_sources,to_jsonb(excluded)))
      where to_jsonb(existing) is distinct from to_jsonb(excluded)',columns_sql,columns_sql) using incoming_sources;
    select coalesce(jsonb_agg(to_jsonb(s) order by s.source,s.source_ref),'[]'::jsonb) into actual_sources
      from public.finding_sources s where s.finding_id=commit_evidence_sources.finding_id;
    if actual_sources is distinct from next_sources then raise exception 'Source rows changed during materialization' using errcode = '40001'; end if;
    saved := public.publish_evidence_manifest(finding_id,expected::bigint,(parent_row->>'suppressed')::boolean,
      item->'finding_pointer',item->'sources_pointer',p_lock_name,p_owner_id);
    if not saved then raise exception 'Source publication changed during locked commit' using errcode = '40001'; end if;
    return next;
  end loop;
  perform public.assert_evidence_lease(p_lock_name,p_owner_id);
end;
$$;
revoke all on function public.commit_evidence_sources(jsonb,text,uuid) from public, anon, authenticated;
grant execute on function public.commit_evidence_sources(jsonb,text,uuid) to service_role;
commit;

-- Experimental coexistence contract, NOT a production migration. Wide finding
-- rows remain intact. Complete cutover/capacity and every legacy writer still
-- require review before enabling this adapter.
begin;
create function public.read_evidence_write_context(p_ids text[])
returns table(id text, row_text text, revision bigint, finding_pointer jsonb,
  sources_pointer jsonb, source_rows text[])
language plpgsql stable security definer set search_path = '' set timezone = 'UTC'
as $$
declare total_bytes bigint := 0; item record;
begin
  if cardinality(p_ids) not between 1 and 200 or p_ids is null
     or exists(select 1 from unnest(p_ids) v where v is null or octet_length(v) not between 1 and 8192)
     or cardinality(p_ids) <> (select count(distinct v) from unnest(p_ids) v) then
    raise exception 'Invalid finding context batch' using errcode = '22023';
  end if;
  for item in
    select wanted.id, case when f.id is null then null else to_jsonb(f)::text end as row_text,
      coalesce(m.revision,0) as revision, public.unpack_evidence_pointer(m.finding_pointer) as finding_pointer,
      public.unpack_evidence_pointer(m.sources_pointer) as sources_pointer,
      case when m.finding_id is null then array(select row_to_json(s)::text from public.finding_sources s
        where s.finding_id = wanted.id order by s.source,s.source_ref limit 10001) else '{}'::text[] end as source_rows
    from unnest(p_ids) with ordinality as wanted(id,position)
    left join public.findings f on f.id = wanted.id
    left join public.evidence_object_manifests m on m.finding_id = wanted.id order by wanted.position
  loop
    total_bytes := total_bytes + coalesce(octet_length(item.row_text),0)
      + coalesce((select sum(octet_length(v)) from unnest(item.source_rows) v),0);
    if cardinality(item.source_rows) > 10000 or total_bytes > 4194304 then
      raise exception 'Finding context exceeds byte or source budget' using errcode = '22023';
    end if;
    id := item.id; row_text := item.row_text; revision := item.revision;
    finding_pointer := item.finding_pointer; sources_pointer := item.sources_pointer; source_rows := item.source_rows;
    return next;
  end loop;
end;
$$;
revoke all on function public.read_evidence_write_context(text[]) from public, anon, authenticated;
grant execute on function public.read_evidence_write_context(text[]) to service_role;

create function public.commit_evidence_findings(p_entries jsonb, p_lock_name text, p_owner_id uuid)
returns table(finding_id text, saved boolean)
language plpgsql security definer set search_path = '' set timezone = 'UTC' set lock_timeout = '2s'
as $$
declare item jsonb; seen text[] := '{}'; expected numeric; current_row jsonb; next_row jsonb;
  current_manifest public.evidence_object_manifests; expected_sources jsonb; actual_sources jsonb;
  typed public.findings; columns_sql text; changed integer; packed_finding bytea; packed_sources bytea;
begin
  perform public.assert_evidence_lease(p_lock_name,p_owner_id);
  if jsonb_typeof(p_entries) is distinct from 'array' or jsonb_array_length(p_entries) not between 1 and 200
     or octet_length(p_entries::text) > 4194304 then
    raise exception 'Invalid finding commit batch' using errcode = '22023';
  end if;
  if exists(select 1 from pg_catalog.pg_attribute where attrelid = 'public.findings'::regclass
      and attnum > 0 and not attisdropped and (attgenerated <> '' or attidentity <> '')) then
    raise exception 'Finding schema requires explicit generated-column review';
  end if;
  select string_agg(format('%I',attname),',' order by attnum) into columns_sql
    from pg_catalog.pg_attribute where attrelid = 'public.findings'::regclass and attnum > 0 and not attisdropped and attname <> 'id';
  for item in select value from jsonb_array_elements(p_entries) order by value->>'id' loop
    if jsonb_typeof(item->'id') is distinct from 'string' or octet_length(item->>'id') not between 1 and 8192
       or jsonb_typeof(item->'expected_revision') is distinct from 'number'
       or jsonb_typeof(item->'row_text') is distinct from 'string'
       or jsonb_typeof(item->'expected_row') not in ('string','null') or not (item ? 'expected_row')
       or jsonb_typeof(item->'source_rows') is distinct from 'array' or not (item ? 'sources_pointer') then
      raise exception 'Invalid finding commit entry' using errcode = '22023';
    end if;
    finding_id := item->>'id'; saved := false;
    if finding_id = any(seen) then raise exception 'Duplicate finding commit' using errcode = '22023'; end if;
    seen := array_append(seen,finding_id); expected := (item->>'expected_revision')::numeric;
    if expected <> trunc(expected) or expected < 0 or expected >= 9007199254740991 then
      raise exception 'Invalid finding revision' using errcode = '22023';
    end if;
    next_row := (item->>'row_text')::jsonb;
    typed := jsonb_populate_record(null::public.findings,next_row);
    if typed.id is distinct from finding_id or to_jsonb(typed) is distinct from next_row then
      raise exception 'Expected complete canonical finding row' using errcode = '22023';
    end if;
    packed_finding := public.pack_evidence_pointer(item->'finding_pointer');
    packed_sources := public.pack_evidence_pointer(nullif(item->'sources_pointer','null'::jsonb));
    if packed_finding is null then raise exception 'Finding pointer is required'; end if;
    -- Stable row lock order; uploads/verification have already completed. This
    -- conflicts with manifest publication's finding FOR SHARE lock as well as
    -- ordinary relational edits. No network call occurs inside this transaction.
    select to_jsonb(f) into current_row from public.findings f where f.id = finding_id for update;
    select m.* into current_manifest from public.evidence_object_manifests m where m.finding_id = commit_evidence_findings.finding_id;
    if current_row is distinct from (item->>'expected_row')::jsonb
       or coalesce(current_manifest.revision,0) <> expected then return next; continue; end if;
    if expected = 0 then
      if jsonb_array_length(item->'source_rows') > 10000
         or exists(select 1 from jsonb_array_elements(item->'source_rows') v where jsonb_typeof(v) <> 'string') then
        raise exception 'Invalid bootstrap sources';
      end if;
      -- Lock existing sightings against concurrent updates/deletes. The parent
      -- FOR UPDATE also fences new FK inserts until this first snapshot commits.
      perform 1 from public.finding_sources s where s.finding_id = commit_evidence_findings.finding_id
        order by s.source,s.source_ref for share;
      select coalesce(jsonb_agg(to_jsonb(s) order by s.source,s.source_ref),'[]'::jsonb) into actual_sources
        from public.finding_sources s where s.finding_id = commit_evidence_findings.finding_id;
      select coalesce(jsonb_agg((v #>> '{}')::jsonb order by ((v #>> '{}')::jsonb)->>'source',((v #>> '{}')::jsonb)->>'source_ref'),'[]'::jsonb)
        into expected_sources from jsonb_array_elements(item->'source_rows') v;
      if actual_sources is distinct from expected_sources then return next; continue; end if;
      if (jsonb_array_length(actual_sources) = 0) <> (packed_sources is null) then raise exception 'Bootstrap sources pointer mismatch'; end if;
    elsif packed_sources is distinct from current_manifest.sources_pointer or jsonb_array_length(item->'source_rows') <> 0 then
      raise exception 'Finding update must preserve current source pointer';
    end if;
    if current_row is null then
      insert into public.findings select typed.* on conflict (id) do nothing;
      get diagnostics changed = row_count;
      if changed <> 1 then return next; continue; end if;
    elsif current_row is distinct from next_row then
      execute format('update public.findings set (%s) = (select %s from jsonb_populate_record(null::public.findings,$1)) where id=$2',columns_sql,columns_sql)
        using next_row,finding_id;
    elsif expected > 0 and packed_finding = current_manifest.finding_pointer then
      saved := true; return next; continue;
    end if;
    if (select to_jsonb(f) from public.findings f where f.id = finding_id) is distinct from next_row then
      raise exception 'Finding row changed during materialization' using errcode = '40001';
    end if;
    saved := public.publish_evidence_manifest(finding_id,expected::bigint,typed.suppressed,
      item->'finding_pointer',nullif(item->'sources_pointer','null'::jsonb),p_lock_name,p_owner_id);
    if not saved then raise exception 'Finding publication changed during locked commit' using errcode = '40001'; end if;
    return next;
  end loop;
  perform public.assert_evidence_lease(p_lock_name,p_owner_id);
end;
$$;
revoke all on function public.commit_evidence_findings(jsonb,text,uuid) from public, anon, authenticated;
grant execute on function public.commit_evidence_findings(jsonb,text,uuid) to service_role;
commit;

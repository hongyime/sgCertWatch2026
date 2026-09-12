-- Draft only. Materialize partial upserts using the current PostgreSQL column
-- types/defaults. Existing snapshots and returned JSON travel as text so clients
-- never round JSONB numbers or microsecond timestamps through JavaScript.
begin;

create function public.prepare_evidence_rows(p_kind text, p_existing text[], p_incoming text[])
returns text[] language plpgsql security invoker set search_path = ''
as $$
declare
  relation regclass; keys text[]; columns text[]; input_text text;
  original jsonb; patch jsonb; candidate jsonb; result jsonb; defaults jsonb := '{}';
  originals jsonb := '{}'; original_texts jsonb := '{}'; seen jsonb := '{}'; key_value text; column_name text;
  attribute record; constraint_row record; default_value jsonb; invalid boolean; duplicate_original boolean;
  output text[] := '{}';
begin
  if p_kind = 'finding' then relation := 'public.findings'::regclass; keys := array['id'];
  elsif p_kind = 'source' then relation := 'public.finding_sources'::regclass; keys := array['finding_id','source','source_ref'];
  else raise exception 'Unknown evidence row kind' using errcode = '22023'; end if;
  if p_existing is null or p_incoming is null or cardinality(p_existing) > 10000
     or cardinality(p_incoming) not between 1 and 200
     or octet_length(array_to_json(p_existing)::text) + octet_length(array_to_json(p_incoming)::text) > 4194304 then
    raise exception 'Evidence row batch exceeds budget' using errcode = '22023';
  end if;

  select array_agg(attname::text order by attnum) into columns
    from pg_catalog.pg_attribute where attrelid = relation and attnum > 0 and not attisdropped;
  -- Evaluate trusted schema defaults once per transaction/batch. Reject future
  -- generated/identity columns until their write contract has been reviewed.
  for attribute in
    select a.attname, a.attgenerated, a.attidentity, pg_catalog.pg_get_expr(d.adbin,d.adrelid) as expression
    from pg_catalog.pg_attribute a left join pg_catalog.pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
    where a.attrelid=relation and a.attnum > 0 and not a.attisdropped order by a.attnum
  loop
    if attribute.attgenerated <> '' or attribute.attidentity <> '' then
      raise exception 'Generated evidence column requires a reviewed contract' using errcode = '0A000';
    end if;
    default_value := 'null'::jsonb;
    if attribute.expression is not null then
      execute 'select to_jsonb(' || attribute.expression || ')' into default_value;
    end if;
    defaults := defaults || jsonb_build_object(attribute.attname, default_value);
  end loop;

  -- Aggregate once. Appending to a growing JSONB object for each of 10,000
  -- original sources repeatedly copies the entire map and exceeds the budget.
  with parsed as materialized (
    select raw, raw::jsonb as value from unnest(p_existing) raw
  ), identified as materialized (
    select raw, value,
      (select jsonb_agg(value->k order by ordinality)::text from unnest(keys) with ordinality as k(k,ordinality)) as row_identity,
      case when jsonb_typeof(value) = 'object' then
        not value ?& columns
        or exists (select 1 from jsonb_object_keys(value) k where not k = any(columns))
        or exists (select 1 from unnest(keys) k where jsonb_typeof(value->k) is distinct from 'string')
      else true end as invalid_row
    from parsed
  )
  select coalesce(jsonb_object_agg(row_identity,value),'{}'::jsonb),
         coalesce(jsonb_object_agg(row_identity,raw),'{}'::jsonb),
         coalesce(bool_or(invalid_row),false), count(*) <> count(distinct row_identity)
    into originals, original_texts, invalid, duplicate_original from identified;
  if invalid then raise exception 'Expected complete original evidence rows with valid identities' using errcode = '22023'; end if;
  if duplicate_original then raise exception 'Duplicate original evidence identity' using errcode = '21000'; end if;

  foreach input_text in array p_incoming loop
    patch := input_text::jsonb;
    if jsonb_typeof(patch) is distinct from 'object' then
      raise exception 'Expected an evidence row object' using errcode = '22023';
    end if;
    if exists (select 1 from jsonb_object_keys(patch) k where not k = any(columns)) then
      raise exception 'Unknown evidence column' using errcode = '42703';
    end if;
    if exists (select 1 from unnest(keys) k where jsonb_typeof(patch->k) is distinct from 'string') then
      raise exception 'All evidence identity columns are required' using errcode = '22023';
    end if;
    select jsonb_agg(patch->k order by ordinality)::text into key_value from unnest(keys) with ordinality as k(k,ordinality);
    if seen ? key_value then raise exception 'Duplicate incoming evidence identity' using errcode = '21000'; end if;
    seen := seen || jsonb_build_object(key_value, true);

    -- INSERT validates its proposed row before ON CONFLICT updates. An existing
    -- row therefore does not make omitted required insert fields valid.
    execute format('select to_jsonb(r) from jsonb_populate_record(null::%s,$1) r',relation)
      into candidate using defaults || patch;
    for attribute in select attname from pg_catalog.pg_attribute
      where attrelid=relation and attnum > 0 and not attisdropped and attnotnull
    loop
      if candidate->attribute.attname is null or candidate->attribute.attname = 'null'::jsonb then
        raise exception 'Null evidence column: %', attribute.attname using errcode = '23502';
      end if;
    end loop;
    for constraint_row in select pg_catalog.pg_get_expr(conbin,conrelid) as expression
      from pg_catalog.pg_constraint where conrelid=relation and contype='c'
    loop
      execute format('select not coalesce((%s),true) from jsonb_populate_record(null::%s,$1)',constraint_row.expression,relation)
        into invalid using candidate;
      if invalid then raise exception 'Evidence row violates a table check' using errcode = '23514'; end if;
    end loop;
    original := originals->key_value;
    if original is null then result := candidate;
    else
      result := original;
      -- Omitted columns keep their original values on conflict, including
      -- created_at, enrichment and even a stored JSONB null value.
      for column_name in select jsonb_object_keys(patch) loop
        result := result || jsonb_build_object(column_name,candidate->column_name);
      end loop;
    end if;
    for constraint_row in select pg_catalog.pg_get_expr(conbin,conrelid) as expression
      from pg_catalog.pg_constraint where conrelid=relation and contype='c'
    loop
      execute format('select not coalesce((%s),true) from jsonb_populate_record(null::%s,$1)',constraint_row.expression,relation)
        into invalid using result;
      if invalid then raise exception 'Evidence update violates a table check' using errcode = '23514'; end if;
    end loop;
    if p_kind='source' and not exists (select 1 from public.findings where id=result->>'finding_id') then
      raise exception 'Source finding is absent' using errcode = '23503';
    end if;
    output := array_append(output,case when original is not null and result = original
      then original_texts->>key_value else result::text end);
  end loop;
  return output;
end;
$$;
revoke all on function public.prepare_evidence_rows(text,text[],text[]) from public, anon, authenticated;
grant execute on function public.prepare_evidence_rows(text,text[],text[]) to service_role;
commit;

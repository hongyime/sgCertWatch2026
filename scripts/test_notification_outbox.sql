-- Run after notification-outbox.sql, using a migration/admin connection.
-- All synthetic jobs, alert history, lease changes and assertions are rolled back.
-- No Telegram/network requests occur. For pre-apply validation, place the migration
-- body (without its BEGIN/COMMIT) and this assertion body inside one transaction.
begin;

do $$
declare
  prefix text := 'outbox-test-' || gen_random_uuid()::text;
  jobs jsonb;
  result jsonb;
  snapshot jsonb;
  job public.notification_outbox;
  owner_one uuid := gen_random_uuid();
  owner_two uuid := gen_random_uuid();
  recent_host text;
  old_host text;
  id_one text;
  id_two text;
  initial_pending bigint;
  sent_count integer := 0;
  role_name text;
  signature text;
begin
  -- Disallow pre-existing jobs being claimed by these synthetic assertions.
  -- Both the pause and global cooldown reset disappear at ROLLBACK.
  update public.notification_outbox_channel set available_at = clock_timestamp() - interval '1 day';
  update public.notification_outbox set available_at = clock_timestamp() + interval '100 years'
    where state = 'pending';
  update public.notification_outbox set lease_until = clock_timestamp() + interval '100 years'
    where state = 'processing';
  select count(*) into initial_pending from public.notification_outbox where state in ('pending', 'processing', 'dead');
  if initial_pending > 9890 then raise exception 'SQL assertions need at least 110 free outbox slots'; end if;

  for role_name in select unnest(array['anon', 'authenticated']) loop
    foreach signature in array array[
      'public.notification_outbox_enqueue(jsonb,integer)',
      'public.notification_outbox_claim(uuid,integer,integer)',
      'public.notification_outbox_ack(text,uuid,bigint)',
      'public.notification_outbox_retry(text,uuid,text,integer,integer,integer,boolean)',
      'public.notification_outbox_retry_dead(text[],integer)',
      'public.notification_outbox_status()'
    ] loop
      if has_function_privilege(role_name, signature, 'execute') then
        raise exception 'Unexpected notification RPC permission: % %', role_name, signature;
      end if;
      if not has_function_privilege('service_role', signature, 'execute') then
        raise exception 'Missing service RPC permission: %', signature;
      end if;
    end loop;
    if has_table_privilege(role_name, 'public.notification_outbox', 'select')
      or has_table_privilege(role_name, 'public.notification_outbox_channel', 'select') then
      raise exception 'Outbox must be private';
    end if;
  end loop;
  if has_table_privilege('service_role', 'public.notification_outbox', 'update') then
    raise exception 'State changes must use atomic RPCs';
  end if;
  if not exists (select 1 from pg_catalog.pg_policy where polrelid = 'public.ingest_state'::regclass
    and polname = 'notifications_status_public_read' and polcmd = 'r') then
    raise exception 'Missing independent public aggregate read policy';
  end if;

  recent_host := prefix || '-recent.invalid';
  old_host := prefix || '-old.invalid';
  id_one := md5(prefix || '-one') || md5(prefix || '-one');
  id_two := md5(prefix || '-two') || md5(prefix || '-two');
  insert into public.alert_log(registrable, alerted_at) values
    (recent_host, clock_timestamp() - interval '71 hours'),
    (old_host, clock_timestamp() - interval '73 hours');
  jobs := jsonb_build_array(
    jsonb_build_object('id', id_one, 'registrable', recent_host, 'payload', '{}'::jsonb),
    jsonb_build_object('id', id_two, 'registrable', old_host, 'payload', '{}'::jsonb));
  result := public.notification_outbox_enqueue(jobs, 2);
  if result <> '{"queued":1,"deduped":1}'::jsonb then raise exception '72-hour legacy dedupe failed: %', result; end if;
  result := public.notification_outbox_enqueue(jobs, 2);
  if result <> '{"queued":0,"deduped":2}'::jsonb then raise exception 'Identity replay failed'; end if;

  select * into job from public.notification_outbox_claim(owner_one, 60, 0);
  if job.id is distinct from id_two or job.attempts <> 1 then raise exception 'Initial claim failed'; end if;
  if exists (select 1 from public.notification_outbox_claim(owner_two, 60, 0)) then raise exception 'Live claim stolen'; end if;
  if public.notification_outbox_ack(id_two, owner_two, 42) then raise exception 'Wrong owner ack accepted'; end if;
  if public.notification_outbox_retry(id_two, owner_two, 'telegram_timeout') <> 'lease_lost' then
    raise exception 'Wrong owner retry accepted';
  end if;
  update public.notification_outbox set lease_until = clock_timestamp() - interval '1 second' where id = id_two;
  if public.notification_outbox_ack(id_two, owner_one, 42) then raise exception 'Expired owner ack accepted'; end if;
  select * into job from public.notification_outbox_claim(owner_two, 60, 0);
  if job.id is distinct from id_two or job.attempts <> 2 then raise exception 'Restart recovery failed'; end if;
  if public.notification_outbox_retry(id_two, owner_two, 'private-token', 1, 2, 7200, true) <> 'dead' then
    raise exception 'Bounded attempts did not dead-letter';
  end if;
  select * into job from public.notification_outbox where id = id_two;
  if job.last_error <> 'telegram_failure' or job.available_at < job.updated_at + interval '7200 seconds' then
    raise exception 'Retry-After or error sanitization failed';
  end if;
  if exists (select 1 from public.notification_outbox_claim(owner_one, 60, 0)) then raise exception 'Rate-limit cooldown bypassed'; end if;
  if public.notification_outbox_retry_dead(array[id_two], 8) <> 1 then raise exception 'Manual retry failed'; end if;
  update public.notification_outbox_channel set available_at = clock_timestamp() - interval '1 second';
  select * into job from public.notification_outbox_claim(owner_one, 60, 0);
  if job.id is distinct from id_two or job.attempts <> 1 then raise exception 'Dead letter not recovered'; end if;

  -- A failed receipt validation must not change either half of the ack transaction.
  begin
    perform public.notification_outbox_ack(id_two, owner_one, 0);
    raise exception 'Expected invalid receipt rejection';
  exception when raise_exception then
    if sqlerrm <> 'Invalid Telegram message receipt' then raise; end if;
  end;
  if not public.notification_outbox_ack(id_two, owner_one, 42) then raise exception 'Valid ack failed'; end if;
  if not exists (select 1 from public.alert_log where registrable = old_host and alerted_at > clock_timestamp() - interval '1 minute')
    or not exists (select 1 from public.notification_outbox where id = id_two and state = 'sent' and message_id = 42) then
    raise exception 'Atomic sent/dedupe ack failed';
  end if;
  if public.notification_outbox_ack(id_two, owner_two, 42) then raise exception 'Wrong owner replay ack accepted'; end if;
  if not public.notification_outbox_ack(id_two, owner_one, 42) then raise exception 'Ack response replay failed'; end if;

  select jsonb_agg(jsonb_build_object('id', md5(prefix || i) || md5(prefix || i),
    'registrable', prefix || '-' || i || '.invalid', 'payload', '{}'::jsonb)) into jobs from generate_series(1,100) i;
  result := public.notification_outbox_enqueue(jobs, 8);
  if (result->>'queued')::integer <> 100 then raise exception '100-job enqueue lost overflow'; end if;
  for i in 1..100 loop
    select * into job from public.notification_outbox_claim(owner_one, 60, 0);
    if job.id is null or job.registrable not like prefix || '-%' then raise exception '100-job claim lost overflow'; end if;
    if not public.notification_outbox_ack(job.id, owner_one, 1000 + i) then raise exception '100-job ack failed'; end if;
    sent_count := sent_count + 1;
  end loop;
  if sent_count <> 100 then raise exception '100-job drain incomplete'; end if;
  snapshot := public.notification_outbox_status();
  if snapshot->>'checked_at' is null or snapshot::text like '%' || prefix || '%' then
    raise exception 'Aggregate freshness/privacy failed';
  end if;
  raise notice 'Notification outbox SQL assertions passed: auth, 72h dedupe, owners, leases, retries, dead letters, atomic ack, 100 jobs, aggregate privacy';
end;
$$;

rollback;

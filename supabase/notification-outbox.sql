-- Apply after schema.sql. Service-only RPCs; never expose these through a public API.
-- Pending/processing/dead payloads are retained (also when Telegram is unconfigured),
-- bounded to 10,000 rows. Capacity errors must prevent the ingest cursor commit.
-- Terminal identity tombstones are retained indefinitely to make ingest replay safe.
-- Delivery is at least once: a crash between Telegram send and ack can duplicate it.
begin;

create table if not exists public.notification_outbox (
  id text primary key check (id ~ '^[a-f0-9]{64}$'),
  registrable text not null check (length(registrable) between 3 and 253
    and registrable = lower(registrable) and registrable ~ '^[a-z0-9.-]+$'),
  payload jsonb not null check (jsonb_typeof(payload) = 'object' and octet_length(payload::text) <= 16384),
  state text not null default 'pending' check (state in ('pending', 'processing', 'sent', 'suppressed', 'dead')),
  attempts integer not null default 0 check (attempts >= 0),
  max_attempts integer not null default 8 check (max_attempts between 1 and 100),
  available_at timestamptz not null default now(),
  lease_owner uuid,
  lease_until timestamptz,
  last_error text,
  message_id bigint,
  delivered_owner uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  sent_at timestamptz,
  check ((state = 'processing') = (lease_owner is not null and lease_until is not null)),
  check (state <> 'sent' or (sent_at is not null and message_id > 0))
);
create unique index if not exists notification_outbox_open_registrable
  on public.notification_outbox (registrable) where state in ('pending', 'processing', 'dead');
create index if not exists notification_outbox_due
  on public.notification_outbox (available_at, created_at, id) where state in ('pending', 'processing');

create table if not exists public.notification_outbox_channel (
  channel text primary key check (channel = 'telegram'),
  available_at timestamptz not null default now()
);
insert into public.notification_outbox_channel(channel) values ('telegram') on conflict do nothing;
alter table public.notification_outbox enable row level security;
alter table public.notification_outbox_channel enable row level security;
revoke all on public.notification_outbox, public.notification_outbox_channel from public, anon, authenticated, service_role;
grant select on public.notification_outbox, public.notification_outbox_channel to service_role;

create or replace function public.notification_outbox_enqueue(p_jobs jsonb, p_max_attempts integer default 8)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  item jsonb;
  v_queued integer := 0;
  v_deduped integer := 0;
  v_open integer;
  v_suppressed boolean;
begin
  if p_jobs is null or jsonb_typeof(p_jobs) <> 'array' or jsonb_array_length(p_jobs) > 200
    or p_max_attempts is null or p_max_attempts not between 1 and 100 then
    raise exception 'Invalid notification enqueue parameters';
  end if;
  -- All mutating RPCs take this lock first: one order prevents races and deadlocks.
  perform 1 from public.notification_outbox_channel where channel = 'telegram' for update;
  select count(*) into v_open from public.notification_outbox where state in ('pending', 'processing', 'dead');
  for item in select value from jsonb_array_elements(p_jobs) loop
    if item->>'id' is null or item->>'registrable' is null
      or jsonb_typeof(item->'payload') is distinct from 'object' then
      raise exception 'Invalid notification job';
    end if;
    if exists (select 1 from public.notification_outbox where id = item->>'id') then
      v_deduped := v_deduped + 1;
      continue;
    end if;
    v_suppressed := exists (select 1 from public.notification_outbox
      where registrable = item->>'registrable' and state in ('pending', 'processing', 'dead'))
      or exists (select 1 from public.alert_log where registrable = item->>'registrable'
        and alerted_at > clock_timestamp() - interval '72 hours');
    if not v_suppressed and v_open >= 10000 then
      raise exception 'Notification outbox capacity reached';
    end if;
    insert into public.notification_outbox (id, registrable, payload, state, max_attempts)
      values (item->>'id', item->>'registrable', case when v_suppressed then '{}'::jsonb else item->'payload' end,
        case when v_suppressed then 'suppressed' else 'pending' end, p_max_attempts);
    if v_suppressed then v_deduped := v_deduped + 1;
    else v_queued := v_queued + 1; v_open := v_open + 1;
    end if;
  end loop;
  return jsonb_build_object('queued', v_queued, 'deduped', v_deduped);
end;
$$;

create or replace function public.notification_outbox_claim(p_owner uuid, p_lease_seconds integer default 60,
  p_spacing_ms integer default 1100)
returns setof public.notification_outbox language plpgsql security definer set search_path = '' as $$
declare job public.notification_outbox; v_now timestamptz;
begin
  if p_owner is null or p_lease_seconds is null or p_lease_seconds not between 15 and 3600
    or p_spacing_ms is null or p_spacing_ms not between 0 and 60000 then
    raise exception 'Invalid notification claim parameters';
  end if;
  perform 1 from public.notification_outbox_channel where channel = 'telegram' for update;
  v_now := clock_timestamp();
  if exists (select 1 from public.notification_outbox_channel where channel = 'telegram' and available_at > v_now) then
    return;
  end if;
  -- Expired claims are recoverable even if the previous process never called retry.
  for job in select * from public.notification_outbox
    where (state = 'pending' and available_at <= v_now) or (state = 'processing' and lease_until <= v_now)
    order by available_at, created_at, id for update skip locked loop
    if exists (select 1 from public.alert_log where registrable = job.registrable
      and alerted_at > v_now - interval '72 hours') then
      update public.notification_outbox set state = 'suppressed', payload = '{}', lease_owner = null,
        lease_until = null, updated_at = v_now where id = job.id;
      continue;
    end if;
    if job.attempts >= job.max_attempts then
      update public.notification_outbox set state = 'dead', lease_owner = null, lease_until = null,
        last_error = 'attempts_exhausted', updated_at = v_now where id = job.id;
      continue;
    end if;
    update public.notification_outbox_channel set available_at = v_now + p_spacing_ms * interval '1 millisecond'
      where channel = 'telegram';
    return query update public.notification_outbox set state = 'processing', attempts = attempts + 1,
      lease_owner = p_owner, lease_until = v_now + p_lease_seconds * interval '1 second', updated_at = v_now
      where id = job.id returning *;
    return;
  end loop;
end;
$$;

create or replace function public.notification_outbox_ack(p_id text, p_owner uuid, p_message_id bigint)
returns boolean language plpgsql security definer set search_path = '' as $$
declare job public.notification_outbox; v_now timestamptz;
begin
  if p_message_id is null or p_message_id <= 0 then raise exception 'Invalid Telegram message receipt'; end if;
  perform 1 from public.notification_outbox_channel where channel = 'telegram' for update;
  v_now := clock_timestamp();
  select * into job from public.notification_outbox where id = p_id for update;
  if job.id is null then return false; end if;
  -- Idempotent response recovery does not rewrite the dedupe timestamp.
  if job.state = 'sent' and job.message_id = p_message_id and job.delivered_owner = p_owner then return true; end if;
  if job.state <> 'processing' or job.lease_owner is distinct from p_owner or job.lease_until <= v_now then return false; end if;
  insert into public.alert_log(registrable, alerted_at) values (job.registrable, v_now)
    on conflict (registrable) do update set alerted_at = greatest(public.alert_log.alerted_at, excluded.alerted_at);
  update public.notification_outbox set state = 'sent', message_id = p_message_id, delivered_owner = p_owner, sent_at = v_now,
    payload = '{}', lease_owner = null, lease_until = null, last_error = null, updated_at = v_now where id = p_id;
  return true;
end;
$$;

create or replace function public.notification_outbox_retry(p_id text, p_owner uuid, p_error text,
  p_base_seconds integer default 30, p_max_seconds integer default 21600, p_retry_after_seconds integer default 0,
  p_rate_limited boolean default false)
returns text language plpgsql security definer set search_path = '' as $$
declare job public.notification_outbox; v_now timestamptz; v_delay double precision; v_state text;
begin
  if p_base_seconds is null or p_base_seconds not between 1 and 86400
    or p_max_seconds is null or p_max_seconds not between p_base_seconds and 604800
    or p_retry_after_seconds is null or p_retry_after_seconds < 0 or p_rate_limited is null then
    raise exception 'Invalid notification retry parameters';
  end if;
  perform 1 from public.notification_outbox_channel where channel = 'telegram' for update;
  v_now := clock_timestamp();
  select * into job from public.notification_outbox where id = p_id for update;
  if job.id is null or job.state <> 'processing' or job.lease_owner is distinct from p_owner
    or job.lease_until <= v_now then return 'lease_lost'; end if;
  v_delay := greatest(p_retry_after_seconds,
    least(p_max_seconds::double precision, p_base_seconds * power(2::double precision, least(job.attempts - 1, 30))));
  v_state := case when job.attempts >= job.max_attempts then 'dead' else 'pending' end;
  update public.notification_outbox set state = v_state, available_at = v_now + v_delay * interval '1 second',
    lease_owner = null, lease_until = null, updated_at = v_now,
    -- Persist only stable error codes, never provider response bodies, URLs or tokens.
    last_error = case when p_error ~ '^telegram_(http_[0-9]{3}|api_[0-9]{3}|network|timeout|invalid_json|invalid_receipt|unconfigured)$'
      then p_error else 'telegram_failure' end where id = p_id;
  if p_rate_limited then
    update public.notification_outbox_channel set available_at = greatest(available_at, v_now + v_delay * interval '1 second')
      where channel = 'telegram';
  end if;
  return v_state;
end;
$$;

create or replace function public.notification_outbox_retry_dead(p_ids text[], p_max_attempts integer default 8)
returns integer language plpgsql security definer set search_path = '' as $$
declare v_count integer;
begin
  if p_ids is null or cardinality(p_ids) not between 1 and 200
    or p_max_attempts is null or p_max_attempts not between 1 and 100 then
    raise exception 'Retry requires 1 to 200 explicit job IDs and bounded attempts';
  end if;
  perform 1 from public.notification_outbox_channel where channel = 'telegram' for update;
  update public.notification_outbox set state = 'pending', attempts = 0, max_attempts = p_max_attempts,
    available_at = clock_timestamp(), last_error = null, updated_at = clock_timestamp()
    where id = any(p_ids) and state = 'dead';
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

-- Add only this aggregate key; preserve the parent's existing state policies.
do $policy$
begin
  if not exists (select 1 from pg_catalog.pg_policy
    where polrelid = 'public.ingest_state'::regclass and polname = 'notifications_status_public_read') then
    create policy notifications_status_public_read on public.ingest_state
      for select to anon using (key = 'notifications_poll_status');
  end if;
end;
$policy$;

-- Read-only RPC. The runner publishes this via the existing service setState.
create or replace function public.notification_outbox_status()
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_now timestamptz; v_status jsonb; v_channel timestamptz;
begin
  v_now := clock_timestamp();
  select available_at into v_channel from public.notification_outbox_channel where channel = 'telegram';
  select jsonb_build_object(
    'checked_at', v_now,
    'pending', count(*) filter (where state = 'pending'),
    'processing', count(*) filter (where state = 'processing'),
    'dead', count(*) filter (where state = 'dead'),
    'sent', count(*) filter (where state = 'sent'),
    'suppressed', count(*) filter (where state = 'suppressed'),
    'ready', count(*) filter (where (state = 'pending' and available_at <= v_now or state = 'processing' and lease_until <= v_now)
      and v_channel <= v_now and attempts < max_attempts),
    'oldest_pending_at', min(created_at) filter (where state in ('pending', 'processing')),
    'next_retry_at', min(greatest(case when state = 'processing' then lease_until else available_at end, v_channel))
      filter (where state in ('pending', 'processing')),
    'last_sent_at', max(sent_at)
  ) into v_status from public.notification_outbox;
  return v_status;
end;
$$;

revoke all on function public.notification_outbox_enqueue(jsonb, integer),
  public.notification_outbox_claim(uuid, integer, integer), public.notification_outbox_ack(text, uuid, bigint),
  public.notification_outbox_retry(text, uuid, text, integer, integer, integer, boolean),
  public.notification_outbox_retry_dead(text[], integer),
  public.notification_outbox_status() from public, anon, authenticated;
grant execute on function public.notification_outbox_enqueue(jsonb, integer),
  public.notification_outbox_claim(uuid, integer, integer), public.notification_outbox_ack(text, uuid, bigint),
  public.notification_outbox_retry(text, uuid, text, integer, integer, integer, boolean),
  public.notification_outbox_retry_dead(text[], integer),
  public.notification_outbox_status() to service_role;
commit;

begin;

create table if not exists public.run_locks (
  name text primary key,
  owner_id uuid not null,
  locked_until timestamptz not null,
  renewed_at timestamptz not null default clock_timestamp()
);
alter table public.run_locks enable row level security;
revoke all on public.run_locks from public, anon, authenticated;
grant select, insert, update on public.run_locks to service_role;

create or replace function public.acquire_run_lock(lock_name text, owner_id uuid, lease_seconds integer default 900)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare existing public.run_locks;
begin
  if lock_name is null or length(lock_name) not between 1 and 100 or owner_id is null
     or lease_seconds is null or lease_seconds not between 30 and 1800 then
    raise exception 'Invalid run lease';
  end if;
  insert into public.run_locks (name, owner_id, locked_until)
    values (lock_name, acquire_run_lock.owner_id, '-infinity'::timestamptz) on conflict (name) do nothing;
  select * into existing from public.run_locks where name = lock_name for update;
  if existing.locked_until > clock_timestamp() then return false; end if;
  update public.run_locks set owner_id = acquire_run_lock.owner_id,
    locked_until = clock_timestamp() + make_interval(secs => lease_seconds), renewed_at = clock_timestamp()
    where name = lock_name;
  return true;
end;
$$;

create or replace function public.renew_run_lock(lock_name text, owner_id uuid, lease_seconds integer default 900)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare existing public.run_locks;
begin
  if lease_seconds is null or lease_seconds not between 30 and 1800 then
    raise exception 'Invalid run lease';
  end if;
  select * into existing from public.run_locks where name = lock_name for update;
  if not found or existing.owner_id is distinct from renew_run_lock.owner_id
    or existing.locked_until <= clock_timestamp() then return false; end if;
  update public.run_locks
  set locked_until = clock_timestamp() + make_interval(secs => lease_seconds), renewed_at = clock_timestamp()
  where name = lock_name;
  return true;
end;
$$;

create or replace function public.release_run_lock(lock_name text, owner_id uuid)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare existing public.run_locks;
begin
  select * into existing from public.run_locks where name = lock_name for update;
  if not found or existing.owner_id is distinct from release_run_lock.owner_id
    or existing.locked_until <= clock_timestamp() then return false; end if;
  update public.run_locks set locked_until = clock_timestamp() where name = lock_name;
  return true;
end;
$$;

-- Lock the lease row through checkpoint commit so an expired owner cannot overwrite a successor.
create or replace function public.set_run_state(lock_name text, owner_id uuid, state_key text, state_value jsonb)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare existing public.run_locks;
begin
  select * into existing from public.run_locks where name = lock_name for update;
  if not found or existing.owner_id is distinct from set_run_state.owner_id
    or existing.locked_until <= clock_timestamp() then return false; end if;
  if not ((lock_name = 'ct_poll_run' and state_key in ('ct_source_state', 'ct_poll_status'))
      or (lock_name = 'intel_poll_run' and state_key in ('intel_source_state', 'intel_poll_status'))) then
    raise exception 'State key does not belong to run lease';
  end if;
  insert into public.ingest_state (key, value, updated_at)
    values (state_key, state_value, clock_timestamp())
    on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at;
  return true;
end;
$$;

revoke all on function public.acquire_run_lock(text, uuid, integer) from public, anon, authenticated;
revoke all on function public.renew_run_lock(text, uuid, integer) from public, anon, authenticated;
revoke all on function public.release_run_lock(text, uuid) from public, anon, authenticated;
revoke all on function public.set_run_state(text, uuid, text, jsonb) from public, anon, authenticated;
grant execute on function public.acquire_run_lock(text, uuid, integer) to service_role;
grant execute on function public.renew_run_lock(text, uuid, integer) to service_role;
grant execute on function public.release_run_lock(text, uuid) to service_role;
grant execute on function public.set_run_state(text, uuid, text, jsonb) to service_role;
notify pgrst, 'reload schema';
commit;

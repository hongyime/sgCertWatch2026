do $$
declare
  owner_a uuid := gen_random_uuid();
  owner_b uuid := gen_random_uuid();
  test_name text := 'lease-test-' || gen_random_uuid()::text;
begin
  if not public.acquire_run_lock(test_name, owner_a, 30) then raise exception 'first acquire failed'; end if;
  if public.acquire_run_lock(test_name, owner_b, 30) then raise exception 'second owner admitted'; end if;
  if public.release_run_lock(test_name, owner_b) then raise exception 'nonowner release admitted'; end if;
  if public.renew_run_lock(test_name, owner_b, 30) then raise exception 'nonowner renewal admitted'; end if;
  if public.set_run_state(test_name, owner_b, 'ct_source_state', '{}'::jsonb) then raise exception 'nonowner checkpoint admitted'; end if;
  if not public.renew_run_lock(test_name, owner_a, 60) then raise exception 'owner renewal failed'; end if;
  update public.run_locks set locked_until = clock_timestamp() - interval '1 second' where name = test_name;
  if public.renew_run_lock(test_name, owner_a, 60) then raise exception 'expired lease revived'; end if;
  if not public.acquire_run_lock(test_name, owner_b, 30) then raise exception 'expired lease not reclaimable'; end if;
  if public.release_run_lock(test_name, owner_a) then raise exception 'old owner released successor'; end if;
  if not public.release_run_lock(test_name, owner_b) then raise exception 'owner release failed'; end if;
  if has_table_privilege('anon', 'public.run_locks', 'SELECT')
      or has_table_privilege('authenticated', 'public.run_locks', 'UPDATE') then
    raise exception 'public lease table access';
  end if;
  if has_function_privilege('anon', 'public.acquire_run_lock(text,uuid,integer)', 'EXECUTE')
      or has_function_privilege('authenticated', 'public.set_run_state(text,uuid,text,jsonb)', 'EXECUTE') then
    raise exception 'public lease RPC access';
  end if;
end;
$$;

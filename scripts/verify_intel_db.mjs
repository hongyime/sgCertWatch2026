import assert from "node:assert/strict";

const query = `
do $verify$
declare
  smoke_id text := 'verification-' || gen_random_uuid()::text;
  host text;
  visible_rows integer;
begin
  select domain into host from public.findings f, unnest(f.domains) as domain
    where f.suppressed = false and f.score >= 60 and domain !~ '[*]'
    limit 1;
  if host is null then raise exception 'No exact host available for verification'; end if;
  begin
    insert into public.intel_evidence (id, domain, source, source_ref, verdict, observed_at, expires_at)
    values (smoke_id, host, 'openphish', 'https://openphish.com/phishing_feeds.html',
      'phishing', now(), now() + interval '1 minute');
    set local role anon;
    select count(*) into visible_rows from public.intel_evidence where id = smoke_id;
    if visible_rows <> 1 then raise exception 'Anon cannot read matching evidence'; end if;
    select count(*) into visible_rows from public.intel_findings_for_hosts(array[host], 10);
    if visible_rows < 1 then raise exception 'Evidence host lookup failed'; end if;
    begin
      update public.intel_evidence set verdict = 'observed' where id = smoke_id;
      raise exception 'Anon unexpectedly wrote evidence';
    exception when insufficient_privilege then null;
    end;
    raise exception using errcode = 'ZX001', message = 'Rollback verification evidence';
  exception when sqlstate 'ZX001' then null;
  end;
  if exists (select 1 from public.intel_evidence where id = smoke_id) then
    raise exception 'Verification evidence was not rolled back';
  end if;
end;
$verify$;
select
  (select relrowsecurity from pg_class where oid = 'public.intel_evidence'::regclass) as rls,
  has_table_privilege('anon', 'public.intel_evidence', 'SELECT') as public_read,
  has_table_privilege('anon', 'public.intel_evidence', 'INSERT') as public_write,
  has_function_privilege('anon', 'public.intel_candidate_findings(integer)', 'EXECUTE') as public_candidates,
  has_function_privilege('anon', 'public.intel_findings_for_hosts(text[],integer)', 'EXECUTE') as public_host_lookup,
  (select count(*) from pg_proc where oid in (
    'public.intel_candidate_findings(integer)'::regprocedure,
    'public.intel_findings_for_hosts(text[],integer)'::regprocedure) and prosecdef) as definer_functions,
  (select count(*) from public.intel_candidate_findings(500)) as candidates,
  (select count(distinct registrable) from public.intel_candidate_findings(500)) as distinct_candidates,
  (select count(*) from public.intel_candidate_findings(500) where score < 70) as near_threshold_candidates,
  exists (select 1 from public.findings where suppressed = false and score >= 60
    group by registrable having max(score) < 70) as near_threshold_available,
  (select qual from pg_policies where tablename = 'ingest_state' and policyname = 'ingest_state_public_read') as public_state_policy;
`;
const started = Date.now();
const response = await fetch("https://api.supabase.com/v1/projects/umixzwbsajyhiuaethxq/database/query", {
  method: "POST", headers: { Authorization: `Bearer ${process.env.SUPABASE_ACCESS_TOKEN}`, "Content-Type": "application/json" },
  body: JSON.stringify({ query }), signal: AbortSignal.timeout(20000)
});
const body = await response.text();
assert.equal(response.status, 201, body);
const [row] = JSON.parse(body);
assert.equal(row.rls, true);
assert.equal(row.public_read, true);
assert.equal(row.public_write, false);
assert.equal(row.public_candidates, false);
assert.equal(row.public_host_lookup, true);
assert.equal(row.definer_functions, 0);
assert.equal(row.candidates, row.distinct_candidates);
assert.ok(row.candidates <= 500);
if (row.near_threshold_available) assert.ok(row.near_threshold_candidates > 0);
assert.ok(row.public_state_policy.includes("intel_poll_status"));
assert.equal(row.public_state_policy.includes("intel_source_state"), false);
console.log(JSON.stringify({ ...row, duration_ms: Date.now() - started }));

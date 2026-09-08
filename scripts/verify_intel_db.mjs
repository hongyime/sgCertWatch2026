import assert from "node:assert/strict";

const query = `
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
assert.ok(row.public_state_policy.includes("intel_poll_status"));
assert.equal(row.public_state_policy.includes("intel_source_state"), false);
console.log(JSON.stringify({ ...row, duration_ms: Date.now() - started }));

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const ref = process.env.SUPABASE_PROJECT_REF;
const token = process.env.SUPABASE_ACCESS_TOKEN;
if (!ref || !token) throw new Error("SUPABASE_PROJECT_REF and SUPABASE_ACCESS_TOKEN required");
async function management(path, options = {}) {
  const response = await fetch(`https://api.supabase.com/v1/projects/${ref}/${path}`, {
    ...options, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    signal: AbortSignal.timeout(30000)
  });
  if (!response.ok) throw new Error(`Database verification HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}
const query = (sql) => management("database/query", { method: "POST", body: JSON.stringify({ query: sql }) });
const migration = await readFile(new URL("../supabase/run-locks.sql", import.meta.url), "utf8");
const checks = await readFile(new URL("./test_run_lock.sql", import.meta.url), "utf8");
await query(migration.replace(/commit;\s*$/, () => `${checks}\nrollback;`));
console.log("SQL transaction: ownership, expiry, renewal and private grants passed (rolled back)");
if (!process.argv.includes("--apply")) process.exit(0);
await query(migration);
const keys = await management("api-keys");
const service = keys.find((key) => key.name === "service_role")?.api_key;
const anon = keys.find((key) => key.name === "anon")?.api_key;
assert.ok(service && anon, "Existing API keys required for live RLS verification");
async function rpc(name, body, key = service) {
  const response = await fetch(`https://${ref}.supabase.co/rest/v1/rpc/${name}`, {
    method: "POST", headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify(body), signal: AbortSignal.timeout(20000)
  });
  if (!response.ok) throw new Error(`Lease RPC ${name} HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}
const lockName = `lease-test-${randomUUID()}`;
const owners = Array.from({ length: 20 }, () => randomUUID());
try {
  // PostgREST reloads the new RPC schema asynchronously after migration commit.
  for (let attempt = 0; ; attempt++) {
    try { await rpc("release_run_lock", { lock_name: lockName, owner_id: owners[0] }); break; }
    catch (error) {
      if (!error.message.includes("HTTP 404") || attempt >= 9) throw error;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  const attempts = await Promise.allSettled(owners.map((owner) => rpc("acquire_run_lock", {
    lock_name: lockName, owner_id: owner, lease_seconds: 30
  })));
  for (const attempt of attempts) if (attempt.status === "rejected") throw attempt.reason;
  const results = attempts.map((attempt) => attempt.value);
  assert.equal(results.filter(Boolean).length, 1);
  const winner = owners[results.indexOf(true)];
  assert.equal(await rpc("release_run_lock", { lock_name: lockName, owner_id: randomUUID() }), false);
  await assert.rejects(rpc("acquire_run_lock", { lock_name: lockName, owner_id: randomUUID(), lease_seconds: 30 }, anon), /HTTP 40[13]/);
  assert.equal(await rpc("release_run_lock", { lock_name: lockName, owner_id: winner }), true);
  console.log("Live REST: 20 simultaneous contenders, exactly one winner; nonowner and anonymous writes rejected");
} finally {
  await query(`delete from public.run_locks where name = '${lockName}'`);
}

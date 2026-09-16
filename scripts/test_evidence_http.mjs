// Real PostgREST differential oracle. Every database and HTTP request is confined
// to a new synthetic loopback database; no production credentials are used.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawn, execFileSync } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { once } from "node:events";
import { test } from "node:test";
import pg from "pg";
import { privateManifestStore, publicManifestReader } from "../lib/storage/supabase-manifests.js";
import { EvidenceRepository } from "../lib/storage/evidence-repository.js";

const target = new URL(process.env.EVIDENCE_HTTP_DATABASE_URL || "invalid:");
assert.equal(target.hostname, "127.0.0.1");
assert(/^\/prawn_evidence_fixture_[a-z0-9]+$/.test(target.pathname));
const binary = process.env.EVIDENCE_POSTGREST_BINARY;
assert(binary, "A checksum-verified PostgREST 14.5 binary is required");
assert.equal(execFileSync(binary, ["--version"], { encoding: "utf8", windowsHide: true }).trim(), "PostgREST 14.5");
let addresses = ["127.0.0.1"];
if (process.env.GITHUB_ACTIONS === "true") {
  const id = process.env.EVIDENCE_TEST_CONTAINER_ID;
  assert(/^[a-f0-9]{64}$/.test(id));
  const [container] = JSON.parse(execFileSync("docker", ["inspect", id], { encoding: "utf8" }));
  assert.equal(container.Id, id); assert.equal(container.Config.Image, "postgres:17.11");
  assert(container.Config.Env.includes("POSTGRES_DB=prawn_evidence_fixture_ci"));
  addresses = Object.values(container.NetworkSettings.Networks).map(n => n.IPAddress).filter(Boolean);
  assert(addresses.length);
}
const pool = new pg.Pool({ connectionString: target.href, max: 3, connectionTimeoutMillis: 5000, statement_timeout: 8000, options: "-c timezone=UTC" });
const nativeFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error("Provider access forbidden in HTTP fixtures"); };
const secret = randomBytes(48).toString("hex");
const jwt = role => {
  const encoded = value => Buffer.from(JSON.stringify(value)).toString("base64url");
  const data = encoded({ alg: "HS256", typ: "JWT" }) + "." + encoded({ role, exp: Math.floor(Date.now() / 1000) + 600 });
  return data + "." + createHmac("sha256", secret).update(data).digest("base64url");
};
const tokens = Object.fromEntries(["anon", "authenticated", "service_role"].map(role => [role, jwt(role)]));
const raw = value => Buffer.from(JSON.stringify(value));
const minimal = id => ({ id, observed_at: "2026-01-01T00:00:00.123456Z", registrable: "synthetic.invalid", score: 1, severity: "low" });
const table = kind => kind === "finding" ? "findings" : "finding_sources";
let origin, server;

async function request(path, { role = "service_role", body, prefer } = {}) {
  assert(path.startsWith("/") && !path.startsWith("//"));
  return nativeFetch(origin + path, { method: body === undefined ? "GET" : "POST", redirect: "error",
    signal: AbortSignal.timeout(8000), headers: { Authorization: `Bearer ${tokens[role]}`,
      "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
    ...(body === undefined ? {} : { body }) });
}
const loopbackFetch = (url, options) => {
  const endpoint = new URL(url);
  assert.equal(endpoint.origin, "https://fixture.invalid");
  assert(endpoint.pathname.startsWith("/rest/v1/"));
  return nativeFetch(origin + endpoint.pathname.slice("/rest/v1".length) + endpoint.search, options);
};
const store = privateManifestStore({ url: "https://fixture.invalid", serviceKey: tokens.service_role, fetchImpl: loopbackFetch });
const reader = publicManifestReader({ url: "https://fixture.invalid", anonKey: tokens.anon, fetchImpl: loopbackFetch });
async function nativeUpsert(kind, rows) {
  // Exactly the production URL selection and Prefer header in lib/supabase.js.
  return request(`/${table(kind)}?select=${kind === "finding" ? "id" : "finding_id"}`, {
    body: "[" + rows.map(r => r.toString()).join(",") + "]",
    prefer: "resolution=merge-duplicates,return=representation"
  });
}
async function originals(kind, id) {
  return (await pool.query(`select row_to_json(t)::text as raw from public.${table(kind)} t where ${kind === "finding" ? "id" : "finding_id"}=$1`, [id])).rows.map(r => Buffer.from(r.raw));
}
async function seedFinding(id, extra = {}) {
  const response = await nativeUpsert("finding", [raw({ ...minimal(id), ...extra })]);
  assert.equal(response.status, 201, await response.text());
  return originals("finding", id);
}
async function compare(kind, id, incoming, { fresh = false } = {}) {
  const existing = await originals(kind, id);
  const before = Date.now();
  const normalized = await store.prepareRows(kind, existing, incoming);
  const response = await nativeUpsert(kind, incoming);
  assert.equal(response.status, existing.length ? 200 : 201);
  const identity = kind === "finding" ? "id" : "finding_id";
  assert.deepEqual(await response.json(), incoming.map(r => ({ [identity]: JSON.parse(r)[identity] })));
  const after = Date.now();
  const saved = await originals(kind, id);
  for (const prepared of normalized) {
    const value = JSON.parse(prepared);
    const actual = saved.find(r => {
      const candidate = JSON.parse(r);
      return kind === "finding" ? candidate.id === value.id : candidate.source === value.source && candidate.source_ref === value.source_ref;
    });
    assert(actual);
    // Native HTTP and RPC use separate transactions. Check now() bounds, then
    // compare all other fields in PostgreSQL without rounding JSONB numbers.
    const exclude = fresh && !Object.hasOwn(JSON.parse(incoming[0]), "created_at");
    if (exclude) for (const row of [prepared, actual]) {
      const created = Date.parse(JSON.parse(row).created_at);
      assert(created >= before - 1 && created <= after + 1);
    }
    const query = exclude ? "select ($1::jsonb-'created_at')=($2::jsonb-'created_at') as equal" : "select $1::jsonb=$2::jsonb as equal";
    assert.equal((await pool.query(query, [prepared.toString(), actual.toString()])).rows[0].equal, true);
  }
  return normalized;
}
async function rejection(kind, incoming, expectedCode) {
  const response = await nativeUpsert(kind, incoming);
  assert(response.status >= 400);
  const error = await response.json(); assert.equal(error.code, expectedCode);
  await assert.rejects(store.prepareRows(kind, [], incoming));
}

await test("PostgREST 14.5 HTTP evidence contracts", { timeout: 60000 }, async t => {
  try {
    const identity = (await pool.query("select current_database() as db,inet_server_addr()::text as address,current_setting('server_version') as version")).rows[0];
    assert.equal(identity.db, target.pathname.slice(1)); assert(addresses.includes(identity.address.split('/')[0]));
    assert(identity.version.startsWith("17.11"));
    assert.equal((await pool.query("select to_regclass('public.findings') as relation")).rows[0].relation, null);
    for (const role of ["anon", "authenticated", "service_role"]) {
      if (!(await pool.query("select 1 from pg_roles where rolname=$1", [role])).rowCount)
        await pool.query(`create role ${role} nologin ${role === "service_role" ? "bypassrls" : "nobypassrls"}`);
    }
    const schema = await readFile(new URL("../supabase/schema.sql", import.meta.url), "utf8");
    await pool.query(schema.split("create table if not exists public.ct_source_runs")[0]);
    for (const [extension] of schema.matchAll(/^alter table public\.findings add column[^;]+;/gm)) await pool.query(extension);
    for (const name of ["evidence-manifests.sql", "evidence-row-contracts.sql"])
      await pool.query(await readFile(new URL("../supabase/experimental/" + name, import.meta.url), "utf8"));
    const authenticator = "prawn_http_" + randomBytes(8).toString("hex");
    const password = randomBytes(32).toString("hex");
    await pool.query(`create role ${authenticator} login noinherit password '${password}'`);
    await pool.query(`alter role ${authenticator} set timezone='UTC'`);
    await pool.query(`alter role ${authenticator} set statement_timeout='8s'`);
    await pool.query(`grant anon, authenticated, service_role to ${authenticator}`);
    await pool.query("grant usage on schema public to anon, authenticated, service_role");
    const uri = new URL(target); uri.username = authenticator; uri.password = password;
    const listener = createServer(); listener.listen(0, "127.0.0.1"); await once(listener, "listening");
    const port = listener.address().port; await new Promise(resolve => listener.close(resolve));
    origin = `http://127.0.0.1:${port}`;
    // Only explicit local settings reach the child; ignore ambient PGRST_*.
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("PGRST_")));
    server = spawn(binary, [], { windowsHide: true, stdio: "ignore", env: { ...env,
      PGRST_DB_URI: uri.href, PGRST_DB_SCHEMAS: "public", PGRST_DB_ANON_ROLE: "anon",
      PGRST_JWT_SECRET: secret, PGRST_SERVER_HOST: "127.0.0.1", PGRST_SERVER_PORT: String(port), PGRST_DB_POOL: "3" } });
    let ready = false;
    for (let i = 0; i < 100; i++) {
      assert.equal(server.exitCode, null, "Owned PostgREST exited during startup");
      try { const response = await request("/"); const data = await response.json(); ready = response.ok && data.info?.version === "14.5"; } catch { /* bounded startup */ }
      if (ready) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert(ready, "Owned PostgREST did not become ready");

    await t.test("new finding defaults and identifier-only acknowledgement", () => compare("finding", "new", [raw(minimal("new"))], { fresh: true }));
    await t.test("omitted existing creation time, enrichment and evidence are retained", async () => {
      await seedFinding("existing", { created_at: "2020-01-01T00:00:00.654321Z", enrichment: { original: true }, source: { original: true } });
      await compare("finding", "existing", [raw({ ...minimal("existing"), score: 42 })]);
    });
    await t.test("explicit null, false and empty arrays replace columns", async () => {
      await seedFinding("explicit", { issuer: "Old", suppressed: true, domains: ["synthetic.invalid"] });
      await compare("finding", "explicit", [raw({ ...minimal("explicit"), issuer: null, suppressed: false, domains: [] })]);
    });
    await t.test("microseconds and large JSONB numbers survive RPC text and HTTP writes", async () => {
      const input = Buffer.from(JSON.stringify({ ...minimal("precision"), created_at: "2023-07-08T16:02:03.123456+08:00" }).slice(0, -1) + ',"source":{"large":9007199254740993123456789,"fraction":1.0000000000000000001}}');
      const [row] = await compare("finding", "precision", [input]);
      assert(row.includes("9007199254740993123456789")); assert(row.includes("1.0000000000000000001")); assert(row.includes("08:02:03.123456"));
    });
    await t.test("source defaults and empty, Unicode and delimiter identity tuples", async () => {
      await seedFinding("sources");
      await compare("source", "sources", [["", ""], ["a|b", 'c"雪'], ["a", 'b|c"雪']].map(([source, source_ref]) => raw({ finding_id: "sources", source, source_ref, observed_at: "2026-01-01T00:00:00.654321Z" })), { fresh: true });
    });
    await t.test("partial source update preserves creation and replaces details", async () => {
      await seedFinding("partial");
      const row = { finding_id: "partial", source: "fixture", source_ref: "old", observed_at: "2026-01-01" };
      const response = await nativeUpsert("source", [raw({ ...row, details: { old: true }, created_at: "2020-01-01T00:00:00.123456Z" })]); assert(response.ok); await response.body.cancel();
      await compare("source", "partial", [raw({ ...row, details: { replacement: true } })]);
    });
    await t.test("unchanged HTTP upsert keeps exact original snapshot bytes", async () => {
      const existing = await seedFinding("unchanged");
      const prepared = await compare("finding", "unchanged", [raw(minimal("unchanged"))]);
      assert.deepEqual(prepared, existing);
    });
    await t.test("heterogeneous bulk column sets are rejected", () => rejection("finding", [raw(minimal("mixed-a")), raw({ ...minimal("mixed-b"), issuer: "extra" })], "PGRST102"));
    await t.test("same columns in different JSON order remain valid", async () => {
      await seedFinding("order");
      await compare("source", "order", [raw({ finding_id: "order", source: "a", source_ref: "a", observed_at: "2026-01-01" }), raw({ observed_at: "2026-01-01", source_ref: "b", source: "a", finding_id: "order" })], { fresh: true });
    });
    await t.test("duplicate primary keys reject the whole native batch", () => rejection("finding", [raw(minimal("duplicate")), raw(minimal("duplicate"))], "21000"));
    await t.test("missing required insert fields are rejected", () => rejection("finding", [raw({ id: "missing" })], "23502"));
    await t.test("explicit SQL null in a required column is rejected", () => rejection("finding", [raw({ ...minimal("null"), score: null })], "23502"));
    await t.test("invalid table check is rejected", () => rejection("finding", [raw({ ...minimal("check"), severity: "invalid" })], "23514"));
    await t.test("unknown columns are rejected", () => rejection("finding", [raw({ ...minimal("unknown"), invented: true })], "PGRST204"));
    await t.test("orphan sources fail their real foreign key", () => rejection("source", [raw({ finding_id: "absent", source: "a", source_ref: "a", observed_at: "2026-01-01" })], "23503"));
    await t.test("anonymous and authenticated JWTs cannot normalize or publish", async () => {
      for (const role of ["anon", "authenticated"]) for (const [path, body] of [
        ["/rpc/prepare_evidence_rows", { p_kind: "finding", p_existing: [], p_incoming: [JSON.stringify(minimal("denied"))] }],
        ["/rpc/publish_evidence_manifests", { p_publications: [] }]
      ]) { const response = await request(path, { role, body: JSON.stringify(body) }); assert.equal(response.status, role === "anon" ? 401 : 403); assert.equal((await response.json()).code, "42501"); }
    });
    await t.test("real HTTP manifests enforce suppression and hide source pointers", async () => {
      await seedFinding("visible"); await seedFinding("hidden", { suppressed: true });
      const pointer = { object: "a".repeat(64), offset: 0, length: 100 };
      for (const id of ["visible", "hidden"]) assert.equal(await store.compareAndSwap(id, 0, { suppressed: id === "hidden", finding: pointer, sources: pointer }), true);
      assert.deepEqual((await reader.get("visible")).finding, pointer); assert.equal(await reader.get("hidden"), null);
      assert.deepEqual((await reader.getMany(["hidden", "visible", "absent"])).map(r => r.id), ["visible"]);
      assert.equal((await store.get("hidden")).suppressed, true);
      const response = await request("/evidence_object_manifests?select=sources_pointer", { role: "anon" }); assert.equal(response.status, 401); assert.equal((await response.json()).code, "42501");
      assert.equal(await store.compareAndSwap("visible", 0, { suppressed: false, finding: pointer, sources: null }), false);
    });
    await t.test("HTTP batch CAS returns per-identity conflicts and atomic failure", async () => {
      await seedFinding("batch-a"); await seedFinding("batch-b");
      const next = { suppressed: false, finding: { object: "b".repeat(64), offset: 0, length: 100 }, sources: null };
      const entries = ["batch-b", "batch-a"].map(id => ({ id, expectedRevision: 0, next }));
      assert.deepEqual(await store.compareAndSwapMany(entries), [{ id: "batch-a", saved: true }, { id: "batch-b", saved: true }]);
      assert.deepEqual(await store.compareAndSwapMany(entries), [{ id: "batch-a", saved: false }, { id: "batch-b", saved: false }]);
      await assert.rejects(store.compareAndSwapMany([{ id: "batch-a", expectedRevision: 1, next }, { id: "batch-b", expectedRevision: 1, next: { ...next, suppressed: true } }]));
      assert.equal((await store.get("batch-a")).revision, 1);
    });
    await t.test("source adapter publishes through HTTP and makes identical retry a no-op", async () => {
      const [finding] = await seedFinding("adapter");
      const blobs = new Map(); let uploads = 0;
      const objects = { async read(key) { assert(blobs.has(key)); return Buffer.from(blobs.get(key)); }, async putIfAbsent(key, value) { uploads++; if (!blobs.has(key)) blobs.set(key, Buffer.from(value)); } };
      const repository = new EvidenceRepository({ objects, publicManifests: reader, privateManifests: store });
      await repository.publish("adapter", { finding, sources: [] }, 0);
      const incoming = [raw({ finding_id: "adapter", source: "fixture", source_ref: "first", observed_at: "2026-01-01T00:00:00.654321Z", details: { retained: true } })];
      const saved = await repository.upsertSourceRows("adapter", incoming);
      const after = uploads; const retried = await repository.upsertSourceRows("adapter", incoming);
      assert.equal(retried.revision, saved.revision); assert.equal(uploads, after);
      const snapshot = await repository.readPrivateSnapshot("adapter"); assert.equal(snapshot.sources.length, 1);
      assert(JSON.parse(snapshot.sources[0]).created_at); assert(snapshot.sources[0].includes(".654321"));
      assert.deepEqual(await repository.readPublicFinding("adapter"), finding);
    });
  } finally {
    if (server && server.exitCode === null) { const stopped = once(server, "exit"); server.kill(); await stopped; }
    await pool.end();
  }
});

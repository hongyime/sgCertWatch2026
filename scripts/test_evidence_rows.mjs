import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import pg from "pg";

globalThis.fetch = async () => { throw new Error("Provider requests forbidden in row fixtures"); };
const target = new URL(process.env.EVIDENCE_ROWS_DATABASE_URL || "invalid:");
assert(["127.0.0.1", "localhost", "[::1]"].includes(target.hostname));
assert(/^\/prawn_evidence_fixture_[a-z0-9]+$/.test(target.pathname));
let addresses = ["127.0.0.1", "::1"];
if (process.env.GITHUB_ACTIONS === "true") {
  const id = process.env.EVIDENCE_TEST_CONTAINER_ID;
  assert(/^[a-f0-9]{64}$/.test(id));
  const [container] = JSON.parse(execFileSync("docker", ["inspect", id], { encoding: "utf8" }));
  assert.equal(container.Id, id);
  assert.equal(container.Config.Image, "postgres:17.11");
  // This fixture uses a separate database in that exact Actions-owned service.
  assert(container.Config.Env.includes("POSTGRES_DB=prawn_evidence_fixture_ci"));
  addresses = Object.values(container.NetworkSettings.Networks).map(n => n.IPAddress).filter(Boolean);
  assert(addresses.length);
}
const pool = new pg.Pool({ connectionString: target.href, max: 3, connectionTimeoutMillis: 5000, statement_timeout: 8000 });
const relation = kind => kind === "finding" ? "findings" : "finding_sources";
const primary = kind => kind === "finding" ? ["id"] : ["finding_id", "source", "source_ref"];
const quote = value => '"' + value.replaceAll('"', '""') + '"';
const text = value => JSON.stringify(value);
const minimal = id => ({ id, observed_at: "2026-01-01T00:00:00.123456Z", registrable: "synthetic.invalid", score: 1, severity: "low" });

// Native table INSERT ... ON CONFLICT, with precisely the payload's columns.
// This is the operation used by the production PostgREST merge-duplicates call;
// values remain JSON text until PostgreSQL performs its real type/default checks.
async function nativeUpsert(client, kind, rawRows) {
  const table = relation(kind);
  const columns = Object.keys(JSON.parse(rawRows[0]));
  for (const raw of rawRows) assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), [...columns].sort());
  const names = columns.map(quote);
  const sql = `insert into public.${table} (${names})
    select ${names} from jsonb_populate_recordset(null::public.${table}, $1::jsonb)
    on conflict (${primary(kind).map(quote)}) do update set ${names.map(name => name + '=excluded.' + name)}
    returning row_to_json(${table})::text as raw`;
  return (await client.query(sql, ['[' + rawRows.join(',') + ']'])).rows.map(row => row.raw);
}

async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query("begin; set local role service_role; set local timezone='UTC'");
    return await fn(client);
  } finally {
    await client.query("rollback"); client.release();
  }
}

async function canonical(client, kind, existing, incoming) {
  return (await client.query("select public.prepare_evidence_rows($1,$2,$3) as rows", [kind, existing, incoming])).rows[0].rows;
}

async function compare(client, kind, existing, incoming) {
  const prepared = await canonical(client, kind, existing, incoming);
  const native = await nativeUpsert(client, kind, incoming);
  assert.equal(prepared.length, native.length);
  for (let i = 0; i < native.length; i++) {
    // Compare in PostgreSQL; JSON.parse would mask a precision regression.
    assert.equal((await client.query("select $1::jsonb = $2::jsonb as equal", [prepared[i], native[i]])).rows[0].equal, true);
  }
  return prepared;
}

async function errorCode(client, fn) {
  await client.query("savepoint expected_error");
  try { await fn(); return null; }
  catch (error) { return error.code; }
  finally { await client.query("rollback to savepoint expected_error"); }
}

await test("Evidence partial-row compatibility with native PostgreSQL", { timeout: 60000 }, async t => {
  try {
    const id = (await pool.query("select current_database() as db, inet_server_addr()::text as address")).rows[0];
    assert.equal(id.db, target.pathname.slice(1)); assert(addresses.includes(id.address.split('/')[0]));
    assert.equal((await pool.query("select to_regclass('public.findings') as table")).rows[0].table, null);
    for (const role of ["anon", "authenticated", "service_role"]) {
      if (!(await pool.query("select 1 from pg_roles where rolname=$1", [role])).rowCount) {
        await pool.query(`create role ${role} nologin ${role === "service_role" ? "bypassrls" : "nobypassrls"}`);
      }
    }
    const schema = await readFile(new URL("../supabase/schema.sql", import.meta.url), "utf8");
    await pool.query(schema.split("create table if not exists public.ct_source_runs")[0]);
    for (const [extension] of schema.matchAll(/^alter table public\.findings add column[^;]+;/gm)) await pool.query(extension);
    if (process.env.EVIDENCE_ROWS_BASELINE !== "1") {
      await pool.query(await readFile(new URL("../supabase/experimental/evidence-row-contracts.sql", import.meta.url), "utf8"));
    }

    await t.test("new finding uses native types, nulls, arrays and database defaults", () => transaction(async client => {
      const [row] = await compare(client, "finding", [], [text(minimal("new"))]);
      const parsed = JSON.parse(row);
      assert.deepEqual(parsed.domains, []); assert.deepEqual(parsed.enrichment, {});
      assert.equal(parsed.suppressed, false); assert.equal(parsed.issuer, null);
      assert(parsed.created_at); assert(row.includes(".123456"));
    }));
    await t.test("existing finding retains omitted created_at, evidence and enrichment", () => transaction(async client => {
      const existing = await nativeUpsert(client, "finding", [text({ ...minimal("existing"), created_at: "2020-03-04T00:00:00.654321Z", issuer: "Original issuer", enrichment: { retained: true }, source: { retained: true } })]);
      const [row] = await compare(client, "finding", existing, [text({ ...minimal("existing"), score: 45 })]);
      assert(row.includes("2020-03-04T00:00:00.654321+00:00"));
      assert.equal(JSON.parse(row).issuer, "Original issuer");
    }));
    await t.test("explicit null, false and empty arrays are genuine updates", () => transaction(async client => {
      const existing = await nativeUpsert(client, "finding", [text({ ...minimal("values"), issuer: "Previous", suppressed: true, domains: ["synthetic.invalid"] })]);
      const [row] = await compare(client, "finding", existing, [text({ ...minimal("values"), issuer: null, suppressed: false, domains: [] })]);
      assert.equal(JSON.parse(row).suppressed, false); assert.equal(JSON.parse(row).issuer, null);
    }));
    await t.test("explicit created_at is normalized by PostgreSQL without losing microseconds", () => transaction(async client => {
      const existing = await nativeUpsert(client, "finding", [text(minimal("time"))]);
      const [row] = await compare(client, "finding", existing, [text({ ...minimal("time"), created_at: "2023-07-08T16:02:03.123456+08:00" })]);
      assert(row.includes("2023-07-08T08:02:03.123456+00:00"));
    }));
    await t.test("JSONB integers and fractions keep all significant digits", () => transaction(async client => {
      const input = text(minimal("numbers")).slice(0, -1) + ',"source":{"large":9007199254740993123456789,"fraction":1.0000000000000000001}}';
      const [row] = await compare(client, "finding", [], [input]);
      assert(row.includes("9007199254740993123456789")); assert(row.includes("1.0000000000000000001"));
    }));
    await t.test("new source gets its native timestamp and details default", () => transaction(async client => {
      await nativeUpsert(client, "finding", [text(minimal("parent"))]);
      const [row] = await compare(client, "source", [], [text({ finding_id: "parent", source: "fixture", source_ref: "new", observed_at: "2026-01-01T00:00:00.654321Z" })]);
      assert.deepEqual(JSON.parse(row).details, {}); assert(JSON.parse(row).created_at);
    }));
    await t.test("source update preserves old creation time and omitted JSONB null", () => transaction(async client => {
      await nativeUpsert(client, "finding", [text(minimal("parent"))]);
      const existing = (await client.query(`insert into public.finding_sources values ('parent','fixture','old','2020-01-01','null'::jsonb,'2020-01-01T00:00:00.123456Z') returning row_to_json(finding_sources)::text as raw`)).rows.map(r => r.raw);
      const [row] = await compare(client, "source", existing, [text({ finding_id: "parent", source: "fixture", source_ref: "old", observed_at: "2026-01-02" })]);
      assert(row.includes("2020-01-01T00:00:00.123456+00:00")); assert.equal(JSON.parse(row).details, null);
    }));
    await t.test("unchanged upserts reuse the exact original serialized bytes", () => transaction(async client => {
      const incoming = [text(minimal("unchanged"))];
      const existing = await nativeUpsert(client, "finding", incoming);
      const prepared = await compare(client, "finding", existing, incoming);
      assert.equal(prepared[0], existing[0]);
    }));
    await t.test("provided source details replace the column instead of deep-merging", () => transaction(async client => {
      await nativeUpsert(client, "finding", [text(minimal("parent"))]);
      const base = { finding_id: "parent", source: "fixture", source_ref: "replace", observed_at: "2026-01-01" };
      const existing = await nativeUpsert(client, "source", [text({ ...base, details: { old: true } })]);
      const [row] = await compare(client, "source", existing, [text({ ...base, details: { replacement: true } })]);
      assert.deepEqual(JSON.parse(row).details, { replacement: true });
    }));
    await t.test("complete identity tuples preserve empty strings, delimiters, quotes and Unicode", () => transaction(async client => {
      await nativeUpsert(client, "finding", [text(minimal("parent"))]);
      const incoming = [
        { finding_id: "parent", source: "a|b", source_ref: 'c"雪', observed_at: "2026-01-01" },
        { finding_id: "parent", source: "a", source_ref: 'b|c"雪', observed_at: "2026-01-01" },
        { finding_id: "parent", source: "", source_ref: "", observed_at: "2026-01-01" },
        { finding_id: "parent", source: "", source_ref: "a", observed_at: "2026-01-01" },
        { finding_id: "parent", source: "a", source_ref: "", observed_at: "2026-01-01" }
      ].map(text);
      const prepared = await compare(client, "source", [], incoming); assert.equal(prepared.length, 5);
    }));

    for (const [name, patch, expected] of [
      ["omitted required insert field still fails on conflict", { id: "invalid", score: 2 }, "23502"],
      ["explicit null does not invoke a default", { ...minimal("invalid"), created_at: null }, "23502"],
      ["severity check remains enforced", { ...minimal("invalid"), severity: "invalid" }, "23514"],
      ["integer type conversion remains enforced", { ...minimal("invalid"), score: "not an integer" }, "22P02"],
      ["unknown fields cannot silently disappear", { ...minimal("invalid"), unexpected: true }, "42703"]
    ]) {
      await t.test(name, () => transaction(async client => {
        const existing = await nativeUpsert(client, "finding", [text(minimal("invalid"))]); const incoming = [text(patch)];
        const actual = await errorCode(client, () => canonical(client, "finding", existing, incoming));
        const native = await errorCode(client, () => nativeUpsert(client, "finding", incoming));
        assert.equal(actual, expected); assert.equal(native, expected);
      }));
    }
    await t.test("duplicate incoming keys fail like a native bulk upsert", () => transaction(async client => {
      const incoming = [text(minimal("duplicate")), text(minimal("duplicate"))];
      assert.equal(await errorCode(client, () => canonical(client, "finding", [], incoming)), "21000");
      assert.equal(await errorCode(client, () => nativeUpsert(client, "finding", incoming)), "21000");
    }));
    await t.test("source foreign key remains enforced", () => transaction(async client => {
      const incoming = [text({ finding_id: "missing", source: "fixture", source_ref: "reference", observed_at: "2026-01-01" })];
      assert.equal(await errorCode(client, () => canonical(client, "source", [], incoming)), "23503");
      assert.equal(await errorCode(client, () => nativeUpsert(client, "source", incoming)), "23503");
    }));
    await t.test("anonymous and authenticated callers cannot prepare private evidence", async () => {
      for (const role of ["anon", "authenticated"]) await transaction(async client => {
        await client.query(`set local role ${role}`);
        assert.equal(await errorCode(client, () => canonical(client, "finding", [], [text(minimal("denied"))])), "42501");
      });
    });
    await t.test("the 10000-row source limit fits the configured database deadline", () => transaction(async client => {
      await nativeUpsert(client, "finding", [text(minimal("large-parent"))]);
      const existing = (await client.query(`insert into public.finding_sources(finding_id,source,source_ref,observed_at)
        select 'large-parent','fixture','ref-' || n,'2026-01-01'::timestamptz from generate_series(1,10000) n
        returning row_to_json(finding_sources)::text as raw`)).rows.map(r => r.raw);
      const incoming = [text({ finding_id: "large-parent", source: "fixture", source_ref: "ref-10000", observed_at: "2026-01-01" })];
      const started = performance.now(); const prepared = await canonical(client, "source", existing, incoming);
      assert.equal(prepared[0], existing[9999]);
      console.log("EVIDENCE_ROW_LIMIT_MS", Math.round(performance.now() - started));
    }));
  } finally { await pool.end(); }
});

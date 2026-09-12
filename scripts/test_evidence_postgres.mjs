import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import pg from "pg";
import { EvidenceRepository } from "../lib/storage/evidence-repository.js";

globalThis.fetch = async () => { throw new Error("Live provider requests forbidden in PostgreSQL fixtures"); };
const connectionString = process.env.EVIDENCE_TEST_DATABASE_URL;
if (!connectionString) throw new Error("EVIDENCE_TEST_DATABASE_URL must name a disposable loopback fixture database");
const target = new URL(connectionString);
if (!["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)
    || !/^\/prawn_evidence_fixture_[a-z0-9]+$/.test(target.pathname)) {
  throw new Error("Refusing database outside the disposable loopback fixture scope");
}
let serverAddresses = ["127.0.0.1", "::1"];
if (process.env.GITHUB_ACTIONS === "true") {
  // A loopback port published by Actions reaches the service's bridge address.
  // Bind the exception to the exact Actions-owned container, not a broad private
  // IP range or a user-supplied address. This inspects an existing CI service.
  const containerId = process.env.EVIDENCE_TEST_CONTAINER_ID;
  assert(/^[a-f0-9]{64}$/.test(containerId), "Expected the Actions fixture container ID");
  const [container] = JSON.parse(execFileSync("docker", ["inspect", containerId], { encoding: "utf8" }));
  assert.equal(container.Id, containerId);
  assert(container.Config.Env.includes("POSTGRES_DB=" + target.pathname.slice(1)));
  assert.equal(container.Config.Image, "postgres:17.11");
  serverAddresses = Object.values(container.NetworkSettings.Networks).map(network => network.IPAddress).filter(Boolean);
  assert(serverAddresses.length > 0);
}
const pool = new pg.Pool({ connectionString, max: 4, connectionTimeoutMillis: 5000, statement_timeout: 8000 });
const bytes = (value) => Buffer.from(JSON.stringify(value));
const finding = (id) => bytes({ id, suppressed: false, observed_at: "2026-01-01T00:00:00Z", domains: ["synthetic.invalid"], score: 1 });
const source = (id, ref) => Buffer.from(`{"finding_id":${JSON.stringify(id)},"source":"fixture","source_ref":${JSON.stringify(ref)},"observed_at":"2026-01-01T00:00:00.654321Z","details":{"large":9007199254740993123456789,"fraction":1.0000000000000000001},"created_at":"2026-01-01T00:00:00.123456Z"}`);

async function asRole(role, sql, params = []) {
  assert(["anon", "authenticated", "service_role"].includes(role));
  const client = await pool.connect();
  try {
    await client.query("begin"); await client.query(`set local role ${role}`);
    const result = await client.query(sql, params); await client.query("commit"); return result;
  } catch (error) { await client.query("rollback"); throw error; }
  finally { client.release(); }
}

function stores() {
  const blobs = new Map(); const events = [];
  const objects = {
    async read(key) { events.push("object_read"); assert(blobs.has(key)); return Buffer.from(blobs.get(key)); },
    async putIfAbsent(key, value) { events.push("object_put"); if (!blobs.has(key)) blobs.set(key, Buffer.from(value)); }
  };
  const publicManifests = { async get(id) {
    events.push("anon_authorization");
    const { rows } = await asRole("anon", "select finding_id,revision,finding_pointer from public.evidence_object_manifests where finding_id=$1", [id]);
    return rows.length ? { id: rows[0].finding_id, suppressed: false, finding: rows[0].finding_pointer } : null;
  } };
  publicManifests.getMany = async ids => {
    events.push("anon_batch_authorization");
    const { rows } = await asRole("anon", "select * from public.read_evidence_manifests($1)", [ids]);
    return rows.map(row => ({ id: row.finding_id, suppressed: false, finding: row.finding_pointer }));
  };
  const privateManifests = {
    async get(id) {
      const { rows } = await asRole("service_role", "select m.*,f.suppressed from public.evidence_object_manifests m join public.findings f on f.id=m.finding_id where finding_id=$1", [id]);
      if (!rows.length) return null;
      const row = rows[0]; return { id: row.finding_id, revision: Number(row.revision), suppressed: row.suppressed, finding: row.finding_pointer, sources: row.sources_pointer };
    },
    async compareAndSwap(id, revision, next) {
      const { rows } = await asRole("service_role", "select public.publish_evidence_manifest($1,$2,$3,$4,$5) as saved",
        [id, revision, next.suppressed, next.finding, next.sources]); return rows[0].saved;
    }
  };
  return { blobs, events, objects, publicManifests, privateManifests,
    repository: new EvidenceRepository({ objects, publicManifests, privateManifests }) };
}

async function seed(id) {
  await pool.query("insert into public.findings(id,observed_at,registrable,score,severity) values ($1,'2026-01-01','synthetic.invalid',1,'low')", [id]);
}

await test("PostgreSQL evidence manifest contract", { timeout: 60000 }, async (t) => {
  try {
    const identity = (await pool.query("select current_database() as db,inet_server_addr()::text as address,current_setting('server_version') as version")).rows[0];
    assert.equal(identity.db, target.pathname.slice(1)); assert(serverAddresses.includes(identity.address.split("/")[0]));
    assert.equal((await pool.query("select to_regclass('public.findings') as existing")).rows[0].existing, null, "Fixture database must be empty");
    for (const role of ["anon", "authenticated", "service_role"]) {
      if (!(await pool.query("select 1 from pg_roles where rolname=$1", [role])).rowCount) {
        await pool.query(`create role ${role} nologin ${role === "service_role" ? "bypassrls" : "nobypassrls"}`);
      }
    }
    const schema = await readFile(new URL("../supabase/schema.sql", import.meta.url), "utf8");
    await pool.query(schema.split("create table if not exists public.ct_source_runs")[0]);
    await pool.query(await readFile(new URL("../supabase/experimental/evidence-manifests.sql", import.meta.url), "utf8"));
    await t.test("complete original bytes survive publication through real SQL CAS", async () => {
      const id = "pg-roundtrip"; await seed(id); const store = stores(); const raw = source(id, "ref|original");
      await store.repository.publish(id, { finding: finding(id), sources: [raw] }, 0);
      const saved = await store.repository.readPrivateSnapshot(id);
      assert.equal(saved.manifest.revision, 1); assert.deepEqual(saved.finding, finding(id)); assert.deepEqual(saved.sources, [raw]);
      assert.deepEqual(await store.repository.readPublicFinding(id), finding(id));
    });
    await t.test("anon cannot read source pointers, mutate manifests or execute publication RPC", async () => {
      for (const sql of ["select sources_pointer from public.evidence_object_manifests", "update public.evidence_object_manifests set revision=revision+1", "select public.publish_evidence_manifest('pg-roundtrip',1,false,null,null)"]) {
        await assert.rejects(asRole("anon", sql), error => error.code === "42501");
      }
      await assert.rejects(asRole("authenticated", "select finding_id from public.evidence_object_manifests"), error => error.code === "42501");
    });
    await t.test("suppression immediately denies manifest and prevents object retrieval", async () => {
      const id = "pg-suppression"; await seed(id); const store = stores();
      await store.repository.publish(id, { finding: finding(id), sources: [source(id, "private")] }, 0);
      await pool.query("update public.findings set suppressed=true where id=$1", [id]); store.events.length = 0;
      assert.equal(await store.repository.readPublicFinding(id), null); assert.deepEqual(store.events, ["anon_authorization"]);
      store.events.length = 0;
      assert.deepEqual(await store.repository.readPublicFindings([id]), []); assert.deepEqual(store.events, ["anon_batch_authorization"]);
      const before = await store.repository.readPrivateSnapshot(id);
      const updated = await store.repository.upsertSources(id, [source(id, "new-private-sighting")]);
      assert.deepEqual(updated.finding, before.manifest.finding); assert.equal(updated.suppressed, true);
      assert.equal((await store.repository.readPrivateSnapshot(id)).sources.length, 2);
      assert.equal(await store.repository.readPublicFinding(id), null);
    });
    await t.test("overlapping source writers rebase without dropping either original row", async () => {
      const id = "pg-concurrent"; await seed(id); const store = stores();
      await store.repository.publish(id, { finding: finding(id), sources: [source(id, "original")] }, 0);
      const get = store.privateManifests.get; let firstReads = 0; let release;
      const barrier = new Promise(resolve => { release = resolve; });
      store.privateManifests.get = async key => {
        const result = await get(key);
        if (firstReads < 2) { firstReads++; if (firstReads === 2) release(); await barrier; }
        return result;
      };
      await Promise.all([store.repository.upsertSources(id, [source(id, "first")]), store.repository.upsertSources(id, [source(id, "second")])]);
      const saved = await store.repository.readPrivateSnapshot(id);
      assert.equal(firstReads, 2); assert.equal(saved.manifest.revision, 3); assert.equal(saved.sources.length, 3);
      for (const ref of ["original", "first", "second"]) assert(saved.sources.some(row => row.equals(source(id, ref))));
    });
    await t.test("stale revision and visibility changes cannot publish new pointers", async () => {
      const id = "pg-stale"; await seed(id); const store = stores();
      const initial = await store.repository.publish(id, { finding: finding(id), sources: [] }, 0);
      assert.equal(await store.repository.publish(id, { finding: finding(id), sources: [source(id, "stale")] }, 0), null);
      await pool.query("update public.findings set suppressed=true where id=$1", [id]);
      await assert.rejects(store.repository.publish(id, { finding: finding(id), sources: [source(id, "hidden")] }, 1), /visibility changed/);
      const persisted = await store.privateManifests.get(id); assert.equal(persisted.revision, 1); assert.deepEqual(persisted.finding, initial.finding); assert.equal(persisted.sources, null);
    });
    await t.test("failed object upload leaves the committed database revision unchanged", async () => {
      const id = "pg-upload-failure"; await seed(id); const store = stores();
      await store.repository.publish(id, { finding: finding(id), sources: [source(id, "kept")] }, 0);
      store.objects.putIfAbsent = async () => { throw new Error("Synthetic upload failure"); };
      await assert.rejects(store.repository.upsertSources(id, [source(id, "new")]), /upload failure/);
      const saved = await store.repository.readPrivateSnapshot(id); assert.equal(saved.manifest.revision, 1); assert.deepEqual(saved.sources, [source(id, "kept")]);
    });
    await t.test("invalid pointer constraints fail transaction without replacing manifest", async () => {
      const row = (await pool.query("select * from public.evidence_object_manifests where finding_id='pg-roundtrip'")).rows[0];
      for (const pointer of [{ object: "../escape", offset: 0, length: 100 }, { object: "a".repeat(64), offset: 0.5, length: 100 }, { object: "a".repeat(64), offset: 0, length: 4194305 }]) {
        await assert.rejects(asRole("service_role", "update public.evidence_object_manifests set finding_pointer=$1 where finding_id='pg-roundtrip'", [pointer]), error => error.code === "23514");
      }
      assert.deepEqual((await pool.query("select * from public.evidence_object_manifests where finding_id='pg-roundtrip'")).rows[0], row);
    });
    console.log("EVIDENCE_POSTGRES_IDENTITY " + JSON.stringify(identity));
  } finally { await pool.end(); }
});

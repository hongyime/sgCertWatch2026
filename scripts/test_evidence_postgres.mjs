import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import pg from "pg";
import { EvidenceRepository } from "../lib/storage/evidence-repository.js";
import { privateManifestStore, publicManifestReader } from "../lib/storage/supabase-manifests.js";

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
    const { rows } = await asRole("anon", "select finding_id,revision,public.unpack_evidence_pointer(finding_pointer) as finding_pointer from public.evidence_object_manifests where finding_id=$1", [id]);
    return rows.length ? { id: rows[0].finding_id, suppressed: false, finding: rows[0].finding_pointer } : null;
  } };
  publicManifests.getMany = async ids => {
    events.push("anon_batch_authorization");
    const { rows } = await asRole("anon", "select * from public.read_evidence_manifests($1)", [ids]);
    return rows.map(row => ({ id: row.finding_id, suppressed: false, finding: row.finding_pointer }));
  };
  const privateManifests = {
    async prepareRows(kind, existing, incoming) {
      events.push("normalize_rows");
      const { rows } = await asRole("service_role", "select public.prepare_evidence_rows($1,$2,$3) as prepared",
        [kind, existing.map(row => row.toString()), incoming.map(row => row.toString())]);
      return rows[0].prepared.map(row => Buffer.from(row));
    },
    async get(id) {
      const { rows } = await asRole("service_role", "select m.finding_id,m.revision,public.unpack_evidence_pointer(m.finding_pointer) as finding_pointer,public.unpack_evidence_pointer(m.sources_pointer) as sources_pointer,f.suppressed from public.evidence_object_manifests m join public.findings f on f.id=m.finding_id where finding_id=$1", [id]);
      if (!rows.length) return null;
      const row = rows[0]; return { id: row.finding_id, revision: Number(row.revision), suppressed: row.suppressed, finding: row.finding_pointer, sources: row.sources_pointer };
    },
    async compareAndSwap(id, revision, next) {
      const { rows } = await asRole("service_role", "select public.publish_evidence_manifest($1,$2,$3,$4,$5) as saved",
        [id, revision, next.suppressed, next.finding, next.sources]); return rows[0].saved;
    },
    async compareAndSwapMany(entries) {
      const payload = entries.map(entry => ({ id: entry.id, expected_revision: entry.expectedRevision,
        suppressed: entry.next.suppressed, finding_pointer: entry.next.finding, sources_pointer: entry.next.sources }));
      const { rows } = await asRole("service_role", "select * from public.publish_evidence_manifests($1)", [JSON.stringify(payload)]);
      return rows.map(row => ({ id: row.finding_id, saved: row.saved }));
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
    await pool.query(await readFile(new URL("../supabase/experimental/evidence-row-contracts.sql", import.meta.url), "utf8"));
    await t.test("partial source writes preserve timestamps and precision through real normalization and CAS", async () => {
      const id = "partial-upsert"; await seed(id); const store = stores();
      const original = source(id, "old");
      await store.repository.publish(id, { finding: finding(id), sources: [original] }, 0);
      const pointer = (await store.privateManifests.get(id)).finding;
      const partial = bytes({ finding_id: id, source: "fixture", source_ref: "old", observed_at: "2026-02-03T16:00:00.123456+08:00" });
      await store.repository.upsertSourceRows(id, [partial]);
      const saved = await store.repository.readPrivateSnapshot(id);
      assert.deepEqual(saved.manifest.finding, pointer);
      const exact = (await pool.query(`select $1::jsonb->'details' = $2::jsonb->'details' as details,
        $1::jsonb->>'created_at' = $2::jsonb->>'created_at' as created,
        ($1::jsonb->>'observed_at')::timestamptz = '2026-02-03T08:00:00.123456Z'::timestamptz as observed`,
      [saved.sources[0].toString(), original.toString()])).rows[0];
      assert.deepEqual(exact, { details: true, created: true, observed: true });
      store.events.length = 0;
      const retry = await store.repository.upsertSourceRows(id, [partial]);
      assert.equal(retry.revision, saved.manifest.revision);
      assert.equal(store.events.filter(event => event === "object_put").length, 0);
    });
    await t.test("empty source identity fields survive normalization and publication", async () => {
      const id = "partial-empty"; await seed(id); const store = stores();
      await store.repository.publish(id, { finding: finding(id), sources: [] }, 0);
      const rows = [["", ""], ["fixture", ""], ["", "ref"]].map(([name, ref]) =>
        bytes({ finding_id: id, source: name, source_ref: ref, observed_at: "2026-02-03" }));
      await store.repository.upsertSourceRows(id, rows);
      const saved = await store.repository.readPrivateSnapshot(id);
      assert.deepEqual(saved.sources.map(raw => { const row = JSON.parse(raw); return [row.source, row.source_ref]; }), [["", ""], ["fixture", ""], ["", "ref"]]);
      const retry = await store.repository.upsertSourceRows(id, rows);
      assert.equal(retry.revision, saved.manifest.revision);
    });
    await t.test("concurrent partial source upserts re-normalize against the winning snapshot", async () => {
      const id = "partial-concurrent"; await seed(id); const store = stores(); const original = source(id, "original");
      await store.repository.publish(id, { finding: finding(id), sources: [original] }, 0);
      const get = store.privateManifests.get; let reads = 0; let release;
      const barrier = new Promise(resolve => { release = resolve; });
      store.privateManifests.get = async key => {
        const current = await get(key);
        if (reads < 2) { reads++; if (reads === 2) release(); await barrier; }
        return current;
      };
      const partial = ref => bytes({ finding_id: id, source: "fixture", source_ref: ref, observed_at: "2026-02-03" });
      await Promise.all([store.repository.upsertSourceRows(id, [partial("first")]), store.repository.upsertSourceRows(id, [partial("second")])]);
      const saved = await store.repository.readPrivateSnapshot(id);
      assert.equal(saved.manifest.revision, 3); assert.equal(saved.sources.length, 3);
      assert.deepEqual(saved.sources.find(raw => JSON.parse(raw).source_ref === "original"), original);
      assert.deepEqual(saved.sources.map(raw => JSON.parse(raw).source_ref).sort(), ["first", "original", "second"]);
      assert.equal(store.events.filter(event => event === "normalize_rows").length, 3);
      for (const raw of saved.sources.filter(raw => JSON.parse(raw).source_ref !== "original")) {
        assert.equal((await pool.query("select ($1::jsonb->>'created_at')::timestamptz between now()-interval '1 minute' and now() as recent", [raw.toString()])).rows[0].recent, true);
      }
    });
    await t.test("failed normalization and lease loss cannot publish or upload source updates", async () => {
      const id = "partial-failure"; await seed(id); const store = stores();
      await store.repository.publish(id, { finding: finding(id), sources: [source(id, "old")] }, 0);
      const before = await store.privateManifests.get(id); store.events.length = 0;
      await assert.rejects(store.repository.upsertSourceRows(id, [bytes({ finding_id: id, source: "fixture", source_ref: "new" })]), error => error.code === "23502");
      assert.equal(store.events.filter(event => event === "object_put").length, 0);
      let owned = true; const prepare = store.privateManifests.prepareRows;
      store.privateManifests.prepareRows = async (...args) => { const rows = await prepare(...args); owned = false; return rows; };
      await assert.rejects(store.repository.upsertSourceRows(id, [bytes({ finding_id: id, source: "fixture", source_ref: "new", observed_at: "2026-02-03" })],
        { assertOwned: () => { if (!owned) throw new Error("fixture lease lost"); } }), /lease lost/);
      assert.equal(store.events.filter(event => event === "object_put").length, 0);
      assert.deepEqual(await store.privateManifests.get(id), before);
    });
    await t.test("binary pointers retain all digest bits and frame boundaries", async () => {
      for (const pointer of [
        { object: "00".repeat(32), offset: 0, length: 46 },
        { object: "ff".repeat(32), offset: 66051, length: 1029 },
        { object: "ab".repeat(32), offset: 4194258, length: 46 },
        { object: "01".repeat(32), offset: 0, length: 4194304 }
      ]) {
        const { rows } = await asRole("service_role", "select public.pack_evidence_pointer($1) as packed,public.unpack_evidence_pointer(public.pack_evidence_pointer($1)) as unpacked", [pointer]);
        const expected = Buffer.alloc(40); Buffer.from(pointer.object, "hex").copy(expected);
        expected.writeUInt32BE(pointer.offset, 32); expected.writeUInt32BE(pointer.length, 36);
        assert.deepEqual(rows[0].packed, expected); assert.deepEqual(rows[0].unpacked, pointer);
      }
      const numeric = '{"object":"' + "a".repeat(64) + '","offset":1.0,"length":46.0}';
      assert.deepEqual((await asRole("service_role", "select public.unpack_evidence_pointer(public.pack_evidence_pointer($1)) as pointer", [numeric])).rows[0].pointer,
        { object: "a".repeat(64), offset: 1, length: 46 });
      await assert.rejects(asRole("service_role", "select public.pack_evidence_pointer($1)",
        [{ object: "a".repeat(64), offset: 1, length: 46, unrecognized: "must not disappear" }]), error => error.code === "22023");
    });
    await t.test("malformed binary pointers cannot enter storage or be decoded", async () => {
      const id = "pg-invalid-binary"; await seed(id);
      const valid = Buffer.alloc(40); valid.writeUInt32BE(46, 36);
      const beyond = Buffer.from(valid); beyond.writeUInt32BE(0xffffffff, 32);
      const lengthOverflow = Buffer.from(valid); lengthOverflow.writeUInt32BE(0xffffffff, 36);
      for (const invalid of [Buffer.alloc(39), Buffer.alloc(41), Buffer.alloc(40), beyond, lengthOverflow]) {
        await assert.rejects(asRole("service_role", "insert into public.evidence_object_manifests values ($1,1,$2,null)", [id, invalid]), error => error.code === "23514");
        await assert.rejects(asRole("anon", "select public.unpack_evidence_pointer($1)", [invalid]), error => error.code === "22023");
      }
      assert.equal((await pool.query("select count(*)::integer as n from public.evidence_object_manifests where finding_id=$1", [id])).rows[0].n, 0);
    });
    await t.test("complete original bytes survive publication through real SQL CAS", async () => {
      const id = "pg-roundtrip"; await seed(id); const store = stores(); const raw = source(id, "ref|original");
      await store.repository.publish(id, { finding: finding(id), sources: [raw] }, 0);
      const saved = await store.repository.readPrivateSnapshot(id);
      assert.equal(saved.manifest.revision, 1); assert.deepEqual(saved.finding, finding(id)); assert.deepEqual(saved.sources, [raw]);
      assert.deepEqual(await store.repository.readPublicFinding(id), finding(id));
    });
    await t.test("PostgreSQL JSON output decodes through the actual REST client boundary", async () => {
      const id = "pg-roundtrip";
      const { rows } = await pool.query("select to_jsonb(m) || jsonb_build_object('findings',jsonb_build_object('suppressed',f.suppressed)) as value from public.evidence_object_manifests m join public.findings f on f.id=m.finding_id where finding_id=$1", [id]);
      assert.match(rows[0].value.finding_pointer, /^\\x[a-f0-9]{80}$/);
      const fetchImpl = async () => Response.json([rows[0].value]);
      const publicRow = await publicManifestReader({ url: "https://fixture.invalid", anonKey: "synthetic-anon", fetchImpl }).get(id);
      const privateRow = await privateManifestStore({ url: "https://fixture.invalid", serviceKey: "synthetic-service", fetchImpl }).get(id);
      const decoded = (await pool.query("select public.unpack_evidence_pointer(finding_pointer) as finding,public.unpack_evidence_pointer(sources_pointer) as sources from public.evidence_object_manifests where finding_id=$1", [id])).rows[0];
      assert.deepEqual(publicRow.finding, decoded.finding); assert.equal(publicRow.sources, undefined);
      assert.deepEqual(privateRow.finding, decoded.finding); assert.deepEqual(privateRow.sources, decoded.sources);
    });
    await t.test("anon cannot read source pointers, mutate manifests or execute publication RPC", async () => {
      for (const sql of ["select sources_pointer from public.evidence_object_manifests", "update public.evidence_object_manifests set revision=revision+1", "select public.publish_evidence_manifest('pg-roundtrip',1,false,null,null)"]) {
        await assert.rejects(asRole("anon", sql), error => error.code === "42501");
      }
      await assert.rejects(asRole("authenticated", "select finding_id from public.evidence_object_manifests"), error => error.code === "42501");
      for (const role of ["anon", "authenticated"]) await assert.rejects(asRole(role, "select * from public.publish_evidence_manifests('[]')"), error => error.code === "42501");
    });
    await t.test("packed batch publication preserves rows and reports revision conflicts", async () => {
      const store = stores();
      const entries = [];
      for (let index = 0; index < 200; index++) {
        const id = `pg-batch-${index}`; await seed(id);
        entries.push({ findingId: id, finding: finding(id), sources: [source(id, "original")], expectedRevision: 0 });
      }
      const result = await store.repository.publishBatch(entries);
      assert.equal(result.length, 200); assert(result.every(r => r.saved)); assert.equal(store.blobs.size, 2);
      for (const index of [0, 99, 199]) {
        const saved = await store.repository.readPrivateSnapshot(entries[index].findingId);
        assert.deepEqual(saved.finding, entries[index].finding); assert.deepEqual(saved.sources, entries[index].sources);
      }
      const retry = await store.repository.publishBatch([entries[0], { ...entries[1], expectedRevision: 1 }]);
      assert.deepEqual(retry.map(r => r.saved), [false, true]);
      assert.equal((await store.privateManifests.get(entries[0].findingId)).revision, 1);
      assert.equal((await store.privateManifests.get(entries[1].findingId)).revision, 2);
    });
    await t.test("a later batch validation failure rolls back earlier manifest writes", async () => {
      const a = "pg-atomic-a", b = "pg-atomic-b"; await seed(a); await seed(b);
      const pointer = { object: "a".repeat(64), offset: 0, length: 46 };
      const first = { id: a, expected_revision: 0, suppressed: false, finding_pointer: pointer, sources_pointer: null };
      const second = { ...first, id: b, finding_pointer: { ...pointer, length: 0 } };
      await assert.rejects(asRole("service_role", "select * from public.publish_evidence_manifests($1)", [JSON.stringify([first, second])]), error => error.code === "22023");
      assert.equal((await pool.query("select count(*)::integer as n from public.evidence_object_manifests where finding_id=any($1)", [[a, b]])).rows[0].n, 0);
      await assert.rejects(asRole("service_role", "select * from public.publish_evidence_manifests($1)", [JSON.stringify([first, first])]), error => error.code === "22023");
      assert.equal((await pool.query("select count(*)::integer as n from public.evidence_object_manifests where finding_id=$1", [a])).rows[0].n, 0);
    });
    await t.test("opposite-order concurrent batches serialize without lost updates or deadlock", async () => {
      const ids = ["pg-overlap-a", "pg-overlap-b"]; for (const id of ids) await seed(id);
      const store = stores();
      const first = ids.map(id => ({ findingId: id, finding: finding(id), sources: [source(id, "first")], expectedRevision: 0 }));
      const second = [...ids].reverse().map(id => ({ findingId: id, finding: finding(id), sources: [source(id, "second")], expectedRevision: 0 }));
      const results = await Promise.all([store.repository.publishBatch(first), store.repository.publishBatch(second)]);
      const savedCounts = results.map(rows => rows.filter(row => row.saved).length).sort();
      assert.deepEqual(savedCounts, [0, 2]);
      const winner = results[0].every(row => row.saved) ? "first" : "second";
      for (const id of ids) {
        const snapshot = await store.repository.readPrivateSnapshot(id);
        assert.equal(snapshot.manifest.revision, 1); assert.deepEqual(snapshot.sources, [source(id, winner)]);
      }
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

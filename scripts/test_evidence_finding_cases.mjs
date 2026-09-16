import assert from "node:assert/strict";
import { EvidenceRepository } from "../lib/storage/evidence-repository.js";
import { evidenceIngestWriter, upsertFindingRows } from "../lib/storage/evidence-ingest-writer.js";
import { runIngest } from "./run-ingest.mjs";
import { privateManifestStore } from "../lib/storage/supabase-manifests.js";

export async function findingWriterCases(t, { pool, store, reader, raw, minimal, request, seedFinding, originals, loopbackFetch, tokens }) {
  const memory = (hook = async () => {}) => {
    const blobs = new Map(); const stats = { uploads: 0, reads: 0 };
    return { stats, async read(key) { stats.reads++; assert(blobs.has(key)); return Buffer.from(blobs.get(key)); },
      async putIfAbsent(key, value) { stats.uploads++; await hook(); if (!blobs.has(key)) blobs.set(key, Buffer.from(value)); } };
  };
  const repository = (objects, service = store) => new EvidenceRepository({ objects, privateManifests: service, publicManifests: reader });
  const sighting = (id, source = "fixture", ref = "old") => ({ finding_id: id, source, source_ref: ref, observed_at: "2026-01-01T00:00:00.654321Z", details: { retained: true } });
  const insertSources = async rows => { const response = await request("/finding_sources", { body: JSON.stringify(rows) }); assert(response.ok, await response.text()); };

  await t.test("finding writer packs 200 new rows with one context/normalize/commit request each", async () => {
    const calls = {}; const service = { ...store };
    for (const name of ["assertLease", "readWriteContext", "prepareRows", "commitFindings"]) service[name] = async (...args) => { calls[name] = (calls[name] || 0) + 1; return store[name](...args); };
    const objects = memory(); const repo = repository(objects, service);
    const rows = Array.from({ length: 200 }, (_, i) => raw(minimal("writer-batch-" + i)));
    assert.deepEqual(await upsertFindingRows(repo, rows), rows.map(row => ({ id: JSON.parse(row).id })));
    assert.deepEqual(calls, { assertLease: 1, readWriteContext: 1, prepareRows: 1, commitFindings: 1 });
    assert.equal(objects.stats.uploads, 1); assert.equal(objects.stats.reads, 1);
    assert.equal((await repo.readPrivateSnapshot("writer-batch-199")).manifest.revision, 1);
    const before = { ...objects.stats };
    await upsertFindingRows(repo, rows);
    assert.equal(objects.stats.uploads, before.uploads); assert.equal(objects.stats.reads, before.reads + 1);
    assert.equal((await store.get("writer-batch-0")).revision, 1);
  });
  await t.test("first finding snapshot retains all old sightings, timestamps and large JSONB numbers", async () => {
    const id = "writer-bootstrap";
    await seedFinding(id, { created_at: "2020-01-01T00:00:00.123456Z", enrichment: { original: true } });
    await pool.query("update public.findings set source=$2::jsonb where id=$1", [id, '{"large":9007199254740993123456789,"fraction":1.0000000000000000001}']);
    await insertSources([sighting(id, "a|b", "c"), sighting(id, "a", "b|c")]);
    const old = await originals("source", id); const repo = repository(memory());
    await upsertFindingRows(repo, [raw({ ...minimal(id), score: 42 })]);
    const snapshot = await repo.readPrivateSnapshot(id);
    assert(snapshot.finding.includes("9007199254740993123456789")); assert(snapshot.finding.includes("1.0000000000000000001"));
    assert(snapshot.finding.includes("2020-01-01T00:00:00.123456")); assert.equal(JSON.parse(snapshot.finding).enrichment.original, true);
    assert.deepEqual(snapshot.sources.map(String).sort(), old.map(String).sort());
    const pointer = snapshot.manifest.sources;
    await upsertFindingRows(repo, [raw({ ...minimal(id), score: 43 })]);
    assert.deepEqual((await store.get(id)).sources, pointer);
  });
  await t.test("a relational edit during upload retries and preserves omitted suppression/enrichment", async () => {
    const id = "writer-race-row"; await seedFinding(id); let changed = false;
    const objects = memory(async () => { if (!changed) { changed = true; await pool.query("update public.findings set suppressed=true,enrichment='{}'::jsonb where id=$1", [id]); } });
    const repo = repository(objects); await upsertFindingRows(repo, [raw({ ...minimal(id), score: 7 })]);
    assert.equal(JSON.parse((await repo.readPrivateSnapshot(id)).finding).suppressed, true);
    assert.equal(await reader.get(id), null); assert.equal((await store.get(id)).revision, 1);
  });
  await t.test("a newly arriving legacy sighting during bootstrap is included after retry", async () => {
    const id = "writer-race-source"; await seedFinding(id); await insertSources([sighting(id)]); let changed = false;
    const repo = repository(memory(async () => { if (!changed) { changed = true; await insertSources([sighting(id, "late", "new")]); } }));
    await upsertFindingRows(repo, [raw(minimal(id))]);
    assert.equal((await repo.readPrivateSnapshot(id)).sources.length, 2);
  });
  await t.test("a concurrent source manifest update survives finding retry", async () => {
    const id = "writer-race-manifest"; const objects = memory(); const repo = repository(objects);
    await upsertFindingRows(repo, [raw(minimal(id))]); let changed = false;
    const service = { ...store, async commitFindings(entries) {
      if (!changed) { changed = true; await repo.upsertSourceRows(id, [raw(sighting(id))]); }
      return store.commitFindings(entries);
    } };
    await upsertFindingRows(repository(objects, service), [raw({ ...minimal(id), score: 8 })]);
    const result = await repo.readPrivateSnapshot(id); assert.equal(result.sources.length, 1); assert.equal(JSON.parse(result.finding).score, 8);
  });
  await t.test("exhausted conflicts never overwrite a concurrent row", async () => {
    const id = "writer-conflict"; await seedFinding(id);
    const service = { ...store, async commitFindings(entries) {
      await pool.query("update public.findings set score=score+1 where id=$1", [id]); return store.commitFindings(entries);
    } };
    await assert.rejects(upsertFindingRows(repository(memory(), service), [raw({ ...minimal(id), score: 90 })], { maxConflicts: 1 }), /retry limit/);
    assert.equal(await store.get(id), null); assert.equal(JSON.parse((await originals("finding", id))[0]).score, 3);
  });
  await t.test("an existing manifest refreshes after a legacy edit even if incoming fields are unchanged", async () => {
    const id = "writer-stale-body"; const repo = repository(memory());
    await upsertFindingRows(repo, [raw(minimal(id))]);
    await pool.query("update public.findings set suppressed=true,source=$2::jsonb where id=$1", [id, '{"large":9007199254740993123456789}']);
    await upsertFindingRows(repo, [raw(minimal(id))]);
    const snapshot = await repo.readPrivateSnapshot(id);
    assert.equal(JSON.parse(snapshot.finding).suppressed, true); assert(snapshot.finding.includes("9007199254740993123456789"));
    assert.equal(await reader.get(id), null);
  });
  await t.test("invalid later SQL entry rolls back every earlier finding and manifest", async () => {
    const ids = ["writer-atomic-a", "writer-atomic-z"];
    const rows = await store.prepareRows("finding", [], ids.map(id => raw(minimal(id))));
    const pointer = { object: "a".repeat(64), offset: 0, length: 100 };
    const entries = rows.map((row, i) => ({ id: ids[i], expectedRevision: 0, expectedRow: null, row, sourceRows: [], finding: pointer, sources: null }));
    entries[1].row = Buffer.from(entries[1].row.toString().replace('"low"', '"invalid"'));
    await assert.rejects(store.commitFindings(entries), /HTTP 400/);
    assert.equal((await originals("finding", ids[0])).length, 0); assert.equal(await store.get(ids[0]), null);
  });
  await t.test("finding commit rejects lease takeover after object upload", async () => {
    const lease = { name: "writer-takeover", owner: "d673a2ad-2be0-4f10-8e57-6dc202609138" };
    await pool.query("select public.acquire_run_lock($1,$2,900)", [lease.name, lease.owner]);
    const service = privateManifestStore({ url: "https://fixture.invalid", serviceKey: tokens.service_role, fetchImpl: loopbackFetch, lease });
    const objects = memory(async () => {
      await pool.query("update public.run_locks set locked_until=clock_timestamp()-interval '1 second' where name=$1", [lease.name]);
      await pool.query("select public.acquire_run_lock($1,$2,900)", [lease.name, "d673a2ad-2be0-4f10-8e57-6dc202609139"]);
    });
    await assert.rejects(upsertFindingRows(repository(objects, service), [raw(minimal("writer-takeover"))]), /HTTP 409/);
    assert.equal((await originals("finding", "writer-takeover")).length, 0); assert.equal(await store.get("writer-takeover"), null);
  });
  await t.test("corrupt existing finding objects fail closed before an unchanged write is acknowledged", async () => {
    const id = "writer-corrupt"; const objects = memory(); await upsertFindingRows(repository(objects), [raw(minimal(id))]);
    await assert.rejects(upsertFindingRows(repository({ ...objects, async read() { return Buffer.from("corrupt"); } }), [raw(minimal(id))]), /integrity/);
    assert.equal((await store.get(id)).revision, 1);
  });
  await t.test("bootstrap waits for an in-flight legacy source edit and retries with its committed details", async () => {
    const id = "writer-source-lock"; await seedFinding(id); await insertSources([sighting(id)]);
    const blocker = await pool.connect(); let running;
    try {
      await blocker.query("begin"); await blocker.query("update public.finding_sources set details='{\"winner\":true}'::jsonb where finding_id=$1", [id]);
      let entered; const committing = new Promise(resolve => { entered = resolve; });
      const service = { ...store, async commitFindings(entries) { entered(); return store.commitFindings(entries); } };
      const repo = repository(memory(), service); running = upsertFindingRows(repo, [raw(minimal(id))]);
      // Attach rejection immediately; release the owned transaction in finally.
      running.catch(() => {}); await committing;
      let waiting = false;
      for (let i = 0; i < 100; i++) {
        const { rows } = await pool.query("select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%commit_evidence_findings%') as waiting");
        if (rows[0].waiting) { waiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      assert(waiting, "Actual publication must wait on the owned source row lock");
      await blocker.query("commit"); await running;
      assert.equal(JSON.parse((await repo.readPrivateSnapshot(id)).sources[0]).details.winner, true);
    } finally { await blocker.query("rollback"); blocker.release(); await running?.catch(() => {}); }
  });
  await t.test("finding context and commit RPCs reject anonymous and authenticated callers", async () => {
    for (const role of ["anon", "authenticated"]) for (const [path, body] of [
      ["/rpc/read_evidence_write_context", { p_ids: ["writer-bootstrap"] }],
      ["/rpc/commit_evidence_findings", { p_entries: [], p_lock_name: "fixture", p_owner_id: "d673a2ad-2be0-4f10-8e57-6dc202609130" }]
    ]) { const response = await request(path, { role, body: JSON.stringify(body) }); assert([401,403].includes(response.status)); await response.body.cancel(); }
  });
  await t.test("invalid duplicate and oversized contexts fail before publication", async () => {
    await assert.rejects(upsertFindingRows(repository(memory()), [raw(minimal("dup")), raw(minimal("dup"))]), /identity/);
    await assert.rejects(store.readWriteContext(Array.from({ length: 201 }, (_, i) => "limit" + i)), /batch/);
    const response = await request("/rpc/read_evidence_write_context", { body: JSON.stringify({ p_ids: ["a", "a"] }) }); assert.equal(response.status, 400); await response.body.cancel();
  });
  await t.test("ingest uses its freshly acquired owner and checkpoints only after both evidence writes", async () => {
    const objects = memory(); const seenOwners = [];
    const state = new Map(); const events = [];
    const database = {
      configured: () => true,
      async tryAcquireRunLock(name, seconds, owner) { seenOwners.push(owner); return (await pool.query("select public.acquire_run_lock($1,$2,$3) as ok", [name, owner, seconds])).rows[0].ok; },
      async renewRunLock(name, seconds, owner) { return (await pool.query("select public.renew_run_lock($1,$2,$3) as ok", [name, owner, seconds])).rows[0].ok; },
      async releaseRunLock(name, owner) { await pool.query("select public.release_run_lock($1,$2)", [name, owner]); },
      async getServiceState(key) { return { value: state.get(key) }; },
      async setRunState(name, owner, key, value) { await pool.query("select public.assert_evidence_lease($1,$2)", [name, owner]); events.push(key); state.set(key, value); },
      async insertSourceRuns() { events.push("summaries"); },
      async upsertFindings() { throw new Error("Unexpected legacy fallback"); },
      async upsertFindingSources() { throw new Error("Unexpected legacy fallback"); }
    };
    const run = (id, failure) => runIngest({ store: database, minIntervalMs: 0, readData: () => ({}), score: entry => entry,
      leaseOptions: { name: "writer-ingest", heartbeatMs: 600000 },
      scan: async () => [{ source: "direct_ct", label: "fixture", entries: [{ ...minimal(id), domains: ["synthetic.invalid"] }],
        ok: true, scanned_entries: 1, duration_ms: 1, details: {}, errors: [], statePatch: { direct_ct: { cursor: id } } }],
      writerFactory: lease => {
        assert(Object.isFrozen(lease)); assert.equal(lease.owner, seenOwners.at(-1));
        const transport = failure === "finding" ? { ...objects, async putIfAbsent() { throw new Error("Upload failed"); } } : objects;
        const writer = evidenceIngestWriter({ url: "https://fixture.invalid", serviceKey: tokens.service_role, fetchImpl: loopbackFetch, objects: transport, lease });
        return { async upsertFindings(...args) { const result = await writer.upsertFindings(...args); events.push("findings"); return result; },
          async upsertFindingSources(...args) { if (failure === "source") throw new Error("Source upload failed"); const result = await writer.upsertFindingSources(...args); events.push("sources"); return result; } };
      }
    });
    await run("writer-ingest-good");
    assert(events.indexOf("findings") < events.indexOf("sources")); assert(events.indexOf("sources") < events.indexOf("ct_source_state"));
    const cursor = structuredClone(state.get("ct_source_state")); assert.equal(cursor.direct_ct.cursor, "writer-ingest-good");
    for (const phase of ["finding", "source"]) {
      await assert.rejects(run("writer-ingest-" + phase, phase), /[Uu]pload failed/);
      assert.deepEqual(state.get("ct_source_state"), cursor);
    }
    assert.equal(new Set(seenOwners).size, 3); assert.equal(await store.get("writer-ingest-finding"), null);
    const privateRepo = repository(objects); assert.equal((await privateRepo.readPrivateSnapshot("writer-ingest-good")).sources.length, 1);
    assert.equal((await pool.query("select count(*)::int as count from public.run_locks where name='writer-ingest' and locked_until>clock_timestamp()" )).rows[0].count, 0);
  });
}

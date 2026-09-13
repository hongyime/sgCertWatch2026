import assert from "node:assert/strict";
import { evidenceIngestWriter, upsertFindingRows } from "../lib/storage/evidence-ingest-writer.js";
import { EvidenceRepository } from "../lib/storage/evidence-repository.js";
import { upsertSourceRowsBatch } from "../lib/storage/evidence-source-writer.js";
import { privateManifestStore } from "../lib/storage/supabase-manifests.js";

export async function sourceWriterCases(t, { pool, store, reader, raw, minimal, request, seedFinding, loopbackFetch, tokens, fixtureLease }) {
  const memory = (hook = async () => {}) => {
    const blobs = new Map(); const stats = { uploads: 0, reads: 0 };
    return { stats, async read(key) { stats.reads++; assert(blobs.has(key)); return Buffer.from(blobs.get(key)); },
      async putIfAbsent(key, value) { stats.uploads++; await hook(); if (!blobs.has(key)) blobs.set(key, Buffer.from(value)); } };
  };
  const repository = (objects, service = store) => new EvidenceRepository({ objects, privateManifests: service, publicManifests: reader });
  const sighting = (id, source = "fixture", ref = "source") => ({ finding_id: id, source, source_ref: ref, observed_at: "2026-01-02T00:00:00.654321Z" });
  const writer = (objects, calls = {}) => evidenceIngestWriter({ url: "https://fixture.invalid", serviceKey: tokens.service_role,
    lease: fixtureLease, objects,
    fetchImpl: (url, options) => { const name = new URL(url).pathname.split('/').at(-1); calls[name] = (calls[name] || 0) + 1; return loopbackFetch(url, options); } });

  await t.test("source writer batches 200 native rows and pointers; identical retry writes nothing", async () => {
    const objects = memory(); const repo = repository(objects);
    const findings = Array.from({ length: 200 }, (_, i) => minimal("source-batch-" + i));
    await upsertFindingRows(repo, findings.map(raw));
    const initial = { ...objects.stats }; const calls = {}; const adapter = writer(objects, calls);
    const rows = findings.map(row => sighting(row.id));
    assert.deepEqual(await adapter.upsertFindingSources(rows), rows.map(row => ({ finding_id: row.finding_id })));
    assert.equal(Number((await pool.query("select count(*) from public.finding_sources where finding_id like 'source-batch-%'")).rows[0].count), 200);
    assert.deepEqual(calls, { assert_evidence_lease: 1, read_evidence_source_context: 1, prepare_evidence_rows: 1, commit_evidence_sources: 1 });
    assert.equal(objects.stats.uploads - initial.uploads, 1);
    assert.equal(objects.stats.reads - initial.reads, 2);
    const snapshot = await repo.readPrivateSnapshot("source-batch-199");
    assert.equal(snapshot.sources.length, 1); assert.equal(snapshot.manifest.revision, 2);
    const nativeFingerprint = async () => (await pool.query("select md5(string_agg(row_to_json(s)::text||ctid::text||xmin::text,'' order by finding_id)) as hash from public.finding_sources s where finding_id like 'source-batch-%'")).rows[0].hash;
    const originalRows = await nativeFingerprint();
    const beforeRetry = { ...objects.stats }; await adapter.upsertFindingSources(rows);
    assert.equal(objects.stats.uploads, beforeRetry.uploads); assert.equal(objects.stats.reads - beforeRetry.reads, 2);
    assert.equal((await store.get("source-batch-0")).revision, 2);
    assert.equal(await nativeFingerprint(), originalRows);
  });
  await t.test("source writer materializes partial updates with original precision and untouched sightings", async () => {
    const id = "source-native-fields"; await seedFinding(id);
    const response = await request("/finding_sources", { body: JSON.stringify([sighting(id), sighting(id, "other", "retained")]) });
    assert(response.ok, await response.text());
    await pool.query("update public.finding_sources set details=$2::jsonb,created_at='2020-01-01T00:00:00.123456Z' where finding_id=$1", [id, '{"large":9007199254740993123456789,"fraction":1.0000000000000000001}']);
    const old = (await pool.query("select row_to_json(s)::text as raw from public.finding_sources s where finding_id=$1 and source='other'", [id])).rows[0].raw;
    const objects = memory(); const repo = repository(objects); await upsertFindingRows(repo, [raw(minimal(id))]);
    await writer(objects).upsertFindingSources([{ ...sighting(id), observed_at: "2026-02-01T00:00:00.987654Z" }]);
    const native = (await pool.query("select row_to_json(s)::text as raw from public.finding_sources s where finding_id=$1 order by source", [id])).rows.map(row => row.raw);
    assert(native.some(row => row === old)); assert(native.some(row => row.includes("2026-02-01T00:00:00.987654")));
    assert(native.every(row => row.includes("9007199254740993123456789") && row.includes("1.0000000000000000001") && row.includes("2020-01-01T00:00:00.123456")));
    const snapshot = await repo.readPrivateSnapshot(id);
    assert(snapshot.sources.every(row => row.includes("9007199254740993123456789") && row.includes("1.0000000000000000001")));
    assert.deepEqual(snapshot.sources.map(row => JSON.parse(row)), native.map(row => JSON.parse(row)));
  });
  await t.test("native source and parent edits during upload survive bounded retry", async () => {
    const id = "source-legacy-race"; await seedFinding(id);
    assert((await request("/finding_sources", { body: JSON.stringify([sighting(id)]) })).ok);
    let active = false; let changed = false;
    const objects = memory(async () => {
      if (active && !changed) {
        changed = true;
        await pool.query("update public.finding_sources set details='{\"legacy\":true}'::jsonb where finding_id=$1", [id]);
        assert((await request("/finding_sources", { body: JSON.stringify([sighting(id, "legacy-new", "retained")]) })).ok);
        await pool.query("update public.findings set suppressed=true where id=$1", [id]);
      }
    });
    const repo = repository(objects); await upsertFindingRows(repo, [raw(minimal(id))]); active = true;
    await writer(objects).upsertFindingSources([{ ...sighting(id), observed_at: "2026-03-01T00:00:00.123456Z" }]);
    const snapshot = await repo.readPrivateSnapshot(id);
    assert.equal(snapshot.sources.length, 2); assert.equal(JSON.parse(snapshot.finding).suppressed, true);
    assert.equal(JSON.parse(snapshot.sources.find(row => JSON.parse(row).source === "fixture")).details.legacy, true);
    assert.equal(await reader.get(id), null);
    assert.equal(Number((await pool.query("select count(*) from public.finding_sources where finding_id=$1", [id])).rows[0].count), 2);
  });
  await t.test("concurrent source publications retain both writers' native rows", async () => {
    const id = "source-writer-race"; const objects = memory(); const repo = repository(objects);
    await upsertFindingRows(repo, [raw(minimal(id))]); let raced = false;
    const service = { ...store, async commitSources(entries) {
      if (!raced) { raced = true; await upsertSourceRowsBatch(repo, [raw(sighting(id, "other", "winner"))]); }
      return store.commitSources(entries);
    } };
    await upsertSourceRowsBatch(repository(objects, service), [raw(sighting(id))]);
    const snapshot = await repo.readPrivateSnapshot(id);
    assert.equal(snapshot.sources.length, 2); assert.equal(snapshot.manifest.revision, 3);
    assert.equal(Number((await pool.query("select count(*) from public.finding_sources where finding_id=$1", [id])).rows[0].count), 2);
  });
  await t.test("unchanged incoming fields refresh stale source objects without rewriting native rows", async () => {
    const id = "source-stale-body"; const objects = memory(); const repo = repository(objects);
    await upsertFindingRows(repo, [raw(minimal(id))]); await upsertSourceRowsBatch(repo, [raw(sighting(id))]);
    const old = await store.get(id);
    await pool.query("update public.finding_sources set details='{\"legacy\":true}'::jsonb where finding_id=$1", [id]);
    const native = async () => (await pool.query("select row_to_json(s)::text as row,ctid::text,xmin::text from public.finding_sources s where finding_id=$1", [id])).rows;
    const before = await native(); await upsertSourceRowsBatch(repo, [raw(sighting(id))]);
    assert.deepEqual(await native(), before);
    const snapshot = await repo.readPrivateSnapshot(id);
    assert.equal(JSON.parse(snapshot.sources[0]).details.legacy, true);
    assert.equal(snapshot.manifest.revision, old.revision + 1); assert.deepEqual(snapshot.manifest.finding, old.finding);
  });
  await t.test("invalid later materialization rolls back earlier source rows and pointers", async () => {
    const ids = ["source-atomic-a", "source-atomic-z"]; const objects = memory(); const repo = repository(objects);
    await upsertFindingRows(repo, ids.map(id => raw(minimal(id))));
    const service = { ...store, async commitSources(entries) {
      const entry = entries.find(row => row.id === ids[1]);
      const invalid = raw({ ...JSON.parse(entry.incoming[0]), observed_at: null });
      entry.incoming = [invalid]; entry.sourceRows = [invalid];
      return store.commitSources(entries);
    } };
    await assert.rejects(upsertSourceRowsBatch(repository(objects, service), ids.map(id => raw(sighting(id)))), /HTTP 400/);
    assert.equal(Number((await pool.query("select count(*) from public.finding_sources where finding_id=any($1)", [ids])).rows[0].count), 0);
    for (const id of ids) assert.equal((await store.get(id)).revision, 1);
  });
  await t.test("source materialization refuses lease takeover after object upload", async () => {
    const id = "source-takeover"; let active = false;
    const lease = { name: "source-takeover", owner: "d673a2ad-2be0-4f10-8e57-6dc202609138" };
    await pool.query("select public.acquire_run_lock($1,$2,900)", [lease.name, lease.owner]);
    const objects = memory(async () => {
      if (!active) return;
      await pool.query("update public.run_locks set locked_until=clock_timestamp()-interval '1 second' where name=$1", [lease.name]);
      await pool.query("select public.acquire_run_lock($1,$2,900)", [lease.name, "d673a2ad-2be0-4f10-8e57-6dc202609139"]);
    });
    await upsertFindingRows(repository(objects), [raw(minimal(id))]); active = true;
    const service = privateManifestStore({ url: "https://fixture.invalid", serviceKey: tokens.service_role, fetchImpl: loopbackFetch, lease });
    await assert.rejects(upsertSourceRowsBatch(repository(objects, service), [raw(sighting(id))]), /HTTP 409/);
    assert.equal(Number((await pool.query("select count(*) from public.finding_sources where finding_id=$1", [id])).rows[0].count), 0);
    assert.equal((await store.get(id)).revision, 1);
  });
  await t.test("existing object-only evidence cannot be silently discarded by the coexistence writer", async () => {
    const id = "source-object-only"; const objects = memory(); const repo = repository(objects);
    await upsertFindingRows(repo, [raw(minimal(id))]);
    await repo.upsertSourceRows(id, [raw(sighting(id, "old-draft", "retained"))]);
    const before = await store.get(id);
    await assert.rejects(upsertSourceRowsBatch(repo, [raw(sighting(id))]), /requires reconciliation/);
    assert.deepEqual(await store.get(id), before); assert.equal((await repo.readPrivateSnapshot(id)).sources.length, 1);
  });
  await t.test("source context and commit RPCs deny anon and authenticated roles", async () => {
    for (const role of ["anon", "authenticated"]) for (const [path, body] of [
      ["/rpc/read_evidence_source_context", { p_ids: ["source-batch-0"] }],
      ["/rpc/commit_evidence_sources", { p_entries: [], p_lock_name: fixtureLease.name, p_owner_id: fixtureLease.owner }],
    ]) {
      const response = await request(path, { role, body: JSON.stringify(body) });
      assert([401, 403].includes(response.status)); await response.body.cancel();
    }
  });
  await t.test("source commit waits on a real native update and preserves its committed fields", async () => {
    const id = "source-row-lock"; const objects = memory(); const repo = repository(objects);
    await upsertFindingRows(repo, [raw(minimal(id))]); await upsertSourceRowsBatch(repo, [raw(sighting(id))]);
    const blocker = await pool.connect(); let running;
    try {
      await blocker.query("begin"); await blocker.query("update public.finding_sources set details='{\"winner\":true}'::jsonb where finding_id=$1", [id]);
      let entered; const committing = new Promise(resolve => { entered = resolve; });
      const service = { ...store, async commitSources(entries) { entered(); return store.commitSources(entries); } };
      running = upsertSourceRowsBatch(repository(objects, service), [raw({ ...sighting(id), observed_at: "2026-04-01T00:00:00.123456Z" })]);
      running.catch(() => {}); await committing;
      let waiting = false;
      for (let i = 0; i < 100; i++) {
        const { rows } = await pool.query("select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%commit_evidence_sources%') as waiting");
        if (rows[0].waiting) { waiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      assert(waiting); await blocker.query("commit"); await running;
      assert.equal(JSON.parse((await repo.readPrivateSnapshot(id)).sources[0]).details.winner, true);
    } finally { await blocker.query("rollback"); blocker.release(); if (running) await running.catch(() => {}); }
  });
}

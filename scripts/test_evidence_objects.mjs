import assert from "node:assert/strict";
import { test } from "node:test";
import { digest, encodeFrame, decodeFrame, packFrames, readFrame, MAX_OBJECT_BYTES } from "../lib/storage/evidence-frames.js";
import { EvidenceRepository, mergeSourceRows } from "../lib/storage/evidence-repository.js";
import { SupabasePrivateObjects } from "../lib/storage/supabase-objects.js";
import { publicManifestReader, privateManifestStore } from "../lib/storage/supabase-manifests.js";

globalThis.fetch = async () => { throw new Error("Live network forbidden in evidence fixtures"); };
const finding = (id = "fixture-a", extra = {}) => Buffer.from(JSON.stringify({ id, suppressed: false, ...extra }));
const source = (ref = "fixture:one", id = "fixture-a", name = "fixture") => Buffer.from(
  `{"finding_id":${JSON.stringify(id)},"source":${JSON.stringify(name)},"source_ref":${JSON.stringify(ref)},` +
  '"observed_at":"2026-01-02T03:04:05.123456Z","created_at":"2026-01-01T00:00:00Z",' +
  '"details":{"huge":9007199254740993123456789,"fraction":0.123456789012345678901,"unicode":"🦐","nullable":null}}');

export function fixtureStore() {
  const state = new Map(); const blobs = new Map(); const events = [];
  const objects = {
    async read(key) { events.push(["read", key]); if (!blobs.has(key)) throw new Error("Object absent"); return Buffer.from(blobs.get(key)); },
    async putIfAbsent(key, bytes) { events.push(["put", key]); if (!blobs.has(key)) blobs.set(key, Buffer.from(bytes)); }
  };
  const privateManifests = {
    async get(id) { events.push(["private", id]); return structuredClone(state.get(id) ?? null); },
    async compareAndSwap(id, revision, next) {
      events.push(["cas", id]); if ((state.get(id)?.revision ?? 0) !== revision) return false;
      state.set(id, structuredClone(next)); return true;
    },
    async compareAndSwapMany(entries) {
      events.push(["cas_batch", entries.length]);
      const results = [];
      for (const entry of entries) results.push({ id: entry.id,
        saved: await this.compareAndSwap(entry.id, entry.expectedRevision, entry.next) });
      return results;
    }
  };
  const publicManifests = { async get(id) {
    events.push(["authorize", id]); const row = state.get(id);
    return row && !row.suppressed ? { id, suppressed: false, finding: structuredClone(row.finding) } : null;
  } };
  publicManifests.getMany = async ids => {
    events.push(["authorize_many", ids]);
    return ids.flatMap(id => {
      const row = state.get(id);
      return row && !row.suppressed ? [{ id, suppressed: false, finding: structuredClone(row.finding) }] : [];
    });
  };
  const repository = new EvidenceRepository({ objects, privateManifests, publicManifests });
  return { state, blobs, events, objects, privateManifests, publicManifests, repository };
}

test("original JSON bytes, large numbers, fractional digits and Unicode round-trip", () => {
  const bytes = source(); assert.deepEqual(decodeFrame(encodeFrame("sources", [bytes]), "sources"), [bytes]);
  assert.match(bytes.toString(), /9007199254740993123456789/);
});
test("frame kinds enforce public/private boundary", () => {
  assert.throws(() => decodeFrame(encodeFrame("sources", [source()]), "finding"), /permission boundary/);
});
test("corrupt/truncated data, frame pointers and decoding overrun fail", () => {
  const packed = packFrames([encodeFrame("finding", [finding()])]);
  const { bytes } = packed.objects[0]; const pointer = packed.pointers[0];
  for (const bad of [bytes.subarray(0, bytes.length - 1), Buffer.concat([bytes, Buffer.from("x")])]) {
    assert.throws(() => readFrame(bad, pointer, "finding"), /integrity/);
  }
  const corrupt = Buffer.from(bytes); corrupt[14] ^= 1; assert.throws(() => decodeFrame(corrupt, "finding"), /checksum/);
  const overrun = Buffer.from(bytes); overrun.writeUInt32BE(5, 6); assert.throws(() => decodeFrame(overrun, "finding"), /budget/);
  for (const bad of [{ ...pointer, offset: -1 }, { ...pointer, offset: 0.5 }, { ...pointer, object: "../other" }, { ...pointer, length: MAX_OBJECT_BYTES + 1 }]) {
    assert.throws(() => readFrame(bytes, bad, "finding"), /pointer/);
  }
});
test("oversized rows and invalid UTF-8 are rejected before compression", () => {
  assert.throws(() => encodeFrame("finding", [Buffer.alloc(MAX_OBJECT_BYTES + 1)]), /size/);
  assert.throws(() => encodeFrame("finding", [Buffer.from([0xff])]), /JSON/);
});
test("source identity uses complete tuple, including delimiters and exact references", () => {
  const a = source("c", "fixture-a", "a|b"); const b = source("b|c", "fixture-a", "a");
  assert.equal(mergeSourceRows([a], [b], "fixture-a").length, 2);
  assert.equal(mergeSourceRows([a, b], [a], "fixture-a").length, 2);
  assert.throws(() => mergeSourceRows([a], [source("x", "other")], "fixture-a"), /another finding/);
});
test("packed public read returns one authorized finding, never a sibling or private frame", async () => {
  const store = fixtureStore(); const a = finding(); const b = finding("hidden", { private_note: "SIBLING MUST STAY PRIVATE" });
  const packed = packFrames([encodeFrame("finding", [a]), encodeFrame("finding", [b])]);
  store.blobs.set(packed.objects[0].key, packed.objects[0].bytes);
  store.state.set("fixture-a", { id: "fixture-a", suppressed: false, finding: packed.pointers[0] });
  assert.deepEqual(await store.repository.readPublicFinding("fixture-a"), a);
  assert.equal(store.events[0][0], "authorize");
  store.state.get("fixture-a").finding = packed.pointers[1];
  await assert.rejects(store.repository.readPublicFinding("fixture-a"), /identity/);
});
test("denied public authorization makes no object request", async () => {
  const store = fixtureStore(); store.state.set("fixture-a", { suppressed: true });
  assert.equal(await store.repository.readPublicFinding("fixture-a"), null);
  assert.deepEqual(store.events, [["authorize", "fixture-a"]]);
});
test("a public page authorizes once and downloads a shared packed object once", async () => {
  const store = fixtureStore(); const a = finding("a"); const b = finding("b");
  const packed = packFrames([encodeFrame("finding", [a]), encodeFrame("finding", [b])]);
  store.blobs.set(packed.objects[0].key, packed.objects[0].bytes);
  for (const [index, id] of ["a", "b"].entries()) store.state.set(id, { id, suppressed: false, finding: packed.pointers[index] });
  assert.deepEqual(await store.repository.readPublicFindings(["b", "missing", "a"]), [b, a]);
  assert.equal(store.events.filter(event => event[0] === "authorize_many").length, 1);
  assert.equal(store.events.filter(event => event[0] === "read").length, 1);
  store.state.get("b").suppressed = true; store.events.length = 0;
  assert.deepEqual(await store.repository.readPublicFindings(["b"]), []);
  assert.equal(store.events.filter(event => event[0] === "read").length, 0);
});
test("forged public batch authorization is rejected before object requests", async () => {
  const store = fixtureStore(); store.publicManifests.getMany = async () => [{ id: "other", suppressed: false }];
  await assert.rejects(store.repository.readPublicFindings(["a"]), /authorization/); assert.equal(store.events.length, 0);
});
test("upload failure preserves the previously published snapshot", async () => {
  const store = fixtureStore(); await store.repository.publish("fixture-a", { finding: finding(), sources: [source()] }, 0);
  const before = structuredClone(store.state.get("fixture-a"));
  store.objects.putIfAbsent = async () => { throw new Error("Upload failed"); };
  await assert.rejects(store.repository.upsertSources("fixture-a", [source("second")]), /Upload failed/);
  assert.deepEqual(store.state.get("fixture-a"), before);
});
test("truncated upload verification blocks publication", async () => {
  const store = fixtureStore(); store.objects.putIfAbsent = async (key, bytes) => store.blobs.set(key, bytes.subarray(0, -1));
  await assert.rejects(store.repository.publish("fixture-a", { finding: finding(), sources: [] }, 0), /verification/);
  assert.equal(store.state.size, 0);
});
test("lease loss before CAS preserves the previous manifest", async () => {
  const store = fixtureStore(); let owned = true;
  const read = store.objects.read; store.objects.read = async (key) => { const value = await read(key); owned = false; return value; };
  await assert.rejects(store.repository.publish("fixture-a", { finding: finding(), sources: [] }, 0,
    { assertOwned() { if (!owned) throw new Error("Lease lost"); } }), /Lease lost/);
  assert.equal(store.state.size, 0);
});
test("concurrent source upserts rebase and preserve both complete rows", async () => {
  const store = fixtureStore(); await store.repository.publish("fixture-a", { finding: finding(), sources: [source()] }, 0);
  await Promise.all([store.repository.upsertSources("fixture-a", [source("second")]), store.repository.upsertSources("fixture-a", [source("third")])]);
  const saved = await store.repository.readPrivateSnapshot("fixture-a");
  assert.equal(saved.manifest.revision, 3); assert.equal(saved.sources.length, 3);
  assert(saved.sources.some(bytes => bytes.equals(source("second"))));
  assert(saved.sources.some(bytes => bytes.equals(source("third"))));
});
test("source updates reuse the finding pointer and identical retries publish nothing", async () => {
  const store = fixtureStore(); const initial = await store.repository.publish("fixture-a", { finding: finding(), sources: [source()] }, 0);
  store.events.length = 0;
  const updated = await store.repository.upsertSources("fixture-a", [source("second")]);
  assert.deepEqual(updated.finding, initial.finding); assert.equal(store.events.filter(event => event[0] === "put").length, 1);
  store.events.length = 0;
  const repeated = await store.repository.upsertSources("fixture-a", [source("second")]);
  assert.equal(repeated.revision, updated.revision);
  assert.equal(store.events.filter(event => ["put", "cas"].includes(event[0])).length, 0);
});
test("CAS conflicts have a bounded retry budget and never overwrite the winner", async () => {
  const store = fixtureStore(); await store.repository.publish("fixture-a", { finding: finding(), sources: [] }, 0);
  const before = structuredClone(store.state.get("fixture-a")); let attempts = 0;
  store.privateManifests.compareAndSwap = async () => { attempts++; return false; };
  await assert.rejects(store.repository.upsertSources("fixture-a", [source()], { maxConflicts: 2 }), /retry limit/);
  assert.equal(attempts, 3); assert.deepEqual(store.state.get("fixture-a"), before);
});
test("Storage uses private authenticated paths, immutable upload and no redirects", async () => {
  const bytes = encodeFrame("finding", [finding()]); const key = digest(bytes); const seen = [];
  const objects = new SupabasePrivateObjects({ url: "https://fixture.invalid", bucket: "evidence-private", serviceKey: "synthetic-service", fetchImpl: async (url, options) => {
    seen.push({ url, options }); return new Response(options.method === "GET" ? bytes : "{}", { status: 200 });
  } });
  await objects.putIfAbsent(key, bytes); assert.deepEqual(await objects.read(key), bytes);
  assert.match(seen[1].url, /\/object\/authenticated\/evidence-private\//);
  assert.equal(seen[0].options.headers["x-upsert"], "false"); assert.equal(seen[0].options.redirect, "error");
  await assert.rejects(objects.read("../secret"), /key/); assert.equal(seen.length, 2);
});
test("Storage response limits reject oversized, truncated and wrong-content downloads", async () => {
  const key = digest(Buffer.from("expected"));
  for (const response of [new Response("short", { headers: { "content-length": "100" } }),
    new Response("x", { headers: { "content-length": String(MAX_OBJECT_BYTES + 1) } }), new Response("wrong"),
    new Response(new Uint8Array(MAX_OBJECT_BYTES + 1))]) {
    const objects = new SupabasePrivateObjects({ url: "https://fixture.invalid", bucket: "evidence", serviceKey: "synthetic", fetchImpl: async () => response });
    await assert.rejects(objects.read(key), /size|Truncated|checksum/);
  }
});
test("existing-object upload responses are accepted only after verifying original bytes", async () => {
  const value = encodeFrame("finding", [finding()]); const key = digest(value);
  for (const status of [400, 409]) {
    let reads = 0;
    const objects = new SupabasePrivateObjects({ url: "https://fixture.invalid", bucket: "evidence", serviceKey: "synthetic", fetchImpl: async (_url, options) => {
      if (options.method === "POST") return new Response("existing object", { status });
      reads++; return new Response(value);
    } });
    await objects.putIfAbsent(key, value); assert.equal(reads, 1);
  }
  const mismatch = new SupabasePrivateObjects({ url: "https://fixture.invalid", bucket: "evidence", serviceKey: "synthetic", fetchImpl: async (_url, options) =>
    options.method === "POST" ? new Response("exists", { status: 400 }) : new Response("different") });
  await assert.rejects(mismatch.putIfAbsent(key, value), /checksum/);
});
test("partial source snapshots cannot overwrite existing complete evidence", async () => {
  const store = fixtureStore(); await store.repository.publish("fixture-a", { finding: finding(), sources: [source()] }, 0);
  await assert.rejects(store.repository.upsertSources("fixture-a", [Buffer.from('{"finding_id":"fixture-a","source":"fixture","source_ref":"fixture:one"}')]), /all original columns/);
  assert.deepEqual((await store.repository.readPrivateSnapshot("fixture-a")).sources, [source()]);
});
test("public manifest client uses only anon key and excludes private pointer", async () => {
  const pointer = { object: "a".repeat(64), offset: 0, length: 100 }; let seen;
  const reader = publicManifestReader({ url: "https://fixture.invalid", anonKey: "synthetic-anon", fetchImpl: async (url, options) => {
    seen = { url, options }; return Response.json([{ finding_id: "id|?&x", revision: 1, finding_pointer: pointer, sources_pointer: "must-not-escape" }]);
  } });
  const value = await reader.get("id|?&x"); assert.equal(value.sources, undefined);
  assert.equal(seen.options.headers.apikey, "synthetic-anon");
  assert.equal(seen.url.searchParams.get("finding_id"), "eq.id|?&x");
  assert(!seen.url.searchParams.get("select").includes("sources"));
  assert.throws(() => publicManifestReader({ url: "https://fixture.invalid", serviceKey: "unused" }), /configuration/);
});
test("private publication sends expected revision and both pointers in one RPC", async () => {
  let seen; const store = privateManifestStore({ url: "https://fixture.invalid", serviceKey: "synthetic-service", fetchImpl: async (url, options) => {
    seen = { url, options }; return Response.json(false);
  } });
  const pointer = { object: "a".repeat(64), offset: 0, length: 100 };
  assert.equal(await store.compareAndSwap("id", 4, { suppressed: false, finding: pointer, sources: null }), false);
  assert.match(seen.url.pathname, /rpc\/publish_evidence_manifest$/);
  assert.deepEqual(JSON.parse(seen.options.body), { p_finding_id: "id", p_expected_revision: 4, p_suppressed: false, p_finding_pointer: pointer, p_sources_pointer: null });
});

test("public and private clients decode compact pointers without exposing source metadata", async () => {
  const pointer = { object: "00ff".repeat(16), offset: 66051, length: 1029 };
  const binary = Buffer.alloc(40); Buffer.from(pointer.object, "hex").copy(binary);
  binary.writeUInt32BE(pointer.offset, 32); binary.writeUInt32BE(pointer.length, 36);
  const wire = "\\x" + binary.toString("hex");
  const fetchImpl = async () => Response.json([{ finding_id: "fixture", revision: 1,
    finding_pointer: wire, sources_pointer: wire, findings: { suppressed: true } }]);
  const publicRow = await publicManifestReader({ url: "https://fixture.invalid", anonKey: "synthetic-anon", fetchImpl }).get("fixture");
  assert.deepEqual(publicRow.finding, pointer); assert.equal(publicRow.sources, undefined);
  const privateRow = await privateManifestStore({ url: "https://fixture.invalid", serviceKey: "synthetic-service", fetchImpl }).get("fixture");
  assert.deepEqual(privateRow.finding, pointer); assert.deepEqual(privateRow.sources, pointer);
  assert.equal(privateRow.suppressed, true);
});

test("manifest clients reject truncated, malformed and out-of-bounds binary pointers", async () => {
  const overflow = Buffer.alloc(40); overflow.writeUInt32BE(0xffffffff, 32); overflow.writeUInt32BE(46, 36);
  for (const pointer of ["\\x" + "00".repeat(39), "\\x" + "00".repeat(41), "\\x" + "zz".repeat(40),
    "00".repeat(40), "\\x" + Buffer.alloc(40).toString("hex"), "\\x" + overflow.toString("hex")]) {
    const reader = publicManifestReader({ url: "https://fixture.invalid", anonKey: "synthetic-anon",
      fetchImpl: async () => Response.json([{ finding_id: "fixture", revision: 1, finding_pointer: pointer }]) });
    await assert.rejects(reader.get("fixture"), /pointer/);
  }
});

test("200 findings share two private objects and one publication call", async () => {
  const entries = Array.from({ length: 200 }, (_, index) => {
    const id = `batch-${index}`;
    return { findingId: id, finding: finding(id), sources: [source("exact", id)], expectedRevision: 0 };
  });
  const individual = fixtureStore();
  for (const entry of entries) await individual.repository.publish(entry.findingId, entry, 0);
  assert.equal(individual.blobs.size, 400);
  const batch = fixtureStore();
  const result = await batch.repository.publishBatch(entries);
  assert.equal(result.length, 200); assert(result.every(row => row.saved));
  assert.equal(batch.blobs.size, 2); assert.equal(batch.events.filter(([kind]) => kind === "cas_batch").length, 1);
  for (const entry of entries) {
    const saved = await batch.repository.readPrivateSnapshot(entry.findingId);
    assert.deepEqual(saved.finding, entry.finding); assert.deepEqual(saved.sources, entry.sources);
  }
  batch.events.length = 0;
  const page = await batch.repository.readPublicFindings(entries.slice(0, 100).map(e => e.findingId));
  assert.deepEqual(page, entries.slice(0, 100).map(e => e.finding));
  assert.equal(batch.events.filter(([kind]) => kind === "read").length, 1);
});

test("invalid batch data and byte budgets fail before Storage calls", async () => {
  const store = fixtureStore(); const entry = { findingId: "a", finding: finding("a"), sources: [], expectedRevision: 0 };
  for (const entries of [[], Array.from({ length: 201 }, () => entry), [entry, entry],
    [{ ...entry, finding: finding("other") }], [{ ...entry, sources: [source("wrong-finding")] }],
    [{ ...entry, finding: finding("a", { oversized: "x".repeat(MAX_OBJECT_BYTES) }) }]]) {
    await assert.rejects(store.repository.publishBatch(entries));
    assert.equal(store.events.length, 0);
  }
});

test("batch conflicts are explicit and malformed acknowledgements cannot advance callers", async () => {
  const store = fixtureStore(); const entry = { findingId: "a", finding: finding("a"), sources: [], expectedRevision: 0 };
  await store.repository.publishBatch([entry]);
  const conflict = await store.repository.publishBatch([entry, { ...entry, findingId: "b", finding: finding("b") }]);
  assert.deepEqual(conflict.map(({ id, saved }) => ({ id, saved })), [{ id: "a", saved: false }, { id: "b", saved: true }]);
  assert.equal(conflict[0].manifest, null); assert.equal(store.state.get("a").revision, 1);
  for (const result of [[], [{ id: "other", saved: true }], [{ id: "a", saved: "true" }]]) {
    store.privateManifests.compareAndSwapMany = async () => result;
    await assert.rejects(store.repository.publishBatch([entry]), /acknowledgement/);
  }
});

test("batch upload or lease failure cannot publish any new manifest", async () => {
  const entry = { findingId: "a", finding: finding("a"), sources: [source("private", "a")], expectedRevision: 0 };
  const failed = fixtureStore(); failed.objects.putIfAbsent = async () => { throw new Error("upload failed"); };
  await assert.rejects(failed.repository.publishBatch([entry]), /upload failed/); assert.equal(failed.state.size, 0);
  const expired = fixtureStore(); let owned = true;
  const read = expired.objects.read; expired.objects.read = async key => { const value = await read(key); owned = false; return value; };
  await assert.rejects(expired.repository.publishBatch([entry], { assertOwned: () => { if (!owned) throw new Error("lease lost"); } }), /lease lost/);
  assert.equal(expired.state.size, 0); assert.equal(expired.events.filter(([kind]) => kind === "cas_batch").length, 0);
});

test("batch manifest client sends one bounded RPC with explicit revisions", async () => {
  const pointer = { object: "a".repeat(64), offset: 0, length: 46 }; let calls = 0;
  const store = privateManifestStore({ url: "https://fixture.invalid", serviceKey: "synthetic-service", fetchImpl: async (url, options) => {
    calls++; assert.match(url.pathname, /rpc\/publish_evidence_manifests$/);
    assert.deepEqual(JSON.parse(options.body), { p_publications: [{ id: "a", expected_revision: 3,
      suppressed: false, finding_pointer: pointer, sources_pointer: null }] });
    return Response.json([{ finding_id: "a", saved: false }]);
  } });
  assert.deepEqual(await store.compareAndSwapMany([{ id: "a", expectedRevision: 3, next: { suppressed: false, finding: pointer, sources: null } }]), [{ id: "a", saved: false }]);
  assert.equal(calls, 1);
});

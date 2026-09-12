// Experimental adapter, deliberately not wired into production readers/writers.
import { digest, encodeFrame, decodeFrame, originalRow, packFrames, readFrame, validatePointer, MAX_OBJECT_BYTES } from "./evidence-frames.js";

function identity(value) {
  if (typeof value !== "string" || !value.length || Buffer.byteLength(value) > 8192) {
    throw new Error("Invalid evidence identity");
  }
  return value;
}

function sourceIdentity(bytes, findingId) {
  const row = originalRow(bytes);
  if (row.finding_id !== findingId) throw new Error("Source belongs to another finding");
  if (!Object.hasOwn(row, "details") || typeof row.observed_at !== "string" || !row.observed_at
      || typeof row.created_at !== "string" || !row.created_at) throw new Error("Source snapshot must contain all original columns");
  // Compare complete tuples. Delimiter concatenation and hashes alone do not
  // preserve identity when references collide or contain delimiters.
  return JSON.stringify([identity(row.finding_id), identity(row.source), identity(row.source_ref)]);
}

export function mergeSourceRows(existing, incoming, findingId) {
  if (!Array.isArray(existing) || !Array.isArray(incoming) || existing.length > 10000 || incoming.length > 10000) {
    throw new Error("Source batch exceeds row budget");
  }
  const rows = new Map();
  for (const raw of [...existing, ...incoming]) rows.set(sourceIdentity(raw, findingId), Buffer.from(raw));
  if (rows.size > 10000) throw new Error("Source snapshot exceeds row budget");
  return [...rows.values()];
}

export class EvidenceRepository {
  constructor({ publicManifests, privateManifests, objects }) {
    this.publicManifests = publicManifests;
    this.privateManifests = privateManifests;
    this.objects = objects;
  }

  async frame(pointer, kind) {
    validatePointer(pointer);
    const object = await this.objects.read(pointer.object);
    return readFrame(object, pointer, kind);
  }

  async readPublicFinding(findingId) {
    identity(findingId);
    // The trusted manifest implementation MUST use the anon database role/RLS.
    // Callers supply an ID, never a pointer or a service-authenticated manifest.
    const manifest = await this.publicManifests.get(findingId);
    if (manifest === null) return null;
    if (!manifest || manifest.id !== findingId || manifest.suppressed !== false) {
      throw new Error("Invalid public finding authorization");
    }
    const [bytes] = await this.frame(manifest.finding, "finding");
    const row = originalRow(bytes);
    if (row.id !== findingId || row.suppressed !== false) throw new Error("Finding identity/visibility mismatch");
    // Return only this original row. Never return an object URL, packed bytes,
    // sibling frames or the private source manifest to a public caller.
    return bytes;
  }

  async readPublicFindings(findingIds) {
    if (!Array.isArray(findingIds) || !findingIds.length || findingIds.length > 100) throw new Error("Invalid public page size");
    const ids = [...new Set(findingIds.map(identity))]; const requested = new Set(ids);
    const manifests = await this.publicManifests.getMany(ids);
    if (!Array.isArray(manifests) || manifests.length > ids.length) throw new Error("Invalid public manifest batch");
    const seen = new Set(); const groups = new Map();
    for (const manifest of manifests) {
      if (!manifest || !requested.has(manifest.id) || seen.has(manifest.id) || manifest.suppressed !== false) {
        throw new Error("Invalid public finding authorization");
      }
      validatePointer(manifest.finding); seen.add(manifest.id);
      const group = groups.get(manifest.finding.object) ?? []; group.push(manifest); groups.set(manifest.finding.object, group);
    }
    const rows = new Map(); let rawSize = 0;
    // One bounded object in memory at a time, shared by all rows in this page.
    // No cross-request cache can outlive a fresh anonymous/RLS authorization.
    for (const [key, group] of groups) {
      const object = await this.objects.read(key);
      if (!Buffer.isBuffer(object) || object.length > MAX_OBJECT_BYTES || digest(object) !== key) throw new Error("Object integrity failure");
      for (const manifest of group) {
        const pointer = manifest.finding;
        if (pointer.offset + pointer.length > object.length) throw new Error("Object integrity failure");
        const [bytes] = decodeFrame(object.subarray(pointer.offset, pointer.offset + pointer.length), "finding"); const row = originalRow(bytes);
        if (row.id !== manifest.id || row.suppressed !== false) throw new Error("Finding identity/visibility mismatch");
        rawSize += bytes.length;
        if (rawSize > MAX_OBJECT_BYTES) throw new Error("Public response exceeds decoding budget");
        rows.set(manifest.id, bytes);
      }
    }
    return ids.filter(id => rows.has(id)).map(id => rows.get(id));
  }

  async readPrivateSnapshot(findingId) {
    identity(findingId);
    const manifest = await this.privateManifests.get(findingId);
    if (manifest === null) return null;
    if (!manifest || manifest.id !== findingId || !Number.isSafeInteger(manifest.revision) || manifest.revision < 1) {
      throw new Error("Invalid private finding manifest");
    }
    const [finding] = await this.frame(manifest.finding, "finding");
    if (originalRow(finding).id !== findingId) throw new Error("Finding identity mismatch");
    const sources = manifest.sources ? await this.frame(manifest.sources, "sources") : [];
    const unique = mergeSourceRows([], sources, findingId);
    if (unique.length !== sources.length) throw new Error("Duplicate source identity in stored snapshot");
    return { manifest, finding, sources };
  }

  async publish(findingId, { finding, sources }, expectedRevision, { assertOwned = () => {} } = {}) {
    identity(findingId);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0 || expectedRevision >= Number.MAX_SAFE_INTEGER) throw new Error("Invalid expected revision");
    const row = originalRow(finding);
    if (row.id !== findingId || typeof row.suppressed !== "boolean") throw new Error("Finding identity/visibility mismatch");
    if (!Array.isArray(sources) || mergeSourceRows([], sources, findingId).length !== sources.length) {
      throw new Error("Invalid or duplicate source rows");
    }
    // No original bytes are reserialized. Finding and private source frames are
    // packed separately so future compaction cannot mix permission categories.
    const findingPack = packFrames([encodeFrame("finding", [finding])]);
    const sourcePack = packFrames(sources.length ? [encodeFrame("sources", sources)] : []);
    await this.persistObjects([...findingPack.objects, ...sourcePack.objects], assertOwned);
    assertOwned();
    const next = { id: findingId, revision: expectedRevision + 1, suppressed: row.suppressed,
      finding: findingPack.pointers[0], sources: sourcePack.pointers[0] ?? null };
    // The DB implementation must atomically compare the expected revision and
    // publish both pointers. A failed CAS retains the previous manifest. Uploaded
    // but unreferenced objects remain private; no destructive cleanup is assumed.
    const saved = await this.privateManifests.compareAndSwap(findingId, expectedRevision, next);
    if (typeof saved !== "boolean") throw new Error("Invalid publication acknowledgement");
    return saved ? next : null;
  }

  async persistObjects(objects, assertOwned) {
    for (const object of objects) {
      assertOwned();
      await this.objects.putIfAbsent(object.key, object.bytes);
      // Verify the persisted bytes even after an already-existing-object reply.
      const saved = await this.objects.read(object.key);
      if (!Buffer.isBuffer(saved) || saved.length !== object.bytes.length || digest(saved) !== object.key) {
        throw new Error("Uploaded evidence failed verification");
      }
    }
  }

  async publishBatch(publications, { assertOwned = () => {} } = {}) {
    if (!Array.isArray(publications) || !publications.length || publications.length > 200) throw new Error("Invalid publication batch");
    const seen = new Set(); let rawSize = 0;
    for (const item of publications) {
      identity(item.findingId);
      if (seen.has(item.findingId)) throw new Error("Duplicate finding in publication batch");
      seen.add(item.findingId);
      if (!Number.isSafeInteger(item.expectedRevision) || item.expectedRevision < 0 || item.expectedRevision >= Number.MAX_SAFE_INTEGER) throw new Error("Invalid expected revision");
      const row = originalRow(item.finding);
      if (row.id !== item.findingId || typeof row.suppressed !== "boolean") throw new Error("Finding identity/visibility mismatch");
      if (!Array.isArray(item.sources) || mergeSourceRows([], item.sources, item.findingId).length !== item.sources.length) throw new Error("Invalid or duplicate source rows");
      rawSize += item.finding.length + item.sources.reduce((n, source) => n + source.length, 0);
      if (rawSize > MAX_OBJECT_BYTES) throw new Error("Publication exceeds raw byte budget");
    }
    const findings = packFrames(publications.map(item => encodeFrame("finding", [item.finding])));
    const sourceItems = publications.filter(item => item.sources.length);
    const sources = packFrames(sourceItems.map(item => encodeFrame("sources", item.sources)));
    const sourcePointers = new Map(sourceItems.map((item, index) => [item.findingId, sources.pointers[index]]));
    await this.persistObjects([...findings.objects, ...sources.objects], assertOwned);
    assertOwned();
    const entries = publications.map((item, index) => ({ id: item.findingId, expectedRevision: item.expectedRevision,
      next: { id: item.findingId, revision: item.expectedRevision + 1, suppressed: originalRow(item.finding).suppressed,
        finding: findings.pointers[index], sources: sourcePointers.get(item.findingId) ?? null } }));
    const acknowledgements = await this.privateManifests.compareAndSwapMany(entries);
    if (!Array.isArray(acknowledgements) || acknowledgements.length !== entries.length) throw new Error("Invalid batch publication acknowledgement");
    const results = new Map();
    for (const row of acknowledgements) {
      if (!seen.has(row.id) || results.has(row.id) || typeof row.saved !== "boolean") throw new Error("Invalid batch publication acknowledgement");
      results.set(row.id, row.saved);
    }
    // Conflicts are explicit: callers must resolve them before advancing a
    // collection cursor. Successfully published neighbors remain acknowledged.
    return entries.map(entry => ({ id: entry.id, saved: results.get(entry.id),
      manifest: results.get(entry.id) ? entry.next : null }));
  }

  async upsertSources(findingId, incoming, { maxConflicts = 3, assertOwned = () => {} } = {}) {
    identity(findingId);
    if (!Number.isSafeInteger(maxConflicts) || maxConflicts < 0 || maxConflicts > 5) throw new Error("Invalid retry limit");
    for (let attempt = 0; attempt <= maxConflicts; attempt++) {
      assertOwned();
      const current = await this.readPrivateSnapshot(findingId);
      if (!current) throw new Error("Finding must exist before source publication");
      const sources = mergeSourceRows(current.sources, incoming, findingId);
      if (sources.length === current.sources.length && sources.every((row, index) => row.equals(current.sources[index]))) {
        assertOwned(); return current.manifest;
      }
      if (current.manifest.revision >= Number.MAX_SAFE_INTEGER) throw new Error("Invalid expected revision");
      const packed = packFrames([encodeFrame("sources", sources)]);
      await this.persistObjects(packed.objects, assertOwned); assertOwned();
      // Keep the already-verified finding pointer, including its pack offset.
      // New source sightings do not rewrite/re-upload an unchanged finding or
      // revert a current suppression decision encoded in manifest metadata.
      const next = { ...current.manifest, revision: current.manifest.revision + 1, sources: packed.pointers[0] };
      const saved = await this.privateManifests.compareAndSwap(findingId, current.manifest.revision, next);
      if (typeof saved !== "boolean") throw new Error("Invalid publication acknowledgement");
      if (saved) return next;
    }
    throw new Error("Concurrent evidence publication exceeded retry limit");
  }
}

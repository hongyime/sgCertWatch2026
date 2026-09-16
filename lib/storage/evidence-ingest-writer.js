// Explicit experimental dependency injection only. No environment flag enables
// this in production. Legacy wide rows remain during this contract review.
import { EvidenceRepository } from "./evidence-repository.js";
import { upsertSourceRowsBatch } from "./evidence-source-writer.js";
import { privateManifestStore } from "./supabase-manifests.js";
import { originalRow, encodeFrame, decodeFrame, packFrames, digest, validatePointer, MAX_OBJECT_BYTES } from "./evidence-frames.js";

async function verifyUnchangedBodies(repository, entries, assertOwned) {
  const groups = new Map(); let decodedBytes = 0;
  for (const entry of entries.filter(entry => entry.unchanged)) {
    validatePointer(entry.finding);
    const group = groups.get(entry.finding.object) ?? []; group.push(entry); groups.set(entry.finding.object, group);
  }
  // A legacy relational edit can make an old object stale without changing its
  // manifest revision. Verify each shared pack once before declaring a no-op.
  for (const [key, group] of groups) {
    assertOwned(); const object = await repository.objects.read(key);
    if (!Buffer.isBuffer(object) || object.length > MAX_OBJECT_BYTES || digest(object) !== key) throw new Error("Object integrity failure");
    for (const entry of group) {
      const { offset, length } = entry.finding;
      if (offset + length > object.length) throw new Error("Object integrity failure");
      const [stored] = decodeFrame(object.subarray(offset, offset + length), "finding");
      decodedBytes += stored.length;
      if (originalRow(stored).id !== entry.id || decodedBytes > MAX_OBJECT_BYTES) throw new Error("Invalid existing finding body");
      entry.unchanged = stored.equals(entry.row);
    }
  }
}

export async function upsertFindingRows(repository, incoming, { maxConflicts = 3, assertOwned = () => {} } = {}) {
  if (!Array.isArray(incoming) || !incoming.length || incoming.length > 200
      || !Number.isSafeInteger(maxConflicts) || maxConflicts < 0 || maxConflicts > 5) throw new Error("Invalid finding upsert batch");
  const ids = incoming.map(raw => originalRow(raw).id);
  if (ids.some(id => typeof id !== "string" || !id || Buffer.byteLength(id) > 8192) || new Set(ids).size !== ids.length) throw new Error("Invalid finding upsert identity");
  if (incoming.reduce((size, row) => size + row.length, 0) > MAX_OBJECT_BYTES) throw new Error("Finding upsert exceeds byte budget");
  const service = repository.privateManifests; let pending = incoming;
  for (let attempt = 0; attempt <= maxConflicts; attempt++) {
    assertOwned(); await service.assertLease(); assertOwned();
    const contexts = new Map((await service.readWriteContext(pending.map(row => originalRow(row).id))).map(row => [row.id, row]));
    const normalized = await service.prepareRows("finding", [...contexts.values()].filter(c => c.row).map(c => c.row), pending);
    if (normalized.length !== pending.length) throw new Error("Invalid finding normalization acknowledgement");
    let size = 0;
    const entries = normalized.map((row, index) => {
      const id = originalRow(pending[index]).id; const context = contexts.get(id);
      if (!context || originalRow(row).id !== id || typeof originalRow(row).suppressed !== "boolean") throw new Error("Invalid normalized finding identity");
      const keys = context.sourceRows.map(source => {
        const value = originalRow(source);
        if (value.finding_id !== id || typeof value.source !== "string" || typeof value.source_ref !== "string") throw new Error("Invalid bootstrap source identity");
        return JSON.stringify([value.finding_id, value.source, value.source_ref]);
      });
      if (new Set(keys).size !== keys.length) throw new Error("Duplicate bootstrap source identity");
      size += row.length + context.sourceRows.reduce((sum, value) => sum + value.length, 0);
      if (size > MAX_OBJECT_BYTES) throw new Error("Finding publication exceeds byte budget");
      return { id, expectedRevision: context.revision, expectedRow: context.row, row,
        sourceRows: context.sourceRows, finding: context.finding, sources: context.sources,
        unchanged: context.revision > 0 && row.equals(context.row) };
    });
    await verifyUnchangedBodies(repository, entries, assertOwned);
    const changed = entries.filter(entry => !entry.unchanged);
    const findingPack = packFrames(changed.map(entry => encodeFrame("finding", [entry.row])));
    changed.forEach((entry, index) => { entry.finding = findingPack.pointers[index]; });
    const bootstrap = entries.filter(entry => !entry.expectedRevision && entry.sourceRows.length);
    const sourcePack = packFrames(bootstrap.map(entry => encodeFrame("sources", entry.sourceRows)));
    bootstrap.forEach((entry, index) => { entry.sources = sourcePack.pointers[index]; });
    assertOwned(); await repository.persistObjects([...findingPack.objects, ...sourcePack.objects], assertOwned); assertOwned();
    const acknowledgements = await service.commitFindings(entries);
    if (!Array.isArray(acknowledgements) || acknowledgements.length !== entries.length) throw new Error("Invalid finding commit acknowledgement");
    const saved = new Map(); const requested = new Set(entries.map(entry => entry.id));
    for (const row of acknowledgements) {
      if (!requested.has(row.id) || saved.has(row.id) || typeof row.saved !== "boolean") throw new Error("Invalid finding commit acknowledgement");
      saved.set(row.id, row.saved);
    }
    assertOwned(); pending = pending.filter(row => !saved.get(originalRow(row).id));
    if (!pending.length) return ids.map(id => ({ id }));
  }
  throw new Error("Concurrent finding publication exceeded retry limit");
}

export function evidenceIngestWriter({ url, serviceKey, fetchImpl, objects, lease }) {
  const privateManifests = privateManifestStore({ url, serviceKey, fetchImpl, lease });
  const repository = new EvidenceRepository({ privateManifests, objects });
  return {
    async upsertFindings(rows, options) {
      const saved = [];
      for (let start = 0; start < rows.length; start += 200) {
        saved.push(...await upsertFindingRows(repository, rows.slice(start, start + 200).map(row => Buffer.from(JSON.stringify(row))), options));
      }
      return saved;
    },
    async upsertFindingSources(rows, options) {
      const saved = [];
      for (let start = 0; start < rows.length; start += 200) {
        saved.push(...await upsertSourceRowsBatch(repository, rows.slice(start, start + 200).map(row => Buffer.from(JSON.stringify(row))), options));
      }
      return saved;
    }
  };
}

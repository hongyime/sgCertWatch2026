// Batched experimental coexistence writer. Existing relational source rows are
// authoritative; object snapshots are replaced only with a checked complete view.
import { mergeSourceRows } from "./evidence-repository.js";
import { originalRow, encodeFrame, decodeFrame, packFrames, digest, validatePointer, MAX_OBJECT_BYTES } from "./evidence-frames.js";

function key(raw) {
  const row = originalRow(raw);
  if (typeof row.finding_id !== "string" || !row.finding_id || Buffer.byteLength(row.finding_id) > 8192
      || [row.source, row.source_ref].some(value => typeof value !== "string" || Buffer.byteLength(value) > 8192)) throw new Error("Invalid source upsert identity");
  return JSON.stringify([row.finding_id, row.source, row.source_ref]);
}

const ordered = rows => [...rows].sort((a, b) => key(a).localeCompare(key(b)));

async function comparePublishedBodies(repository, entries, assertOwned) {
  const groups = new Map(); let decodedBytes = 0;
  for (const entry of entries) for (const kind of ["finding", "sources"]) {
    const pointer = entry[kind];
    if (pointer === null) continue;
    validatePointer(pointer);
    const group = groups.get(pointer.object) ?? []; group.push({ entry, kind, pointer }); groups.set(pointer.object, group);
  }
  for (const [objectKey, group] of groups) {
    assertOwned(); const object = await repository.objects.read(objectKey);
    if (!Buffer.isBuffer(object) || object.length > MAX_OBJECT_BYTES || digest(object) !== objectKey) throw new Error("Object integrity failure");
    for (const { entry, kind, pointer } of group) {
      if (pointer.offset + pointer.length > object.length) throw new Error("Object integrity failure");
      const rows = decodeFrame(object.subarray(pointer.offset, pointer.offset + pointer.length), kind);
      decodedBytes += rows.reduce((sum, row) => sum + row.length, 0);
      if (decodedBytes > MAX_OBJECT_BYTES) throw new Error("Source publication exceeds decoding budget");
      if (kind === "finding") {
        if (originalRow(rows[0]).id !== entry.id) throw new Error("Source parent object identity mismatch");
        entry.sameFinding = rows[0].equals(entry.row);
      } else {
        const originals = ordered(mergeSourceRows([], rows, entry.id));
        if (originals.length !== rows.length) throw new Error("Duplicate source object identity");
        const materialized = new Set(entry.expectedSources.map(key));
        if (originals.some(row => !materialized.has(key(row)))) throw new Error("Unmaterialized source evidence requires reconciliation before publication");
        entry.sameSources = originals.length === entry.sourceRows.length && originals.every((row, i) => row.equals(entry.sourceRows[i]));
      }
    }
  }
}

export async function upsertSourceRowsBatch(repository, incoming, { maxConflicts = 3, assertOwned = () => {} } = {}) {
  if (!Array.isArray(incoming) || !incoming.length || incoming.length > 200
      || !Number.isSafeInteger(maxConflicts) || maxConflicts < 0 || maxConflicts > 5) throw new Error("Invalid source upsert batch");
  const keys = incoming.map(key);
  if (new Set(keys).size !== keys.length) throw new Error("Duplicate source upsert identity");
  if (incoming.reduce((size, row) => size + row.length, 0) > MAX_OBJECT_BYTES) throw new Error("Source upsert exceeds byte budget");
  const service = repository.privateManifests; let pending = incoming;
  for (let attempt = 0; attempt <= maxConflicts; attempt++) {
    assertOwned(); await service.assertLease(); assertOwned();
    const ids = [...new Set(pending.map(row => originalRow(row).finding_id))];
    const contexts = await service.readSourceWriteContext(ids);
    const contextMap = new Map(contexts.map(row => [row.id, row]));
    if (contextMap.size !== ids.length || ids.some(id => !contextMap.has(id))) throw new Error("Invalid source context acknowledgement");
    const normalized = await service.prepareRows("source", contexts.flatMap(context => context.sourceRows), pending);
    if (!Array.isArray(normalized) || normalized.length !== pending.length || normalized.some((row, i) => key(row) !== key(pending[i]))) throw new Error("Invalid source normalization acknowledgement");
    const byId = new Map(ids.map(id => [id, []]));
    normalized.forEach(row => byId.get(originalRow(row).finding_id).push(row));
    let bytes = 0;
    const entries = ids.map(id => {
      const context = contextMap.get(id);
      if (originalRow(context.row).id !== id || typeof originalRow(context.row).suppressed !== "boolean") throw new Error("Invalid source parent row");
      const sourceRows = ordered(mergeSourceRows(context.sourceRows, byId.get(id), id));
      bytes += context.row.length + sourceRows.reduce((sum, row) => sum + row.length, 0);
      if (bytes > MAX_OBJECT_BYTES) throw new Error("Source publication exceeds byte budget");
      return { id, row: context.row, expectedRevision: context.revision, expectedSources: context.sourceRows,
        incoming: byId.get(id), sourceRows, finding: context.finding, sources: context.sources, sameFinding: false, sameSources: false };
    });
    await comparePublishedBodies(repository, entries, assertOwned);
    const changedFindings = entries.filter(entry => !entry.sameFinding);
    const changedSources = entries.filter(entry => !entry.sameSources);
    const findingPack = packFrames(changedFindings.map(entry => encodeFrame("finding", [entry.row])));
    const sourcePack = packFrames(changedSources.map(entry => encodeFrame("sources", entry.sourceRows)));
    changedFindings.forEach((entry, i) => { entry.finding = findingPack.pointers[i]; });
    changedSources.forEach((entry, i) => { entry.sources = sourcePack.pointers[i]; });
    assertOwned(); await repository.persistObjects([...findingPack.objects, ...sourcePack.objects], assertOwned); assertOwned();
    const acknowledgements = await service.commitSources(entries);
    if (!Array.isArray(acknowledgements) || acknowledgements.length !== entries.length) throw new Error("Invalid source commit acknowledgement");
    const saved = new Map();
    for (const row of acknowledgements) {
      if (!byId.has(row.id) || saved.has(row.id) || typeof row.saved !== "boolean") throw new Error("Invalid source commit acknowledgement");
      saved.set(row.id, row.saved);
    }
    assertOwned(); pending = pending.filter(row => !saved.get(originalRow(row).finding_id));
    if (!pending.length) return incoming.map(row => ({ finding_id: originalRow(row).finding_id }));
  }
  throw new Error("Concurrent source publication exceeded retry limit");
}

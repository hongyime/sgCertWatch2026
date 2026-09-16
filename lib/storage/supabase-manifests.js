// Experimental PostgREST clients. Neither factory reads process credentials or
// falls back from the anonymous key to the service key.
import { validatePointer } from "./evidence-frames.js";

function transport({ url, key, fetchImpl = fetch }) {
  const origin = new URL(url);
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.search || origin.hash
      || origin.pathname !== "/" || typeof key !== "string" || !key || /[\r\n]/.test(key)) {
    throw new Error("Invalid manifest configuration");
  }
  return async (path, query, body) => {
    const endpoint = new URL(`/rest/v1/${path}`, origin);
    for (const [name, value] of Object.entries(query ?? {})) endpoint.searchParams.set(name, value);
    const response = await fetchImpl(endpoint, {
      method: body ? "POST" : "GET", redirect: "error", signal: AbortSignal.timeout(8000),
      headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {})
    });
    if (!response.ok) { await response.body?.cancel(); throw new Error(`Manifest request failed: HTTP ${response.status}`); }
    return response.json();
  };
}

function decodedPointer(value) {
  // PostgREST renders bytea using PostgreSQL's default \x hex format. Batch
  // RPCs reconstruct JSON in SQL, so both transports share one external shape.
  if (typeof value === "string") {
    if (!/^\\x[a-f0-9]{80}$/.test(value)) throw new Error("Invalid binary manifest pointer");
    const raw = Buffer.from(value.slice(2), "hex");
    value = { object: raw.subarray(0, 32).toString("hex"),
      offset: raw.readUInt32BE(32), length: raw.readUInt32BE(36) };
  }
  validatePointer(value);
  return value;
}

function fromRow(rows, id, privateRead) {
  if (!Array.isArray(rows) || rows.length > 1) throw new Error("Invalid manifest row count");
  if (!rows.length) return null;
  const row = rows[0]; const revision = Number(row.revision);
  if (row.finding_id !== id || !Number.isSafeInteger(revision) || revision < 1) throw new Error("Invalid manifest identity/revision");
  const finding = decodedPointer(row.finding_pointer);
  const sources = privateRead && row.sources_pointer !== null ? decodedPointer(row.sources_pointer) : null;
  const suppressed = privateRead ? row.findings?.suppressed : false;
  if (typeof suppressed !== "boolean") throw new Error("Invalid manifest visibility");
  return { id, revision, suppressed, finding,
    ...(privateRead ? { sources } : {}) };
}

export function publicManifestReader({ url, anonKey, fetchImpl }) {
  const request = transport({ url, key: anonKey, fetchImpl });
  return { async get(id) {
    const rows = await request("evidence_object_manifests", {
      select: "finding_id,revision,finding_pointer", finding_id: `eq.${id}`, limit: "1"
    });
    return fromRow(rows, id, false);
  }, async getMany(ids) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 100) throw new Error("Invalid public page size");
    const requested = new Set(ids);
    const rows = await request("rpc/read_evidence_manifests", null, { p_ids: ids });
    if (!Array.isArray(rows) || rows.length > requested.size) throw new Error("Invalid manifest row count");
    const seen = new Set();
    return rows.map(row => {
      if (!requested.has(row.finding_id) || seen.has(row.finding_id)) throw new Error("Invalid manifest identity");
      seen.add(row.finding_id); return fromRow([row], row.finding_id, false);
    });
  } };
}

export function privateManifestStore({ url, serviceKey, fetchImpl }) {
  const request = transport({ url, key: serviceKey, fetchImpl });
  return {
    async get(id) {
      const rows = await request("evidence_object_manifests", {
        select: "finding_id,revision,finding_pointer,sources_pointer,findings!inner(suppressed)",
        finding_id: `eq.${id}`, limit: "1"
      });
      return fromRow(rows, id, true);
    },
    async compareAndSwap(id, expectedRevision, next) {
      const saved = await request("rpc/publish_evidence_manifest", null, {
        p_finding_id: id, p_expected_revision: expectedRevision, p_suppressed: next.suppressed,
        p_finding_pointer: next.finding, p_sources_pointer: next.sources
      });
      if (typeof saved !== "boolean") throw new Error("Invalid publication acknowledgement");
      return saved;
    },
    async compareAndSwapMany(entries) {
      if (!Array.isArray(entries) || !entries.length || entries.length > 200) throw new Error("Invalid publication batch");
      const rows = await request("rpc/publish_evidence_manifests", null, { p_publications: entries.map(entry => ({
        id: entry.id, expected_revision: entry.expectedRevision, suppressed: entry.next.suppressed,
        finding_pointer: entry.next.finding, sources_pointer: entry.next.sources
      })) });
      if (!Array.isArray(rows)) throw new Error("Invalid batch publication acknowledgement");
      return rows.map(row => ({ id: row.finding_id, saved: row.saved }));
    }
  };
}

// Private, immutable object transport. Credentials and object bodies stay server-side.
import { digest, MAX_OBJECT_BYTES } from "./evidence-frames.js";

async function boundedBody(response) {
  const advertised = response.headers.get("content-length");
  if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > MAX_OBJECT_BYTES)) {
    await response.body?.cancel(); throw new Error("Invalid object response size");
  }
  if (!response.body) throw new Error("Missing object response body");
  const reader = response.body.getReader(); const chunks = []; let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.length;
      if (size > MAX_OBJECT_BYTES) throw new Error("Object response exceeds size budget");
      chunks.push(Buffer.from(value));
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  if (advertised !== null && size !== Number(advertised)) throw new Error("Truncated object response");
  return Buffer.concat(chunks);
}

export class SupabasePrivateObjects {
  constructor({ url, serviceKey, bucket, fetchImpl = fetch }) {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash
        || parsed.pathname !== "/" || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(bucket)
        || typeof serviceKey !== "string" || !serviceKey || /[\r\n]/.test(serviceKey)) {
      throw new Error("Invalid private Storage configuration");
    }
    this.origin = parsed.origin; this.bucket = bucket; this.serviceKey = serviceKey; this.fetchImpl = fetchImpl;
  }

  async request(key, method, body) {
    if (typeof key !== "string" || !/^[a-f0-9]{64}$/.test(key)) throw new Error("Invalid immutable object key");
    const route = method === "GET" ? "object/authenticated" : "object";
    return this.fetchImpl(`${this.origin}/storage/v1/${route}/${this.bucket}/${key}`, {
      method, redirect: "error", signal: AbortSignal.timeout(10000),
      headers: { apikey: this.serviceKey, Authorization: `Bearer ${this.serviceKey}`,
        "Content-Type": "application/octet-stream", "x-upsert": "false", "Cache-Control": method === "GET" ? "no-store" : "max-age=0" },
      ...(body ? { body } : {})
    });
  }

  async read(key) {
    const response = await this.request(key, "GET");
    if (response.status !== 200) { await response.body?.cancel(); throw new Error(`Storage download failed: HTTP ${response.status}`); }
    const bytes = await boundedBody(response);
    if (digest(bytes) !== key) throw new Error("Stored object checksum mismatch");
    return bytes;
  }

  async putIfAbsent(key, bytes) {
    if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_OBJECT_BYTES || digest(bytes) !== key) {
      throw new Error("Invalid immutable object upload");
    }
    const response = await this.request(key, "POST", bytes);
    // Existing objects are never overwritten. On any ambiguous upload result,
    // callers stop; a later retry verifies the content-addressed object first.
    await response.body?.cancel();
    if (response.ok) return;
    if (response.status === 400 || response.status === 409) {
      // Storage versions report an existing path as 400 or 409. Status alone
      // proves nothing: only the exact content-addressed bytes make this retry
      // idempotent. Never turn an arbitrary 400 into a successful publication.
      await this.read(key); return;
    }
    throw new Error(`Storage upload failed: HTTP ${response.status}`);
  }
}

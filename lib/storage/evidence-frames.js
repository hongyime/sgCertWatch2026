// Experimental lossless storage codec. No live database/storage access.
import { createHash, timingSafeEqual } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";

export const MAX_OBJECT_BYTES = 4 * 1024 * 1024;
const HEADER_BYTES = 46;
const KINDS = Object.freeze({ finding: 1, sources: 2 });
const decoder = new TextDecoder("utf-8", { fatal: true });
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function originalRow(bytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_OBJECT_BYTES) {
    throw new Error("Invalid original row size");
  }
  let row;
  try { row = JSON.parse(decoder.decode(bytes)); } catch { throw new Error("Invalid original JSON row"); }
  if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("Expected a JSON object row");
  // Parsing is used only to validate identities. Never serialize this value to
  // replace original bytes: PostgreSQL JSONB numbers can exceed JS precision.
  return row;
}

export function encodeFrame(kind, rows) {
  if (!Object.hasOwn(KINDS, kind) || !Array.isArray(rows) || !rows.length || rows.length > 10000
      || (kind === "finding" && rows.length !== 1)) throw new Error("Invalid frame kind/count");
  let size = 4;
  for (const row of rows) {
    originalRow(row); size += 4 + row.length;
    if (size > MAX_OBJECT_BYTES) throw new Error("Frame exceeds decoding budget");
  }
  const raw = Buffer.alloc(size);
  raw.writeUInt32BE(rows.length); let position = 4;
  for (const row of rows) {
    raw.writeUInt32BE(row.length, position); position += 4;
    row.copy(raw, position); position += row.length;
  }
  const compressed = gzipSync(raw, { level: 9 });
  const header = Buffer.alloc(HEADER_BYTES);
  header.write("PCW1"); header[4] = 1; header[5] = KINDS[kind];
  header.writeUInt32BE(raw.length, 6); header.writeUInt32BE(compressed.length, 10);
  Buffer.from(digest(raw), "hex").copy(header, 14);
  const frame = Buffer.concat([header, compressed]);
  if (frame.length > MAX_OBJECT_BYTES) throw new Error("Frame exceeds object budget");
  return frame;
}

export function decodeFrame(frame, kind) {
  if (!Object.hasOwn(KINDS, kind) || !Buffer.isBuffer(frame) || frame.length < HEADER_BYTES
      || frame.length > MAX_OBJECT_BYTES) throw new Error("Invalid frame size/kind");
  if (frame.subarray(0, 4).toString() !== "PCW1" || frame[4] !== 1 || frame[5] !== KINDS[kind]) {
    throw new Error("Wrong frame identity or permission boundary");
  }
  const rawSize = frame.readUInt32BE(6); const compressedSize = frame.readUInt32BE(10);
  if (rawSize < 5 || rawSize > MAX_OBJECT_BYTES || compressedSize !== frame.length - HEADER_BYTES) {
    throw new Error("Invalid frame limits");
  }
  let raw;
  try { raw = gunzipSync(frame.subarray(HEADER_BYTES), { maxOutputLength: rawSize }); }
  catch { throw new Error("Invalid or over-budget compressed frame"); }
  if (raw.length !== rawSize || !timingSafeEqual(Buffer.from(digest(raw), "hex"), frame.subarray(14, 46))) {
    throw new Error("Frame checksum/length mismatch");
  }
  const count = raw.readUInt32BE();
  if (!count || count > 10000 || (kind === "finding" && count !== 1)) throw new Error("Invalid row count");
  let position = 4; const rows = [];
  for (let i = 0; i < count; i++) {
    if (position + 4 > raw.length) throw new Error("Incomplete row header");
    const length = raw.readUInt32BE(position); position += 4;
    if (!length || position + length > raw.length) throw new Error("Incomplete row");
    const row = Buffer.from(raw.subarray(position, position + length));
    originalRow(row); rows.push(row); position += length;
  }
  if (position !== raw.length) throw new Error("Trailing row data");
  return rows;
}

export function validatePointer(pointer) {
  if (!pointer || typeof pointer.object !== "string" || !/^[a-f0-9]{64}$/.test(pointer.object)
      || !Number.isSafeInteger(pointer.offset) || pointer.offset < 0
      || !Number.isSafeInteger(pointer.length) || pointer.length < HEADER_BYTES
      || pointer.offset + pointer.length > MAX_OBJECT_BYTES) throw new Error("Invalid object pointer");
}

export function readFrame(object, pointer, kind) {
  validatePointer(pointer);
  if (!Buffer.isBuffer(object) || object.length > MAX_OBJECT_BYTES || digest(object) !== pointer.object
      || pointer.offset + pointer.length > object.length) throw new Error("Object integrity failure");
  return decodeFrame(object.subarray(pointer.offset, pointer.offset + pointer.length), kind);
}

export function packFrames(frames) {
  const objects = []; const pointers = []; let chunks = []; let size = 0; let pending = [];
  function finish() {
    if (!size) return;
    const bytes = Buffer.concat(chunks); const key = digest(bytes);
    objects.push({ key, bytes });
    for (const pointer of pending) pointer.object = key;
    chunks = []; size = 0; pending = [];
  }
  for (const frame of frames) {
    if (!Buffer.isBuffer(frame) || frame.length < HEADER_BYTES || frame.length > MAX_OBJECT_BYTES) {
      throw new Error("Invalid frame for packing");
    }
    if (size + frame.length > MAX_OBJECT_BYTES) finish();
    const pointer = { object: null, offset: size, length: frame.length };
    pointers.push(pointer); pending.push(pointer); chunks.push(frame); size += frame.length;
  }
  finish(); return { objects, pointers };
}

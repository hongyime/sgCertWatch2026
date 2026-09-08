import crypto from "node:crypto";
import { fetchWithTimeout, pollTokens, sourceResult, toIsoTime } from "./common.js";

const HOUR_MS = 60 * 60 * 1000;
const TIMEOUT_MS = 20000;
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function boundedInteger(value, fallback, max) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(max, parsed) : fallback;
}

function retryAfterTime(value, now) {
  if (!value?.trim()) return 0;
  const seconds = Number(value);
  const time = Number.isFinite(seconds) ? now + Math.max(0, seconds) * 1000 : Date.parse(value);
  return Number.isFinite(time) && time <= 8640000000000000 ? time : 0;
}

export function crtShQueryUrl(token) {
  // Supported indexed identity search, not an exact or right-anchored match.
  const url = new URL("https://crt.sh/");
  url.searchParams.set("identity", token);
  url.searchParams.set("output", "json");
  url.searchParams.set("exclude", "expired");
  return url;
}

function crtRowToEntry(row, token) {
  const rawDomains = String(row.name_value || "")
    .split(/\s+/)
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);

  const isWildcard = rawDomains.some((d) => d.startsWith("*.") || d.includes("*"));
  const domains = rawDomains.map((d) => (d.startsWith("*.") ? d.slice(2) : d));
  const issuer = row.issuer_name || "";
  const issuerDnSha256 = issuer ? crypto.createHash("sha256").update(issuer).digest("hex") : null;

  return {
    dns_names: domains,
    common_name: row.common_name || domains[0] || "",
    not_before: toIsoTime(row.not_before || row.entry_timestamp),
    issuer: { aggregated: issuer },
    cert_index: row.id || row.min_cert_id || null,
    cert_link: row.id ? `https://crt.sh/?id=${row.id}` : `crtsh:${token}`,
    cert_serial: row.serial_number || String(row.id || ""),
    cert_issuer_dn_sha256: issuerDnSha256,
    entry_types: ["x509"],
    san_count: domains.length,
    is_wildcard: isWildcard,
    seen: row.entry_timestamp ? Date.parse(row.entry_timestamp) / 1000 : Date.now() / 1000,
    source: "crtsh",
    source_label: "crt.sh backup",
    source_ref: row.id ? `crtsh:${row.id}` : `crtsh:${token}`
  };
}

async function readRows(response) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("crt.sh returned an empty body instead of a JSON array");
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) throw new Error("crt.sh response exceeds 4 MiB budget");
      chunks.push(value);
    }
  } finally {
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  let rows;
  try {
    rows = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("crt.sh returned invalid JSON (possibly an upstream error page)");
  }
  if (!Array.isArray(rows)) throw new Error("crt.sh returned a non-array JSON response");
  return rows;
}

async function runCrtShSource({ data, state = {}, fetchImpl = fetch, now = Date.now(), timeoutMs = TIMEOUT_MS }) {
  const startedAt = Date.now();
  const tokens = pollTokens(data);
  const index = Number.isInteger(state.index) && state.index >= 0 ? state.index : 0;
  const start = tokens.length ? index % tokens.length : 0;
  const waiting = Date.parse(state.next_poll_at) > now;
  const batchSize = Math.min(tokens.length, boundedInteger(process.env.CRTSH_BATCH_SIZE, 1, 2));
  const resultLimit = boundedInteger(process.env.CRTSH_RESULT_LIMIT, 15, 100);
  const lookbackDays = boundedInteger(process.env.CRTSH_LOOKBACK_DAYS, 14, 90);
  const next = { ...state, index: start };
  const batch = [];
  const entries = [];
  const errors = [];
  let scannedEntries = 0;

  if (waiting) {
    if (next.last_error) errors.push(next.last_error);
  } else {
    for (let offset = 0; offset < batchSize; offset++) {
      const token = tokens[(start + offset) % tokens.length];
      batch.push(token);
      next.index = (start + offset + 1) % tokens.length;
      next.last_attempt_at = new Date(now).toISOString();
      try {
        const response = await fetchWithTimeout(crtShQueryUrl(token), {
          timeoutMs,
          fetchImpl,
          redirect: "error",
          headers: { Accept: "application/json", "User-Agent": "sgCertWatch/0.1 (+https://sgcertwatch.vercel.app)" }
        });
        if (!response.ok) {
          void response.body?.cancel().catch(() => {});
          const error = new Error(`crt.sh HTTP ${response.status}`);
          error.status = response.status;
          error.retryAt = retryAfterTime(response.headers.get("retry-after"), now);
          throw error;
        }
        const rows = await readRows(response);
        scannedEntries += rows.length;
        const cutoff = now - lookbackDays * 24 * HOUR_MS;
        const timestamp = (row) => Date.parse(row?.entry_timestamp || row?.not_before || "");
        entries.push(...rows
          .filter((row) => typeof row?.name_value === "string" && timestamp(row) >= cutoff)
          .sort((a, b) => timestamp(b) - timestamp(a))
          .slice(0, resultLimit)
          .map((row) => crtRowToEntry(row, token)));
        next.consecutive_failures = 0;
        next.last_error = null;
        next.last_success_at = next.last_attempt_at;
        next.next_poll_at = new Date(now + HOUR_MS).toISOString();
      } catch (error) {
        next.consecutive_failures = Math.min(10, boundedInteger(next.consecutive_failures, 0, 10) + 1);
        const cooldown = error.status === 429 ? 24 * HOUR_MS
          : Math.min(24, 2 ** (next.consecutive_failures - 1)) * HOUR_MS;
        next.next_poll_at = new Date(Math.max(now + cooldown, error.retryAt || 0)).toISOString();
        next.last_error = {
          token,
          message: error.name === "TimeoutError" || error.name === "AbortError"
            ? `crt.sh response timed out after ${timeoutMs} ms` : error.message,
          ...(error.status ? { status: error.status } : {})
        };
        errors.push(next.last_error);
        break; // Let a future run retry after the persisted cooldown.
      }
    }
  }

  const result = sourceResult({
    source: "crtsh",
    label: "crt.sh backup",
    startedAt,
    entries,
    scannedEntries,
    errors,
    details: {
      batch,
      state: !tokens.length ? "unconfigured" : errors.length ? "cooldown" : waiting ? "scheduled" : "active",
      optional: true,
      skipped: waiting,
      last_attempt_at: next.last_attempt_at || null,
      last_success_at: next.last_success_at || null,
      next_poll_at: next.next_poll_at || null,
      consecutive_failures: next.consecutive_failures || 0,
      circuit_breaker_open: errors.length > 0,
      note: !tokens.length ? "No search tokens configured" : errors.length
        ? "Optional backup unavailable; direct and static CT polling continue independently."
        : "Optional comparison source; at most one batch per hour."
    },
    statePatch: { crtsh: next }
  });
  if (!tokens.length) result.ok = false;
  return result;
}

export {
  crtRowToEntry,
  runCrtShSource
};

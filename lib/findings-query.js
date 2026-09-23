/**
 * lib/findings-query.js
 *
 * Pure query builder for the bounded historical search API (Task 8).
 * No DOM, no fetch, no side effects.
 *
 * Validates and normalises search parameters, builds a size-bounded
 * cursor envelope, and encodes / decodes pagination state.  The cursor
 * is pagination state only — never authorisation.
 */

const SEVERITY_ENUM = new Set(["", "critical", "high", "medium", "low"]);
const VERDICT_ENUM  = new Set(["", "phishing", "malware", "observed"]);
const SOURCE_ENUM   = new Set(["", "openphish", "urlscan", "urlhaus", "threatfox"]);
const SORT_ENUM     = new Set(["observed", "priority"]);

const CURSOR_VERSION  = 1;
const CURSOR_TTL_MS   = 15 * 60 * 1000;         // 15 minutes
const CURSOR_MAX_BYTES = 1024;                  // hard upper bound on the encoded envelope
const Q_MAX_LEN       = 253;
const BRAND_MAX_LEN   = 64;

function boundInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

/**
 * Validate and normalise raw query parameters from the request.
 * @param {Record<string, string|undefined>} raw
 * @returns {{ ok: true, params: object } | { ok: false, error: string, message: string }}
 */
export function parseSearchParams(raw) {
  const rawQ = typeof raw.q === "string" ? raw.q : "";
  const q = rawQ.length > Q_MAX_LEN ? "" : rawQ;
  if (rawQ.length > Q_MAX_LEN) {
    return { ok: false, error: "query_too_long", message: `q must be at most ${Q_MAX_LEN} characters` };
  }

  const brand_id = typeof raw.brand_id === "string" ? raw.brand_id.slice(0, BRAND_MAX_LEN) : "";

  if (q.length > 0 && q.length < 3 && !brand_id) {
    return { ok: false, error: "query_too_short", message: "q must be at least 3 characters or use brand_id" };
  }

  const severity = raw.severity ?? "";
  if (!SEVERITY_ENUM.has(severity)) {
    return { ok: false, error: "invalid_severity", message: `severity must be one of: ${[...SEVERITY_ENUM].filter(Boolean).join(", ")}` };
  }

  const verdict = raw.verdict ?? "";
  if (!VERDICT_ENUM.has(verdict)) {
    return { ok: false, error: "invalid_verdict", message: `verdict must be one of: ${[...VERDICT_ENUM].filter(Boolean).join(", ")}` };
  }

  const source = raw.source ?? "";
  if (!SOURCE_ENUM.has(source)) {
    return { ok: false, error: "invalid_source", message: `source must be one of: ${[...SOURCE_ENUM].filter(Boolean).join(", ")}` };
  }

  const sort = raw.sort ?? "observed";
  if (!SORT_ENUM.has(sort)) {
    return { ok: false, error: "invalid_sort", message: `sort must be one of: ${[...SORT_ENUM].join(", ")}` };
  }

  const limit = boundInt(raw.limit ?? 50, 50, 1, 100);

  const from_at = typeof raw.from_at === "string" ? raw.from_at : "";
  const to_at   = typeof raw.to_at   === "string" ? raw.to_at   : "";
  if (from_at && !Number.isFinite(Date.parse(from_at))) {
    return { ok: false, error: "invalid_from_at", message: "from_at must be an ISO 8601 timestamp" };
  }
  if (to_at && !Number.isFinite(Date.parse(to_at))) {
    return { ok: false, error: "invalid_to_at", message: "to_at must be an ISO 8601 timestamp" };
  }

  // priority_min / priority_max: optional bounded integers
  let priority_min = null;
  let priority_max = null;
  if (raw.priority_min !== undefined && raw.priority_min !== "") {
    const n = Number(raw.priority_min);
    if (!Number.isInteger(n) || n < 0 || n > 200) {
      return { ok: false, error: "invalid_priority_min", message: "priority_min must be an integer between 0 and 200" };
    }
    priority_min = n;
  }
  if (raw.priority_max !== undefined && raw.priority_max !== "") {
    const n = Number(raw.priority_max);
    if (!Number.isInteger(n) || n < 0 || n > 200) {
      return { ok: false, error: "invalid_priority_max", message: "priority_max must be an integer between 0 and 200" };
    }
    priority_max = n;
  }
  if (priority_min !== null && priority_max !== null && priority_min > priority_max) {
    return { ok: false, error: "invalid_priority_range", message: "priority_min must be <= priority_max" };
  }

  return {
    ok: true,
    params: { q, severity, verdict, source, sort, limit, brand_id, from_at, to_at, priority_min, priority_max },
  };
}

/**
 * Canonicalise the filter subset that a cursor binds to.  Keeping this
 * deterministic + size-bounded prevents cursors from being used to smuggle
 * data or grow unbounded.
 * @private
 */
function canonicalFilters(params) {
  return {
    q:            params.q            ?? "",
    severity:     params.severity     ?? "",
    verdict:      params.verdict      ?? "",
    source:       params.source       ?? "",
    sort:         params.sort         ?? "observed",
    brand_id:     params.brand_id     ?? "",
    from_at:      params.from_at      ?? "",
    to_at:        params.to_at        ?? "",
    priority_min: params.priority_min ?? null,
    priority_max: params.priority_max ?? null,
  };
}

/**
 * Encode a cursor envelope.  The envelope is size-bounded ( <= 1 KiB ).
 * @param {{ params: object, last_id: string, last_observed_at: string, last_priority: number, evaluated_at: string }} state
 * @returns {string} base64url-encoded JSON
 */
export function encodeCursor(state) {
  const envelope = {
    v: CURSOR_VERSION,
    p: canonicalFilters(state.params),
    last_id:          String(state.last_id).slice(0, 64),
    last_observed_at: String(state.last_observed_at).slice(0, 40),
    last_priority:    Number.isFinite(state.last_priority) ? Math.trunc(state.last_priority) : 0,
    evaluated_at:     String(state.evaluated_at).slice(0, 40),
    expires_at:       new Date(Date.now() + CURSOR_TTL_MS).toISOString(),
  };
  const encoded = Buffer.from(JSON.stringify(envelope)).toString("base64url");
  if (encoded.length > CURSOR_MAX_BYTES) {
    throw new Error("cursor_envelope_too_large");
  }
  return encoded;
}

/**
 * Decode and validate a cursor envelope.
 * @param {string} cursor
 * @param {object} currentParams
 * @returns {{ ok: true, state: object } | { ok: false, error: string }}
 */
export function decodeCursor(cursor, currentParams) {
  if (typeof cursor !== "string" || cursor.length === 0 || cursor.length > CURSOR_MAX_BYTES) {
    return { ok: false, error: "cursor_malformed" };
  }
  let raw;
  try {
    raw = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
  } catch {
    return { ok: false, error: "cursor_malformed" };
  }
  if (!raw || typeof raw !== "object") return { ok: false, error: "cursor_malformed" };
  if (raw.v !== CURSOR_VERSION) return { ok: false, error: "cursor_version_mismatch" };
  const expiresAtMs = Date.parse(raw.expires_at);
  if (!raw.expires_at || !Number.isFinite(expiresAtMs)) {
    return { ok: false, error: "cursor_malformed" };
  }
  if (expiresAtMs <= Date.now()) {
    return { ok: false, error: "cursor_expired" };
  }
  if (typeof raw.last_id !== "string" || raw.last_id.length === 0 || raw.last_id.length > 64) {
    return { ok: false, error: "cursor_malformed" };
  }
  if (typeof raw.last_observed_at !== "string" || !Number.isFinite(Date.parse(raw.last_observed_at))) {
    return { ok: false, error: "cursor_malformed" };
  }
  const wantP = canonicalFilters(currentParams ?? {});
  const gotP  = canonicalFilters(raw.p ?? {});
  for (const k of Object.keys(wantP)) {
    if (JSON.stringify(wantP[k]) !== JSON.stringify(gotP[k])) {
      return { ok: false, error: "cursor_filter_mismatch" };
    }
  }
  return { ok: true, state: raw };
}

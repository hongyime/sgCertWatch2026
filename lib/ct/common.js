function compact(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function normalizeHost(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.$/, "");
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function pollTokens(data) {
  const brandTokens = data.watchlist.brands
    .flatMap((brand) => brand.tokens || [])
    .filter((token) => compact(token).length >= 3);
  const schemeTokens = data.schemes.schemes.flatMap((scheme) => scheme.tokens || []);
  return unique([...schemeTokens, ...brandTokens]).sort();
}

function toIsoTime(value) {
  if (!value) return null;
  const numeric = Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric * 1000)
    : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

async function fetchWithTimeout(url, options = {}) {
  const { timeoutMs = 10000, fetchImpl = fetch, signal, ...fetchOptions } = options;
  // Keep the deadline active through response-body consumption, not just headers.
  const deadline = AbortSignal.timeout(timeoutMs);
  return fetchImpl(url, {
    ...fetchOptions,
    signal: signal ? AbortSignal.any([signal, deadline]) : deadline
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetchWithTimeout(url, options);
  if (!response.ok) {
    throw new Error(`${new URL(String(url)).hostname} ${response.status}`);
  }
  return response.json();
}

function retryAfterTime(value, now = Date.now()) {
  if (!value?.trim()) return 0;
  const seconds = Number(value);
  const time = Number.isFinite(seconds) ? now + Math.max(0, seconds) * 1000 : Date.parse(value);
  return Number.isFinite(time) && time <= 8640000000000000 ? time : 0;
}

function httpResponseError(response, message) {
  const error = new Error(message);
  error.status = response.status;
  error.retry_at = retryAfterTime(response.headers.get("retry-after"));
  void response.body?.cancel().catch(() => {});
  return error;
}

function sourceResult({
  source,
  label,
  startedAt,
  entries = [],
  scannedEntries = entries.length,
  errors = [],
  details = {},
  statePatch = null
}) {
  const durationMs = Date.now() - startedAt;
  return {
    source,
    label,
    ok: errors.length === 0 && scannedEntries >= 0,
    entries,
    scanned_entries: scannedEntries,
    errors,
    duration_ms: durationMs,
    details,
    statePatch
  };
}

export {
  compact,
  fetchJson,
  fetchWithTimeout,
  httpResponseError,
  normalizeHost,
  pollTokens,
  retryAfterTime,
  sourceResult,
  toIsoTime,
  unique
};

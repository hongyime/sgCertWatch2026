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
  const { timeoutMs = 10000, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...fetchOptions,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetchWithTimeout(url, options);
  if (!response.ok) {
    throw new Error(`${new URL(String(url)).hostname} ${response.status}`);
  }
  return response.json();
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
  normalizeHost,
  pollTokens,
  sourceResult,
  toIsoTime,
  unique
};

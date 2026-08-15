import { fetchWithTimeout, pollTokens, sourceResult, toIsoTime } from "./common.js";

const BATCH_SIZE = Number(process.env.CRTSH_BATCH_SIZE || 2);
const RESULT_LIMIT = Number(process.env.CRTSH_RESULT_LIMIT || 15);
const LOOKBACK_DAYS = Number(process.env.CRTSH_LOOKBACK_DAYS || 14);

function crtRowToEntry(row, token) {
  const domains = String(row.name_value || "")
    .split(/\s+/)
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);

  return {
    dns_names: domains,
    common_name: row.common_name || domains[0] || "",
    not_before: toIsoTime(row.not_before || row.entry_timestamp),
    issuer: { aggregated: row.issuer_name || "" },
    cert_index: row.id || row.min_cert_id || null,
    cert_link: row.id ? `https://crt.sh/?id=${row.id}` : `crtsh:${token}`,
    seen: row.entry_timestamp ? Date.parse(row.entry_timestamp) / 1000 : Date.now() / 1000,
    source: "crtsh",
    source_label: "crt.sh backup",
    source_ref: row.id ? `crtsh:${row.id}` : `crtsh:${token}`
  };
}

async function fetchCrtSh(url) {
  return fetchWithTimeout(url, {
    timeoutMs: 12000,
    headers: { "User-Agent": "sgCertWatch/0.1 (+https://sgcertwatch.vercel.app)" }
  });
}

async function queryCrtSh(token) {
  const url = new URL("https://crt.sh/");
  url.searchParams.set("q", `%${token}%`);
  url.searchParams.set("output", "json");

  let response;
  try {
    response = await fetchCrtSh(url);
  } catch (_error) {
    response = await fetchCrtSh(url);
  }

  if (response.status === 404) {
    return [];
  }

  if (!response.ok) {
    if ([502, 503, 504].includes(response.status)) {
      response = await fetchCrtSh(url);
    }
    if (!response.ok) {
      throw new Error(`crt.sh ${response.status}`);
    }
  }

  const rows = await response.json();
  const cutoff = Date.now() - LOOKBACK_DAYS * 24 * 60 * 60 * 1000;
  return rows
    .filter((row) => {
      const timestamp = Date.parse(row.entry_timestamp || row.not_before || "");
      return Number.isNaN(timestamp) || timestamp >= cutoff;
    })
    .slice(0, RESULT_LIMIT)
    .map((row) => crtRowToEntry(row, token));
}

async function runCrtShSource({ data, state = {} }) {
  const startedAt = Date.now();
  const tokens = pollTokens(data);
  const start = Number(state.index || 0) % tokens.length;
  const batch = Array.from({ length: BATCH_SIZE }, (_, offset) => tokens[(start + offset) % tokens.length]);
  const entries = [];
  const errors = [];

  for (const token of batch) {
    try {
      entries.push(...await queryCrtSh(token));
    } catch (error) {
      errors.push({ token, message: error.message });
    }
  }

  return sourceResult({
    source: "crtsh",
    label: "crt.sh backup",
    startedAt,
    entries,
    scannedEntries: entries.length,
    errors,
    details: { batch },
    statePatch: { crtsh: { index: (start + BATCH_SIZE) % tokens.length } }
  });
}

export {
  crtRowToEntry,
  runCrtShSource
};

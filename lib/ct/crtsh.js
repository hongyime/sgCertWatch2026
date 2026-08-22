import crypto from "node:crypto";
import { fetchWithTimeout, pollTokens, sourceResult, toIsoTime } from "./common.js";

const BATCH_SIZE = Number(process.env.CRTSH_BATCH_SIZE || 2);
const RESULT_LIMIT = Number(process.env.CRTSH_RESULT_LIMIT || 15);
const LOOKBACK_DAYS = Number(process.env.CRTSH_LOOKBACK_DAYS || 14);
const TIMEOUT_MS = 10000;
const BREAKER_RESET_MS = 30 * 60 * 1000; // 30 mins

let consecutiveFailures = 0;
let circuitBreakerOpenUntil = 0;

export function isCircuitBreakerOpen(now = Date.now()) {
  return now < circuitBreakerOpenUntil;
}

export function recordSuccess() {
  consecutiveFailures = 0;
  circuitBreakerOpenUntil = 0;
}

export function recordFailure(now = Date.now()) {
  consecutiveFailures += 1;
  if (consecutiveFailures >= 3) {
    circuitBreakerOpenUntil = now + BREAKER_RESET_MS;
  }
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

async function fetchWithBackoff(url, retries = 3) {
  let lastError = null;
  for (let i = 0; i <= retries; i++) {
    try {
      const response = await fetchWithTimeout(url, {
        timeoutMs: TIMEOUT_MS,
        headers: { "User-Agent": "sgCertWatch/0.1 (+https://sgcertwatch.vercel.app)" }
      });
      if (response.ok || response.status === 404) {
        return response;
      }
      lastError = new Error(`crt.sh status ${response.status}`);
    } catch (err) {
      lastError = err;
    }
    if (i < retries) {
      const delay = Math.min(8000, 1000 * Math.pow(2, i));
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError || new Error("crt.sh request failed");
}

async function queryCrtSh(token) {
  if (isCircuitBreakerOpen()) {
    throw new Error("crt.sh circuit breaker is OPEN (skipping for 30 minutes)");
  }

  // Right-anchored identity query instead of full %token% wildcard
  const url = new URL("https://crt.sh/");
  url.searchParams.set("identity", token);
  url.searchParams.set("output", "json");

  try {
    const response = await fetchWithBackoff(url);
    if (response.status === 404) {
      recordSuccess();
      return [];
    }

    const rows = await response.json();
    recordSuccess();

    const cutoff = Date.now() - LOOKBACK_DAYS * 24 * 60 * 60 * 1000;
    return rows
      .filter((row) => {
        const timestamp = Date.parse(row.entry_timestamp || row.not_before || "");
        return Number.isNaN(timestamp) || timestamp >= cutoff;
      })
      .slice(0, RESULT_LIMIT)
      .map((row) => crtRowToEntry(row, token));
  } catch (error) {
    recordFailure();
    throw error;
  }
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
    details: {
      batch,
      circuit_breaker_open: isCircuitBreakerOpen()
    },
    statePatch: { crtsh: { index: (start + BATCH_SIZE) % tokens.length } }
  });
}

export {
  crtRowToEntry,
  runCrtShSource
};

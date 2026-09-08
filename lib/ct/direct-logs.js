import { X509Certificate } from "node:crypto";
import { fetchJson, normalizeHost, sourceResult, toIsoTime } from "./common.js";
import { fetchDynamicLogList, isLogSelected, normalizeLogUrl, intervalOverlapsWindow } from "./loglist.js";

const LOGS_PER_RUN = Number(process.env.DIRECT_CT_LOGS_PER_RUN || 2);
const ENTRIES_PER_LOG = Number(process.env.DIRECT_CT_ENTRIES_PER_LOG || 48);
const INITIAL_TAIL = Number(process.env.DIRECT_CT_INITIAL_TAIL || 256);
const RATE_LIMIT_COOLDOWN_MS = 3600000;

function readUint24(buffer, offset) {
  return (buffer[offset] << 16) + (buffer[offset + 1] << 8) + buffer[offset + 2];
}

function stateIsReadable(state) {
  return Boolean(state?.usable || state?.qualified || state?.readonly);
}

function intervalIsCurrent(interval, now = Date.now()) {
  return intervalOverlapsWindow(interval, now);
}

function usableRfc6962Logs(logList) {
  return (logList.operators || [])
    .flatMap((operator) => (operator.logs || []).map((log) => ({
      operator: operator.name,
      description: log.description,
      url: normalizeLogUrl(log.url),
      state: log.state || {},
      temporal_interval: log.temporal_interval || null
    })))
    .filter((log) => log.url.startsWith("https://"))
    .filter((log) => stateIsReadable(log.state))
    .filter((log) => intervalOverlapsWindow(log.temporal_interval))
    .filter((log) => !log.url.includes("ct.example.com"))
    .sort((a, b) => `${a.operator} ${a.description}`.localeCompare(`${b.operator} ${b.description}`));
}

function extractDnsNames(subjectAltName) {
  return [...String(subjectAltName || "").matchAll(/DNS:([^,\n]+)/g)]
    .map((match) => normalizeHost(match[1]))
    .filter((domain) => domain.includes("."));
}

function extractCommonName(subject) {
  const match = String(subject || "").match(/(?:^|\n|,\s*)CN\s*=\s*([^,\n]+)/);
  return match ? normalizeHost(match[1]) : "";
}

import crypto from "node:crypto";
import { wrapTbsDer } from "./static/tiles.js";

function extractX509DerFromLeafInput(leafInput) {
  const leaf = Buffer.isBuffer(leafInput) ? leafInput : Buffer.from(leafInput || "", "base64");
  if (leaf.length < 15) return null;
  const timestampMs = Number(leaf.readBigUInt64BE(2));
  const entryType = leaf.readUInt16BE(10);

  if (entryType === 0) {
    const certLength = readUint24(leaf, 12);
    const certStart = 15;
    const certEnd = certStart + certLength;
    if (certLength <= 0 || certEnd > leaf.length) return null;
    return {
      timestampMs,
      der: leaf.subarray(certStart, certEnd),
      isPrecert: false
    };
  }

  if (entryType === 1) {
    if (leaf.length < 47) return null;
    const tbsLength = readUint24(leaf, 44);
    const tbsStart = 47;
    const tbsEnd = tbsStart + tbsLength;
    if (tbsLength <= 0 || tbsEnd > leaf.length) return null;
    const tbsDer = leaf.subarray(tbsStart, tbsEnd);
    return {
      timestampMs,
      der: wrapTbsDer(tbsDer),
      isPrecert: true
    };
  }

  return null;
}

function directLogEntryToEntry(rawEntry, log, index) {
  const extracted = extractX509DerFromLeafInput(rawEntry.leaf_input);
  if (!extracted) throw new Error(`Invalid RFC6962 leaf at index ${index}`);

  try {
    const cert = new X509Certificate(extracted.der);
    const commonName = extractCommonName(cert.subject);
    const rawDnsNames = [...new Set([...extractDnsNames(cert.subjectAltName), commonName].filter(Boolean))];
    if (!rawDnsNames.length) return null;

    const isWildcard = rawDnsNames.some((d) => d.startsWith("*.") || d.includes("*"));
    const dnsNames = rawDnsNames.map((d) => (d.startsWith("*.") ? d.slice(2) : d));
    const issuerDnSha256 = crypto.createHash("sha256").update(cert.issuer).digest("hex");

    return {
      dns_names: dnsNames,
      common_name: commonName || dnsNames[0],
      not_before: toIsoTime(cert.validFrom),
      issuer: { aggregated: cert.issuer },
      cert_index: index,
      cert_link: `${log.url}ct/v1/get-entries?start=${index}&end=${index}`,
      cert_fingerprint: cert.fingerprint256?.replaceAll(":", "").toLowerCase(),
      cert_serial: cert.serialNumber || null,
      cert_issuer_dn_sha256: issuerDnSha256,
      entry_types: [extracted.isPrecert ? "precert" : "x509"],
      san_count: dnsNames.length,
      is_wildcard: isWildcard,
      seen: extracted.timestampMs / 1000,
      source: "direct_ct",
      source_label: extracted.isPrecert ? "Direct CT (Precert)" : "Direct CT logs",
      source_ref: `${log.url}:${index}`,
      log_name: log.description,
      log_operator: log.operator,
      protocol: "rfc6962"
    };
  } catch (error) {
    throw new Error(`Invalid RFC6962 certificate at index ${index}: ${error.message}`, { cause: error });
  }
}

async function fetchLogEntries(log, cursor) {
  const sth = await fetchJson(`${log.url}ct/v1/get-sth`, { timeoutMs: 8000 });
  const treeSize = sth?.tree_size;
  if (!Number.isSafeInteger(treeSize) || treeSize < 0) {
    throw new Error("Invalid RFC6962 tree size");
  }
  const savedNext = cursor?.next == null ? null : Number(cursor.next);
  if (savedNext !== null && (!Number.isSafeInteger(savedNext) || savedNext < 0)) {
    throw new Error("Invalid RFC6962 saved cursor");
  }
  if (savedNext !== null && treeSize < savedNext) {
    throw new Error("RFC6962 tree size is behind the saved cursor");
  }
  const start = savedNext ?? Math.max(0, treeSize - INITIAL_TAIL);
  if (start >= treeSize) {
    return { scanned: 0, entries: [], next: treeSize, treeSize };
  }

  const end = Math.min(treeSize - 1, start + ENTRIES_PER_LOG - 1);
  const payload = await fetchJson(`${log.url}ct/v1/get-entries?start=${start}&end=${end}`, { timeoutMs: 12000 });
  const rawEntries = payload?.entries;
  if (!Array.isArray(rawEntries) || !rawEntries.length || rawEntries.length > end - start + 1
    || rawEntries.some((entry) => typeof entry?.leaf_input !== "string" || !entry.leaf_input)) {
    throw new Error("Invalid RFC6962 entries response");
  }
  const entries = rawEntries
    .map((entry, offset) => directLogEntryToEntry(entry, log, start + offset))
    .filter(Boolean);

  return {
    scanned: rawEntries.length,
    entries,
    next: start + rawEntries.length,
    treeSize
  };
}

async function runDirectCtSource({ state = {} }) {
  const startedAt = Date.now();
  const errors = [];
  const entries = [];
  const cursors = { ...(state.cursors || {}) };
  const cooldowns = Object.fromEntries(Object.entries(state.cooldowns || {})
    .filter(([, until]) => Date.parse(until) > startedAt));

  let logs = [];
  try {
    const listResult = await fetchDynamicLogList();
    logs = listResult.selectedLogs
      .filter((l) => l.protocol === "rfc6962")
      .map((l) => ({
        operator: l.operator,
        description: l.description,
        url: normalizeLogUrl(l.submission_url || l.monitoring_url),
        log_id: l.log_id,
        state: { [l.state]: {} }
      }));
  } catch (err) {
    errors.push({ message: `Dynamic log list fetch failed: ${err.message}` });
  }

  if (!logs.length && !errors.length) {
    errors.push({ message: "No readable RFC6962 logs found" });
  }

  const savedIndex = Number.isSafeInteger(Number(state.index)) && Number(state.index) >= 0 ? Number(state.index) : 0;
  const start = logs.length ? savedIndex % logs.length : savedIndex;
  const batch = [];
  let visitedLogs = 0;
  let cooldownSkipped = 0;
  let scannedEntries = 0;
  let successfulLogCount = 0;

  // Paused siblings do not consume the attempt budget for healthy operators.
  for (let offset = 0; offset < logs.length && batch.length < LOGS_PER_RUN; offset += 1) {
    const log = logs[(start + offset) % logs.length];
    visitedLogs += 1;
    const operator = log.operator || new URL(log.url).hostname;
    const retryAt = Date.parse(cooldowns[operator]);
    if (retryAt > Date.now()) {
      cooldownSkipped += 1;
      errors.push({ log: log.description, operator, status: 429, retry_at: retryAt,
        message: `Operator rate limit; retry after ${cooldowns[operator]}` });
      continue;
    }
    batch.push(log);
    try {
      const result = await fetchLogEntries(log, cursors[log.url]);
      successfulLogCount += 1;
      scannedEntries += result.scanned;
      entries.push(...result.entries);
      cursors[log.url] = {
        next: result.next,
        tree_size: result.treeSize,
        checked_at: new Date().toISOString()
      };
    } catch (error) {
      if (error.status === 429) {
        cooldowns[operator] = new Date(Math.max(Date.now() + RATE_LIMIT_COOLDOWN_MS,
          error.retry_at || 0, Date.parse(cooldowns[operator]) || 0)).toISOString();
      }
      errors.push({ log: log.description, operator, message: error.message,
        status: error.status, retry_at: error.retry_at });
    }
  }

  return sourceResult({
    source: "direct_ct",
    label: "Direct CT logs",
    startedAt,
    entries,
    scannedEntries,
    errors,
    details: {
      log_count: logs.length,
      batch: batch.map((log) => log.description),
      attempted_log_count: batch.length,
      cooldown_skipped_log_count: cooldownSkipped,
      cooldown_operator_count: Object.keys(cooldowns).length,
      next_retry_at: Object.values(cooldowns).sort()[0] || null,
      successful_log_count: successfulLogCount,
      parsed_entries: entries.length
    },
    statePatch: {
      direct_ct: {
        index: logs.length ? (start + visitedLogs) % logs.length : savedIndex,
        cursors,
        cooldowns
      }
    }
  });
}

export {
  directLogEntryToEntry,
  extractX509DerFromLeafInput,
  intervalIsCurrent,
  runDirectCtSource,
  usableRfc6962Logs
};

import { X509Certificate } from "node:crypto";
import { fetchJson, normalizeHost, sourceResult, toIsoTime } from "./common.js";
import { fetchDynamicLogList, isLogSelected, normalizeLogUrl, intervalOverlapsWindow } from "./loglist.js";

const LOGS_PER_RUN = Number(process.env.DIRECT_CT_LOGS_PER_RUN || 2);
const ENTRIES_PER_LOG = Number(process.env.DIRECT_CT_ENTRIES_PER_LOG || 48);
const INITIAL_TAIL = Number(process.env.DIRECT_CT_INITIAL_TAIL || 256);

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

function extractX509DerFromLeafInput(leafInput) {
  const leaf = Buffer.isBuffer(leafInput) ? leafInput : Buffer.from(leafInput || "", "base64");
  if (leaf.length < 15) return null;
  const entryType = leaf.readUInt16BE(10);
  if (entryType !== 0) return null;

  const certLength = readUint24(leaf, 12);
  const certStart = 15;
  const certEnd = certStart + certLength;
  if (certLength <= 0 || certEnd > leaf.length) return null;
  return {
    timestampMs: Number(leaf.readBigUInt64BE(2)),
    der: leaf.subarray(certStart, certEnd)
  };
}

function directLogEntryToEntry(rawEntry, log, index) {
  const extracted = extractX509DerFromLeafInput(rawEntry.leaf_input);
  if (!extracted) return null;

  const cert = new X509Certificate(extracted.der);
  const commonName = extractCommonName(cert.subject);
  const dnsNames = [...new Set([...extractDnsNames(cert.subjectAltName), commonName].filter(Boolean))];
  if (!dnsNames.length) return null;

  return {
    dns_names: dnsNames,
    common_name: commonName || dnsNames[0],
    not_before: toIsoTime(cert.validFrom),
    issuer: { aggregated: cert.issuer },
    cert_index: index,
    cert_link: `${log.url}ct/v1/get-entries?start=${index}&end=${index}`,
    cert_fingerprint: cert.fingerprint256?.replaceAll(":", "").toLowerCase(),
    seen: extracted.timestampMs / 1000,
    source: "direct_ct",
    source_label: "Direct CT logs",
    source_ref: `${log.url}:${index}`,
    log_name: log.description,
    log_operator: log.operator
  };
}

async function fetchLogEntries(log, cursor) {
  const sth = await fetchJson(`${log.url}ct/v1/get-sth`, { timeoutMs: 8000 });
  const treeSize = Number(sth.tree_size || 0);
  if (!treeSize) {
    return { scanned: 0, entries: [], next: 0, treeSize };
  }

  const start = Number.isFinite(Number(cursor?.next))
    ? Math.min(Number(cursor.next), treeSize)
    : Math.max(0, treeSize - INITIAL_TAIL);
  if (start >= treeSize) {
    return { scanned: 0, entries: [], next: treeSize, treeSize };
  }

  const end = Math.min(treeSize - 1, start + ENTRIES_PER_LOG - 1);
  const payload = await fetchJson(`${log.url}ct/v1/get-entries?start=${start}&end=${end}`, { timeoutMs: 12000 });
  const rawEntries = payload.entries || [];
  const entries = rawEntries
    .map((entry, offset) => {
      try {
        return directLogEntryToEntry(entry, log, start + offset);
      } catch (_error) {
        return null;
      }
    })
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

  if (!logs.length) {
    return sourceResult({
      source: "direct_ct",
      label: "Direct CT logs",
      startedAt,
      entries,
      scannedEntries: 0,
      errors: errors.length ? errors : [{ message: "No readable RFC6962 logs found" }],
      details: { log_count: logs.length },
      statePatch: { direct_ct: { index: 0, cursors: state.cursors || {} } }
    });
  }

  const start = Number(state.index || 0) % logs.length;
  const batch = Array.from({ length: Math.min(LOGS_PER_RUN, logs.length) }, (_, offset) => logs[(start + offset) % logs.length]);
  const cursors = { ...(state.cursors || {}) };
  let scannedEntries = 0;

  for (const log of batch) {
    try {
      const result = await fetchLogEntries(log, cursors[log.url]);
      scannedEntries += result.scanned;
      entries.push(...result.entries);
      cursors[log.url] = {
        next: result.next,
        tree_size: result.treeSize,
        checked_at: new Date().toISOString()
      };
    } catch (error) {
      errors.push({ log: log.description, message: error.message });
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
      batch: batch.map((log) => log.description),
      parsed_entries: entries.length
    },
    statePatch: {
      direct_ct: {
        index: (start + batch.length) % logs.length,
        cursors
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

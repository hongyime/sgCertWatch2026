import crypto from "node:crypto";
import { fetchJson, toIsoTime } from "./common.js";

export const CERTSPOTTER_LOG_LIST_URL = "https://loglist.certspotter.org/monitor.json";
export const GOOGLE_V3_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

export const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

export function normalizeLogUrl(url) {
  return String(url || "").replace(/\/?$/, "/");
}

export function computeLogIdFromKey(publicKeyDerBase64) {
  if (!publicKeyDerBase64) return "";
  try {
    const der = Buffer.from(publicKeyDerBase64, "base64");
    return crypto.createHash("sha256").update(der).digest("base64");
  } catch (_e) {
    return "";
  }
}

/**
 * Determine if a log's temporal interval overlaps [now - 1 day, now + 400 days],
 * or if the log is unsharded.
 */
export function intervalOverlapsWindow(interval, nowMs = Date.now()) {
  if (!interval || (!interval.start_inclusive && !interval.end_exclusive)) {
    return true; // unsharded
  }
  const windowStart = nowMs - 1 * 24 * 60 * 60 * 1000;
  const windowEnd = nowMs + 400 * 24 * 60 * 60 * 1000;

  const shardStart = interval.start_inclusive ? Date.parse(interval.start_inclusive) : -Infinity;
  const shardEnd = interval.end_exclusive ? Date.parse(interval.end_exclusive) : Infinity;

  return Math.max(windowStart, shardStart) < Math.min(windowEnd, shardEnd);
}

/**
 * Extract normalized state string ('usable', 'qualified', 'readonly', 'retired', 'rejected').
 */
export function extractLogState(stateObj) {
  if (!stateObj || typeof stateObj !== "object") return "usable";
  for (const s of ["usable", "qualified", "readonly", "retired", "rejected"]) {
    if (stateObj[s]) return s;
  }
  return "usable";
}

/**
 * Check if a log meets all criteria for active polling.
 */
export function isLogSelected(log, nowMs = Date.now()) {
  if (!log) return false;
  const state = log.state?.toLowerCase();
  if (state !== "qualified" && state !== "usable") {
    return false;
  }

  const interval = {
    start_inclusive: log.not_after_start,
    end_exclusive: log.not_after_limit
  };

  return intervalOverlapsWindow(interval, nowMs);
}

/**
 * Parse Google v3 log list format.
 */
export function parseGoogleV3LogList(v3Data) {
  const logs = [];
  for (const op of v3Data?.operators || []) {
    const operatorName = op.name || "Unknown Operator";

    // RFC6962 logs
    for (const log of op.logs || []) {
      const pubKey = log.key || "";
      const logId = log.log_id || computeLogIdFromKey(pubKey);
      const state = extractLogState(log.state);
      logs.push({
        log_id: logId,
        operator: operatorName,
        description: log.description || "",
        protocol: "rfc6962",
        submission_url: normalizeLogUrl(log.url),
        monitoring_url: normalizeLogUrl(log.url),
        public_key_der: pubKey,
        state,
        not_after_start: log.temporal_interval?.start_inclusive || null,
        not_after_limit: log.temporal_interval?.end_exclusive || null,
        refreshed_at: new Date().toISOString()
      });
    }

    // Static CT (tiled) logs
    for (const log of op.tiled_logs || []) {
      const pubKey = log.key || "";
      const logId = log.log_id || computeLogIdFromKey(pubKey);
      const state = extractLogState(log.state);
      logs.push({
        log_id: logId,
        operator: operatorName,
        description: log.description || "",
        protocol: "static-ct-api",
        submission_url: normalizeLogUrl(log.submission_url || log.url),
        monitoring_url: normalizeLogUrl(log.monitoring_url || log.url),
        public_key_der: pubKey,
        state,
        not_after_start: log.temporal_interval?.start_inclusive || null,
        not_after_limit: log.temporal_interval?.end_exclusive || null,
        refreshed_at: new Date().toISOString()
      });
    }
  }
  return logs;
}

/**
 * Parse CertSpotter monitor.json format.
 */
export function parseCertSpotterLogList(csData) {
  const logs = [];
  for (const op of csData?.operators || []) {
    const operatorName = op.name || "Multiple operators";
    for (const log of op.logs || []) {
      const pubKey = log.key || "";
      const logId = log.log_id || computeLogIdFromKey(pubKey);
      const state = extractLogState(log.state);
      const protocol = log.protocol === "static-ct-api" || log.monitoring_url ? "static-ct-api" : "rfc6962";
      logs.push({
        log_id: logId,
        operator: operatorName,
        description: log.description || "",
        protocol,
        submission_url: normalizeLogUrl(log.url || log.submission_url),
        monitoring_url: normalizeLogUrl(log.monitoring_url || log.url),
        public_key_der: pubKey,
        state,
        not_after_start: log.temporal_interval?.start_inclusive || null,
        not_after_limit: log.temporal_interval?.end_exclusive || null,
        refreshed_at: new Date().toISOString()
      });
    }
  }
  return logs;
}

/**
 * Fetch and merge dynamic log lists from CertSpotter (primary) and Google v3 (cross-check).
 */
export async function fetchDynamicLogList() {
  const errors = [];
  let certspotterLogs = [];
  let googleLogs = [];

  try {
    const csData = await fetchJson(CERTSPOTTER_LOG_LIST_URL, { timeoutMs: 10000 });
    certspotterLogs = parseCertSpotterLogList(csData);
  } catch (err) {
    errors.push({ source: "certspotter", error: err.message });
  }

  try {
    const gData = await fetchJson(GOOGLE_V3_LOG_LIST_URL, { timeoutMs: 10000 });
    googleLogs = parseGoogleV3LogList(gData);
  } catch (err) {
    errors.push({ source: "google_v3", error: err.message });
  }

  if (!certspotterLogs.length && !googleLogs.length) {
    throw new Error(`Failed to fetch CT log lists: ${JSON.stringify(errors)}`);
  }

  // Merge map by log_id (Google v3 adds static-ct tiled logs if missing in Certspotter)
  const mergedMap = new Map();

  for (const log of certspotterLogs) {
    if (log.log_id) {
      mergedMap.set(log.log_id, log);
    }
  }

  for (const log of googleLogs) {
    if (!log.log_id) continue;
    if (!mergedMap.has(log.log_id)) {
      mergedMap.set(log.log_id, log);
    } else {
      // If Google has static-ct-api and CertSpotter had rfc6962, upgrade
      const existing = mergedMap.get(log.log_id);
      if (log.protocol === "static-ct-api") {
        existing.protocol = "static-ct-api";
        existing.monitoring_url = log.monitoring_url;
      }
      if (existing.operator === "Multiple operators" && log.operator !== "Multiple operators") {
        existing.operator = log.operator;
      }
    }
  }

  const allLogs = Array.from(mergedMap.values());
  const selectedLogs = allLogs.filter((log) => isLogSelected(log));

  return {
    allLogs,
    selectedLogs,
    errors
  };
}

import { digest, findingHosts, makeEvidence, normalizeIntelHost } from "./evidence.js";

export const SOURCE_CONFIG = {
  openphish: { label: "OpenPhish", interval_hours: 12 },
  urlhaus: { label: "URLhaus", interval_hours: 6, key: "ABUSECH_AUTH_KEY" },
  threatfox: { label: "ThreatFox", interval_hours: 6, key: "ABUSECH_AUTH_KEY" },
  urlscan: { label: "urlscan", interval_hours: 6, key: "URLSCAN_API_KEY" }
};

export class IntelRequestError extends Error {
  constructor(message, status = 0, retryAt = 0) {
    super(message);
    this.status = status;
    this.retryAt = retryAt;
  }
}

export async function requestIntel(url, options = {}, { fetchImpl = fetch, now = Date.now() } = {}) {
  const response = await fetchImpl(url, {
    ...options, redirect: "error", signal: AbortSignal.timeout(20000),
    headers: { "User-Agent": "sgCertWatch/1.0", ...options.headers }
  });
  const retry = response.headers.get("retry-after");
  const retryAt = /^\d+$/.test(retry || "") ? now + Number(retry) * 1000 : Date.parse(retry || "") || 0;
  const resetAt = Date.parse(response.headers.get("x-rate-limit-reset") || "") || 0;
  if (!response.ok) throw new IntelRequestError(`Provider HTTP ${response.status}`, response.status, Math.max(retryAt, resetAt));
  const quotaExhausted = response.headers.get("x-rate-limit-remaining") === "0";
  try {
    const maxBytes = 12 * 1024 * 1024;
    if (Number(response.headers.get("content-length")) > maxBytes) {
      await response.body?.cancel();
      throw new IntelRequestError("Provider response exceeds size limit");
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.byteLength;
      if (size > maxBytes) throw new IntelRequestError("Provider response exceeds size limit");
      chunks.push(chunk);
    }
    return { text: Buffer.concat(chunks).toString("utf8"), quotaExhausted, resetAt };
  } catch (error) {
    if (quotaExhausted) error.retryAt = Math.max(Number(error.retryAt) || 0, resetAt, now + 6 * 3600000);
    throw error;
  }
}

function jsonPayload(text, field) {
  let payload;
  try { payload = JSON.parse(text); } catch { throw new IntelRequestError("Invalid provider JSON"); }
  if (payload.query_status === "no_results") return [];
  if (payload.query_status !== "ok" || !Array.isArray(payload[field])) throw new IntelRequestError("Unexpected provider response");
  return payload[field];
}

export function parseOpenPhish(text, now) {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length || lines.some((line) => !/^https?:\/\//i.test(line))) throw new IntelRequestError("Invalid OpenPhish feed");
  const feedHash = digest(text);
  return lines.map((indicator) => makeEvidence({ source: "openphish", indicator,
    source_ref: "https://openphish.com/phishing_feeds.html", verdict: "phishing",
    observed_at: new Date(now).toISOString(),
    details: { feed_sha256: feedHash }
  }, now)).filter(Boolean);
}

export function parseUrlhaus(text, now) {
  return jsonPayload(text, "urls").filter((row) => /^\d+$/.test(String(row.id)) && row.threat === "malware_download")
    .map((row) => makeEvidence({ source: "urlhaus", indicator: row.url,
      source_ref: `https://urlhaus.abuse.ch/url/${row.id}/`, verdict: "malware",
      observed_at: row.date_added, details: { url_status: row.url_status, provider_id: String(row.id) }
    }, now)).filter(Boolean);
}

export function parseThreatFox(text, now) {
  return jsonPayload(text, "data").filter((row) => ["domain", "url"].includes(row.ioc_type) && /^\d+$/.test(String(row.id)))
    .map((row) => makeEvidence({ source: "threatfox", indicator: row.ioc,
      source_ref: `https://threatfox.abuse.ch/ioc/${row.id}/`, verdict: "malware",
      observed_at: row.last_seen || row.first_seen,
      details: { confidence: Number(row.confidence_level) || 0, threat_type: String(row.threat_type || "").slice(0, 100),
        malware: String(row.malware_printable || row.malware || "").slice(0, 100), provider_id: String(row.id) }
    }, now)).filter(Boolean);
}

const SCAN_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export function parseUrlscanResult(payload, host, now) {
  const id = payload.task?.uuid || payload._id;
  if (!SCAN_ID.test(id || "") || !payload.task?.time || payload.task?.visibility !== "public"
    || normalizeIntelHost(payload.page?.url || payload.page?.domain) !== host
    || normalizeIntelHost(payload.task?.url) !== host) return null;
  const categories = payload.verdicts?.urlscan?.categories || [];
  const confirmed = payload.verdicts?.urlscan?.malicious === true;
  const verdict = confirmed && categories.includes("phishing") ? "phishing"
    : confirmed && categories.includes("malware") ? "malware" : "observed";
  return makeEvidence({ source: "urlscan", indicator: payload.page.url || host,
    source_ref: `https://urlscan.io/result/${id}/`, verdict, observed_at: payload.task?.time,
    details: { title: String(payload.page?.title || "").slice(0, 300),
      screenshot_url: `https://urlscan.io/screenshots/${id}.png`, verdict_confirmed: confirmed,
      provider_id: id }
  }, now);
}

export async function fetchSource(source, { env = process.env, candidates = [], cursor = 0, now = Date.now(), fetchImpl = fetch } = {}) {
  const request = (url, options) => requestIntel(url, options, { fetchImpl, now });
  if (source === "openphish") {
    const result = await request("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt");
    const evidence = parseOpenPhish(result.text, now);
    return { evidence, scanned_entries: result.text.trim().split(/\r?\n/).length };
  }
  const auth = { "Auth-Key": env.ABUSECH_AUTH_KEY };
  if (source === "urlhaus") {
    const result = await request("https://urlhaus-api.abuse.ch/v1/urls/recent/", { headers: auth });
    return { evidence: parseUrlhaus(result.text, now), scanned_entries: jsonPayload(result.text, "urls").length };
  }
  if (source === "threatfox") {
    const result = await request("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST", headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify({ query: "get_iocs", days: 1 })
    });
    return { evidence: parseThreatFox(result.text, now), scanned_entries: jsonPayload(result.text, "data").length };
  }
  const hosts = [...new Set(candidates.flatMap(findingHosts))];
  const evidence = [];
  let scanned = 0;
  let nextPollAt = 0;
  const count = Math.min(3, hosts.length);
  try {
    for (let i = 0; i < count; i++) {
      const host = hosts[(cursor + i) % hosts.length];
      const url = new URL("https://urlscan.io/api/v1/search/");
      url.searchParams.set("q", `page.domain.keyword:"${host}" AND date:>now-7d AND task.visibility:public`);
      url.searchParams.set("size", "1");
      const result = await request(url, { headers: { "api-key": env.URLSCAN_API_KEY } });
      if (result.quotaExhausted) nextPollAt = Math.max(nextPollAt, result.resetAt, now + 6 * 3600000);
      let payload;
      try { payload = JSON.parse(result.text); } catch { throw new IntelRequestError("Invalid urlscan JSON"); }
      if (!Array.isArray(payload.results)) throw new IntelRequestError("Unexpected urlscan search response");
      scanned++;
      const match = payload.results.find((row) => SCAN_ID.test(row._id || "") && normalizeIntelHost(row.page?.domain || row.page?.url) === host);
      if (match) {
        const detail = await request(`https://urlscan.io/api/v1/result/${match._id}/`, { headers: { "api-key": env.URLSCAN_API_KEY } });
        if (detail.quotaExhausted) nextPollAt = Math.max(nextPollAt, detail.resetAt, now + 6 * 3600000);
        let parsed;
        try { parsed = JSON.parse(detail.text); } catch { throw new IntelRequestError("Invalid urlscan result JSON"); }
        const row = parseUrlscanResult(parsed, host, now);
        if (row) evidence.push(row);
        if (detail.quotaExhausted) break;
      }
      if (result.quotaExhausted) break;
    }
  } catch (error) {
    error.retryAt = Math.max(Number(error.retryAt) || 0, nextPollAt);
    throw error;
  }
  return { evidence, scanned_entries: scanned, cursor: hosts.length ? (cursor + scanned) % hosts.length : 0, nextPollAt };
}

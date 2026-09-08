import { createHash } from "node:crypto";
import { isIP } from "node:net";

export const INTEL_SOURCES = ["openphish", "urlscan", "urlhaus", "threatfox"];

export function normalizeIntelHost(value) {
  try {
    const input = String(value || "").trim();
    if (input.includes("*")) return null;
    const url = new URL(input.includes("://") ? input : `https://${input}`);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (isIP(host) || !host.includes(".") || host.length > 253) return null;
    if (!host.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))) return null;
    return host;
  } catch { return null; }
}

export function findingHosts(finding) {
  const domains = finding.domains?.length ? finding.domains : [finding.registrable];
  return [...new Set(domains.map(normalizeIntelHost).filter(Boolean))];
}

export function digest(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function makeEvidence({ source, indicator, source_ref, verdict = "observed", observed_at, details = {} }, now = Date.now()) {
  const domain = normalizeIntelHost(indicator);
  if (!domain || !INTEL_SOURCES.includes(source)) return null;
  const observed = Date.parse(observed_at || "");
  if (!Number.isFinite(observed) || observed > now + 300000) return null;
  const lifetime = source === "openphish" ? 24 * 3600000 : 7 * 86400000;
  const expires = Math.min(observed + lifetime, now + lifetime);
  if (expires <= now) return null;
  return {
    id: digest(`${source}|${domain}|${source_ref}`), domain, source, source_ref, verdict,
    observed_at: new Date(observed).toISOString(), expires_at: new Date(expires).toISOString(),
    details: { ...details, indicator_sha256: digest(indicator) }
  };
}

export function attachIntelEvidence(finding, evidence, now = Date.now()) {
  const hosts = new Set(findingHosts(finding));
  const rows = finding.suppressed ? [] : (evidence || []).filter((row) =>
    INTEL_SOURCES.includes(row.source) && hosts.has(row.domain)
    && Date.parse(row.expires_at) > now && Date.parse(row.observed_at) <= now + 300000
  );
  const freshStrong = rows.some((row) => {
    if (row.source === "openphish") return row.verdict === "phishing";
    if (row.source === "urlhaus") return row.verdict === "malware" && row.details?.url_status === "online";
    if (row.source === "threatfox") return row.verdict === "malware" && Number(row.details?.confidence) >= 75;
    return ["phishing", "malware"].includes(row.verdict) && row.details?.verdict_confirmed === true;
  });
  const boost = Number(finding.score) >= 60 && freshStrong ? 10 : 0;
  return { ...finding, intel_evidence: rows, intel_hit_count: new Set(rows.map((row) => row.source)).size,
    intel_priority_boost: boost, priority_score: Number(finding.score || 0) + boost };
}

/**
 * Pure serialization helpers for finding exports.
 * No DOM, no fetch, no side effects — works in both Node.js and the browser.
 */

const FORMULA_CHARS = new Set(["=", "+", "-", "@"]);

/** Neutralize spreadsheet formula injection by prefixing with tab. */
function neutralize(value) {
  const s = String(value ?? "");
  return FORMULA_CHARS.has(s[0]) ? "\t" + s : s;
}

/** Wrap a value in RFC 4180 CSV quotes, escaping internal double-quotes. */
function csvCell(value) {
  const s = neutralize(value);
  return '"' + s.replaceAll('"', '""') + '"';
}

const CSV_HEADERS = [
  "registrable", "score", "severity", "issuer", "observed_at",
  "matched_brands", "domains",
  "id", "priority_score", "intel_priority_boost", "intel_hit_count",
  "sources", "cert_serial", "cert_issuer_dn_sha256",
  "intel_evidence_summary", "export_scope", "export_time",
];

/**
 * Convert a finding to a flat export object.
 * @param {object} finding
 * @param {string} scope
 * @param {string} exportedAt  ISO string
 * @returns {Record<string, string|number>}
 */
export function exportedFinding(finding, scope = "", exportedAt = new Date().toISOString()) {
  const evidence = Array.isArray(finding.intel_evidence) ? finding.intel_evidence : [];
  return {
    id:                    finding.id ?? "",
    registrable:           finding.registrable ?? "",
    score:                 finding.score ?? 0,
    severity:              finding.severity ?? "",
    priority_score:        finding.priority_score ?? finding.score ?? 0,
    intel_priority_boost:  finding.intel_priority_boost ?? 0,
    issuer:                finding.issuer ?? "",
    observed_at:           finding.observed_at ?? "",
    sources:               Array.isArray(finding.sources) ? finding.sources : [],
    matched_brands:        Array.isArray(finding.matched_brands) ? finding.matched_brands : [],
    domains:               Array.isArray(finding.domains) ? finding.domains : [],
    cert_serial:           finding.cert_serial ?? "",
    cert_issuer_dn_sha256: finding.cert_issuer_dn_sha256 ?? "",
    intel_hit_count:       finding.intel_hit_count ?? 0,
    intel_evidence_summary: evidence.map((e) => ({
      source:      e.source ?? "",
      verdict:     e.verdict ?? "",
      domain:      e.domain ?? "",
      observed_at: e.observed_at ?? "",
      expires_at:  e.expires_at ?? "",
      source_ref:  e.source_ref ?? "",
    })),
    export_scope: scope,
    export_time:  exportedAt,
  };
}

/**
 * Serialize one plain object to a CSV row using the given header order.
 * @param {Record<string, unknown>} obj
 * @param {string[]} headers
 * @returns {string}
 */
export function toCsvRow(obj, headers) {
  return headers.map((h) => {
    const value = obj[h];
    const flat = Array.isArray(value)
      ? (value.length && typeof value[0] === "object" ? JSON.stringify(value) : value.join("; "))
      : value ?? "";
    return csvCell(flat);
  }).join(",");
}

/**
 * Serialize findings to a CSV string (header row + data rows).
 * @param {object[]} findings
 * @param {string} scope
 * @returns {string}
 */
export function toCsv(findings, scope = "") {
  const now = new Date().toISOString();
  const rows = findings.map((f) => toCsvRow(exportedFinding(f, scope, now), CSV_HEADERS));
  return [CSV_HEADERS.join(","), ...rows].join("\n");
}

/**
 * Serialize findings to a JSON array string.
 * Each element is the exported finding with a _export metadata field.
 * Preserves the array shape — no wrapper object.
 * @param {object[]} findings
 * @param {string} scope
 * @returns {string}
 */
export function toJson(findings, scope = "") {
  const now = new Date().toISOString();
  return JSON.stringify(
    findings.map((f) => ({ ...exportedFinding(f, scope, now), _export: { scope, exported_at: now } })),
    null, 2
  );
}

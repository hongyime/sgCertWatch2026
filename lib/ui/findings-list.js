/**
 * lib/ui/findings-list.js
 *
 * Pure ES module — no DOM access, no fetch.
 * Exports rendered HTML for finding cards and the parameterised filter.
 *
 * Helpers are copied verbatim from app.js so that HTML output is identical.
 */

// ---------------------------------------------------------------------------
// Constants (mirrors app.js)
// ---------------------------------------------------------------------------

const INTEL_SOURCES = {
  openphish: "OpenPhish",
  urlscan: "urlscan.io",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox"
};

// ---------------------------------------------------------------------------
// Utilities (copied verbatim from app.js)
// ---------------------------------------------------------------------------

function unique(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function tokenList(values) {
  if (!values?.length) return "";
  return `<div class="token-list">${values.map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function sourceLabel(source) {
  const labels = {
    certstream: "Live stream",
    direct_ct: "Direct CT logs",
    static_ct: "Static CT logs",
    crtsh: "crt.sh backup",
    ...INTEL_SOURCES
  };
  return labels[source] || source;
}

function intelEvidence(finding) {
  return Array.isArray(finding.intel_evidence)
    ? finding.intel_evidence.filter((item) => item && Object.hasOwn(INTEL_SOURCES, item.source))
    : [];
}

function intelHitCount(finding) {
  return Number.isInteger(finding.intel_hit_count) && finding.intel_hit_count >= 0
    ? finding.intel_hit_count : new Set(intelEvidence(finding).map((item) => item.source)).size;
}

function intelVerdict(item) {
  if (item.verdict === "phishing" || item.verdict === "malware" || item.verdict === "observed") return item.verdict;
  return "unknown";
}

function priorityScore(finding) {
  const score = Number(finding.priority_score ?? finding.score ?? 0);
  return Number.isFinite(score) ? score : 0;
}

function renderPriority(finding) {
  const boost = finding.intel_priority_boost === 10 ? 10 : 0;
  const promoted = boost > 0 && Number(finding.score) < 70 && priorityScore(finding) >= 70;
  return `<div class="finding-priority${promoted ? " promoted" : ""}">
    <span>CT score ${escapeHtml(finding.score ?? 0)} + intel ${boost} = priority <b>${priorityScore(finding)}</b></span>
    ${promoted ? '<span class="promotion-label">Promoted to Watch</span>' : ""}
  </div>`;
}

function renderIntelBadges(finding) {
  const badges = unique(intelEvidence(finding).map((item) => `${sourceLabel(item.source)}: ${intelVerdict(item)}`));
  return `<div class="intel-badges"><span class="intel-count">Intel hits: ${intelHitCount(finding)}</span>
    ${badges.map((label) => `<span class="intel-source-badge">${escapeHtml(label)}</span>`).join("")}
  </div>`;
}

function signalText(signal) {
  if (signal.type?.startsWith("brand")) return `${signal.display || signal.brand} name (+${signal.points})`;
  if (signal.type === "tld:mismatch") return `unusual .${signal.actual} (+${signal.points})`;
  if (signal.type === "tld_high_risk") return `high-risk .${signal.tld} (+${signal.points})`;
  if (signal.type === "tld_medium_risk") return `medium-risk .${signal.tld} (+${signal.points})`;
  if (signal.type === "kw") return `${signal.token} keyword (+${signal.points})`;
  if (signal.type === "scheme") return `${signal.display || signal.scheme} scheme (+${signal.points})`;
  if (signal.type === "combo_brand_keyword") return `brand + keyword combo (+${signal.points})`;
  if (signal.type === "combo_scheme_keyword") return `scheme + keyword combo (+${signal.points})`;
  if (signal.type === "issuer_free_dv") return `free DV issuer (+${signal.points})`;
  if (signal.type === "cert_age_under_1h") return `issued < 1 hr ago (+${signal.points})`;
  if (signal.type === "cert_age_under_24h") return `issued < 24 hrs ago (+${signal.points})`;
  if (signal.type === "san_count_over_20") return `SAN count > 20 (+${signal.points})`;
  return `${signal.type || "signal"} (+${signal.points || 0})`;
}

function renderReasons(signals = []) {
  const reasons = unique(signals.map(signalText)).slice(0, 4);
  return reasons.length ? tokenList(reasons) : "";
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString("en-SG", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit"
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/**
 * Render a single finding card `<li>`.
 * Output is identical to the renderFindingCard function in app.js.
 *
 * @param {object} finding
 * @param {number} index  — 0-based position in the filtered findings array
 * @returns {string} HTML string
 */
export function renderFindingCard(finding, index) {
  const domains = (finding.domains || []).slice(0, 3).join(", ");
  const sources = (finding.sources || []).map(sourceLabel).join(", ") || "unknown";
  return `
    <li class="watch-card finding-card interactive-card" data-finding-index="${index}" tabindex="0" role="button" aria-label="Review ${escapeHtml(finding.registrable)}">
      <div class="watch-card-head">
        <strong>${escapeHtml(finding.registrable)}</strong>
        <span class="severity ${escapeHtml(finding.severity)}">CT ${escapeHtml(finding.severity)} ${escapeHtml(finding.score)}</span>
      </div>
      <p>${escapeHtml(domains || "No domain names stored")}</p>
      ${renderPriority(finding)}
      ${renderIntelBadges(finding)}
      ${renderReasons(finding.signals)}
      <div class="watch-meta">
        <span>${escapeHtml(finding.source_count || 0)} CT source${finding.source_count === 1 ? "" : "s"}: ${escapeHtml(sources)}</span>
        <span>Cert seen ${escapeHtml(formatTime(finding.observed_at))}</span>
      </div>
    </li>
  `;
}

/**
 * Render a single manual-review card `<li>`.
 * Output is identical to the renderReviewCard function in app.js.
 *
 * @param {object} entry
 * @returns {string} HTML string
 */
export function renderReviewCard(entry) {
  return `
    <li class="watch-card review-card">
      <div class="watch-card-head">
        <strong>${escapeHtml(entry.registrable)}</strong>
        <span class="review-badge">review</span>
      </div>
      <p>${escapeHtml(entry.brand)} is parked for human checking before it can suppress alerts.</p>
      <div class="watch-meta">
        <span>Not treated as official yet</span>
        <span>Manual source proof needed</span>
      </div>
    </li>
  `;
}

/**
 * Filter and sort findings.
 * Same logic as filteredFindings() in app.js but takes state as a parameter
 * so this module stays pure (no module-level state).
 *
 * @param {{ findings: Array, findingSeverity: string, findingQuery: string }} state
 * @returns {Array}
 */
export function filteredFindings(state) {
  return (state.findings || []).filter((f) => {
    const sevMatch = state.findingSeverity === "watch"
      ? priorityScore(f) >= 70
      : (!state.findingSeverity || f.severity === state.findingSeverity);
    const searchTarget = `${f.registrable} ${(f.domains || []).join(" ")} ${(f.matched_brands || []).join(" ")} ${(f.matched_schemes || []).join(" ")}`.toLowerCase();
    const queryMatch = !state.findingQuery || searchTarget.includes(state.findingQuery);
    return sevMatch && queryMatch;
  }).sort((a, b) => priorityScore(b) - priorityScore(a));
}

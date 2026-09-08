const files = {
  watchlist: "/watchlist.json",
  keywords: "/keywords.json",
  allowlist: "/allowlist.json",
  schemes: "/schemes.json"
};

const CT_SOURCE_STATUS_URL = "/api/source-status";
const INTEL_SOURCES = {
  openphish: "OpenPhish",
  urlscan: "urlscan.io",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox"
};
const SCAN_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

const state = {
  data: null,
  view: "alerts",
  dataset: "brands",
  query: "",
  category: "",
  findings: [],
  findingQuery: "",
  findingSeverity: "watch",
  findingsRequest: 0,
  feedConfigured: false,
  feedLoading: false,
  feedError: false
};

const $ = (id) => document.getElementById(id);

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

// Only http(s) URLs become links; anything else (javascript:, data:, garbage) renders as inert text.
function safeLink(url, className) {
  const raw = String(url || "").trim();
  if (!/^https:\/\/[^\s"'<>]+$/i.test(raw)) return escapeHtml(raw);
  return `<a href="${escapeHtml(raw)}" target="_blank" rel="noopener noreferrer"${className ? ` class="${escapeHtml(className)}"` : ""}>${escapeHtml(raw)}</a>`;
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

function intelVerdict(item) {
  if (item.verdict === "phishing" || item.verdict === "malware" || item.verdict === "observed") return item.verdict;
  return "unknown";
}

function renderIntelBadges(finding) {
  const badges = unique(intelEvidence(finding).map((item) => `${sourceLabel(item.source)}: ${intelVerdict(item)}`));
  return `<div class="intel-badges"><span class="intel-count">Intel hits: ${intelHitCount(finding)}</span>
    ${badges.map((label) => `<span class="intel-source-badge">${escapeHtml(label)}</span>`).join("")}
  </div>`;
}

// Provider report paths only. Never turn an IOC or an arbitrary provider redirect into a link.
function intelProviderUrl(value, source, screenshot = false) {
  if (typeof value !== "string" || !/^https:\/\//i.test(value) || /[\s\\\u0000-\u001f\u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash) return null;
    let allowed = false;
    if (source === "urlscan" && url.hostname === "urlscan.io") {
      const path = screenshot ? `^/screenshots/${SCAN_ID}\\.png$` : `^/result/${SCAN_ID}/?$`;
      allowed = new RegExp(path, "i").test(url.pathname);
    } else if (!screenshot && source === "openphish" && url.hostname === "openphish.com") {
      allowed = /^\/(?:feed\.txt|phishing_feeds\.html)?$/.test(url.pathname);
    } else if (!screenshot && source === "openphish" && url.hostname === "raw.githubusercontent.com") {
      allowed = url.pathname === "/openphish/public_feed/refs/heads/main/feed.txt";
    } else if (!screenshot && source === "urlhaus" && url.hostname === "urlhaus.abuse.ch") {
      allowed = /^\/url\/\d+\/?$/.test(url.pathname);
    } else if (!screenshot && source === "threatfox" && url.hostname === "threatfox.abuse.ch") {
      allowed = /^\/ioc\/\d+\/?$/.test(url.pathname);
    }
    return allowed ? url.href : null;
  } catch {
    return null;
  }
}

function intelProviderLink(value, source, screenshot = false) {
  const url = intelProviderUrl(value, source, screenshot);
  const label = screenshot ? "Provider screenshot" : source === "openphish" ? "Provider feed" : "Provider report";
  return url
    ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">${label}</a>`
    : `<span class="muted-text">${label} unavailable</span>`;
}

function renderIntelEvidence(finding) {
  const evidence = intelEvidence(finding);
  return `<section class="dialog-section intel-evidence" aria-labelledby="intel-evidence-heading">
    <h3 id="intel-evidence-heading">Intel evidence (${intelHitCount(finding)} sources)</h3>
    ${evidence.length ? `<ul class="evidence-list">${evidence.map((item) => {
      const verdict = intelVerdict(item);
      const expired = Date.parse(item.expires_at) <= Date.now();
      const details = item.details || {};
      return `<li class="evidence-row">
        <div class="evidence-heading"><strong>${escapeHtml(sourceLabel(item.source))}</strong>
          <span class="intel-verdict ${verdict}">${verdict}</span>${expired ? '<span class="muted-text">Expired</span>' : ""}</div>
        <dl class="evidence-facts">
          <div><dt>Matched host</dt><dd><code>${escapeHtml(item.domain || "Unknown")}</code></dd></div>
          <div><dt>Observed</dt><dd>${escapeHtml(formatTime(item.observed_at))}</dd></div>
          <div><dt>Expires</dt><dd>${escapeHtml(formatTime(item.expires_at))}</dd></div>
          ${details.title != null ? `<div><dt>Page title</dt><dd>${escapeHtml(details.title)}</dd></div>` : ""}
          ${details.confidence != null ? `<div><dt>Provider confidence</dt><dd>${escapeHtml(details.confidence)}</dd></div>` : ""}
        </dl>
        ${verdict === "observed" ? '<p class="muted-text">Observed only; no phishing or malware verdict.</p>' : ""}
        <div class="evidence-links">${intelProviderLink(item.source_ref, item.source)}
          ${details.screenshot_url ? intelProviderLink(details.screenshot_url, item.source, true) : ""}</div>
      </li>`;
    }).join("")}</ul>` : '<p class="muted-text">No current intel evidence recorded.</p>'}
  </section>`;
}

function sourceState(item) {
  if (item.ok && (item.details?.state === "standby" || item.status === "standby")) {
    return { label: "standby", className: "standby" };
  }
  if (item.ok && item.details?.budget_exhausted) return { label: "budget limited", className: "standby" };
  if (item.ok || item.status === "ok") {
    return { label: "ok", className: "ok" };
  }
  if (item.status === "stale") return { label: "stale", className: "warn" };
  if (item.status === "failed") return { label: "failed", className: "bad" };
  return { label: item.status || "degraded", className: "warn" };
}

function sourceDetail(item) {
  const checked = `${item.scanned_entries || 0} checked`;
  const matched = `${item.matched || 0} matches`;
  const persisted = Number.isFinite(item.persisted) ? ` - ${item.persisted} stored` : "";
  const error = item.errors?.[0];
  const note = [typeof error === "string" ? error : error?.message, item.details?.note,
    item.details?.budget_exhausted ? "Time budget reached; remaining logs resume next run." : ""].filter(Boolean).join(" - ");
  return note ? `${checked} - ${matched}${persisted} - ${note}` : `${checked} - ${matched}${persisted}`;
}

function searchable(row) {
  return JSON.stringify(row).toLowerCase();
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

function renderFindingCard(finding, index) {
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

function renderReviewCard(entry) {
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

function currentRows() {
  const { data } = state;
  if (!data) return [];

  if (state.dataset === "keywords") {
    return data.keywords.keywords.map((keyword) => ({
      name: keyword.token,
      category: keyword.category,
      affix: keyword.affix ? "used in joined words" : "exact/label match"
    }));
  }

  if (state.dataset === "allowlist") {
    return data.allowlist.entries.map((entry) => ({
      name: entry.registrable,
      category: entry.brand,
      verified: entry.verified ? "verified" : "unverified",
      source: entry.source || ""
    }));
  }

  if (state.dataset === "schemes") {
    return data.schemes.schemes.map((scheme) => ({
      name: scheme.display,
      category: scheme.category,
      tokens: scheme.tokens,
      source: scheme.source || ""
    }));
  }

  return data.watchlist.brands.map((brand) => ({
    name: brand.display,
    category: brand.category,
    tokens: brand.tokens,
    tlds: brand.known_tlds,
    context: brand.context_tokens
  }));
}

function filteredRows() {
  return currentRows().filter((row) => {
    const categoryMatch = !state.category || row.category === state.category;
    const queryMatch = !state.query || searchable(row).includes(state.query);
    return categoryMatch && queryMatch;
  });
}

function filteredFindings() {
  return (state.findings || []).filter((f) => {
    const sevMatch = state.findingSeverity === "watch"
      ? priorityScore(f) >= 70
      : (!state.findingSeverity || f.severity === state.findingSeverity);
    const searchTarget = `${f.registrable} ${(f.domains || []).join(" ")} ${(f.matched_brands || []).join(" ")} ${(f.matched_schemes || []).join(" ")}`.toLowerCase();
    const queryMatch = !state.findingQuery || searchTarget.includes(state.findingQuery);
    return sevMatch && queryMatch;
  }).sort((a, b) => priorityScore(b) - priorityScore(a));
}

function renderCategories() {
  const rows = currentRows();
  const categories = unique(rows.map((row) => row.category));
  $("category-filter").innerHTML = [
    '<option value="">All categories</option>',
    ...categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`)
  ].join("");
}

function renderTable() {
  const rows = filteredRows();
  const titles = {
    brands: "Watched Brands",
    keywords: "Suspicious Keywords",
    allowlist: "Allowlist",
    schemes: "Government Schemes"
  };
  $("table-title").textContent = titles[state.dataset];
  $("result-count").textContent = `${rows.length} result${rows.length === 1 ? "" : "s"}`;
  $("watch-count-summary").textContent = `${rows.length} ${titles[state.dataset].toLowerCase()}`;

  if (state.dataset === "keywords") {
    $("table-head").innerHTML = "<tr><th>Keyword</th><th>Type</th><th>How it is used</th></tr>";
    $("table-body").innerHTML = rows.map((row) => `
      <tr>
        <td><strong>${escapeHtml(row.name)}</strong></td>
        <td>${escapeHtml(row.category)}</td>
        <td>${escapeHtml(row.affix)}</td>
      </tr>
    `).join("");
    return;
  }

  if (state.dataset === "allowlist") {
    $("table-head").innerHTML = "<tr><th>Registrable</th><th>Brand</th><th>Status</th><th>Source</th></tr>";
    $("table-body").innerHTML = rows.map((row) => `
      <tr>
        <td>${escapeHtml(row.name)}</td>
        <td>${escapeHtml(row.category)}</td>
        <td>${escapeHtml(row.verified)}</td>
        <td>${row.source ? safeLink(row.source) : ""}</td>
      </tr>
    `).join("");
    return;
  }

  if (state.dataset === "schemes") {
    $("table-head").innerHTML = "<tr><th>Scheme</th><th>Category</th><th>Tokens</th><th>Source</th></tr>";
    $("table-body").innerHTML = rows.map((row) => `
      <tr>
        <td>${escapeHtml(row.name)}</td>
        <td>${escapeHtml(row.category)}</td>
        <td>${tokenList(row.tokens)}</td>
        <td>${row.source ? safeLink(row.source) : ""}</td>
      </tr>
    `).join("");
    return;
  }

  $("table-head").innerHTML = "<tr><th>Brand</th><th>Category</th><th>Tokens</th><th>Known TLDs</th><th>Context</th></tr>";
  $("table-body").innerHTML = rows.map((row) => `
    <tr>
      <td>${escapeHtml(row.name)}</td>
      <td>${escapeHtml(row.category)}</td>
      <td>${tokenList(row.tokens)}</td>
      <td>${tokenList(row.tlds)}</td>
      <td>${tokenList(row.context)}</td>
    </tr>
  `).join("");
}

function setDataset(dataset) {
  state.dataset = dataset;
  state.category = "";
  setView("watch");
  render();

  document.querySelectorAll("[data-dataset]").forEach((element) => {
    const active = element.dataset.dataset === dataset;
    element.classList.toggle("active", active);
    if (element.hasAttribute("aria-pressed")) {
      element.setAttribute("aria-pressed", active ? "true" : "false");
    }
  });
}

function setView(view) {
  state.view = view;
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === view);
  });
}

function renderSummary() {
  const { watchlist, keywords, allowlist, schemes } = state.data;
  const pending = allowlist.pending_verification?.entries || [];
  const unverifiedAllowlist = allowlist.entries.filter((entry) => !entry.verified).length;
  const unverifiedSchemes = schemes.schemes.filter((scheme) => !scheme.verified).length;

  $("brand-count").textContent = watchlist.brands.length;
  $("keyword-count").textContent = keywords.keywords.length;
  $("allowlist-count").textContent = allowlist.entries.length;
  $("scheme-count").textContent = schemes.schemes.length;
  $("allowlist-status").textContent = unverifiedAllowlist === 0 ? "Ready" : `${unverifiedAllowlist} unverified`;
  $("scheme-status").textContent = unverifiedSchemes === 0 ? "Ready" : `${unverifiedSchemes} unverified`;
  $("pending-status").textContent = pending.length === 0 ? "None" : `${pending.length} parked`;
  $("pending-list").innerHTML = pending.length
    ? pending.map(renderReviewCard).join("")
    : '<li class="watch-card review-card"><div class="watch-card-head"><strong>No parked domains</strong><span class="review-badge ok">clear</span></div><p>Nothing is waiting for manual ownership review.</p></li>';
  $("data-status").textContent = `Live at ${new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" })}`;
}

function renderFindingList() {
  if (state.feedError || (state.feedLoading && !state.findings.length)) return;
  const findings = filteredFindings();
  $("feed-status").textContent = !state.feedConfigured ? "Database not connected"
    : findings.length ? `${findings.length} domains need review`
      : state.findingSeverity === "watch" ? "No domains at priority 70 or above" : "No matching stored findings";
  $("finding-list").innerHTML = findings.length
    ? findings.map((f, idx) => renderFindingCard(f, idx)).join("")
    : '<li class="watch-card finding-card"><div class="watch-card-head"><strong>No matching findings</strong><span class="review-badge ok">clear</span></div><p>No alerts match current search/filter criteria.</p></li>';
}

async function renderFindings() {
  const request = ++state.findingsRequest;
  const view = state.findingSeverity === "watch" ? "&view=watch" : "";
  state.feedLoading = true;
  state.feedError = false;
  $("finding-list").setAttribute("aria-busy", "true");
  $("export-json-btn").disabled = true;
  $("export-csv-btn").disabled = true;
  try {
    const response = await fetch(`/api/findings?limit=50${view}`);
    if (!response.ok) throw new Error("Feed unavailable");
    const payload = await response.json();
    // A slow response from an earlier filter must not replace the current view.
    if (request !== state.findingsRequest) return;
    const findings = Array.isArray(payload.findings) ? payload.findings : [];
    state.findings = findings;
    state.feedConfigured = Boolean(payload.storage_configured);
    state.feedLoading = false;
    $("feed-health").textContent = payload.storage_configured ? "Live database connected" : "Database not connected";
    $("feed-count").textContent = findings.length;
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });

    renderFindingList();
  } catch (error) {
    if (request !== state.findingsRequest) return;
    state.findings = [];
    state.feedLoading = false;
    state.feedError = true;
    $("feed-status").textContent = error.message;
    $("feed-health").textContent = "Feed check failed";
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });
    $("finding-list").innerHTML = '<li class="watch-card finding-card"><div class="watch-card-head"><strong>Could not load alerts</strong><span class="review-badge">unavailable</span></div><p>The findings API did not respond on this page load. The next automatic refresh will check again.</p></li>';
  } finally {
    if (request === state.findingsRequest) {
      $("finding-list").setAttribute("aria-busy", "false");
      $("export-json-btn").disabled = state.feedError;
      $("export-csv-btn").disabled = state.feedError;
    }
  }
}

function intelSourceState(item) {
  const status = item.status || item.details?.state;
  if (item.configured === false || status === "not_configured" || status === "unconfigured") return { label: "unconfigured", className: "standby" };
  if (status === "pending") return { label: "pending", className: "standby" };
  if (status === "cooldown" || status === "rate_limited") return { label: "cooldown", className: "warn" };
  if (status === "stale") return { label: "stale", className: "warn" };
  if (status === "failed" || status === "error") return { label: "failed", className: "bad" };
  if (status === "auth_error") return { label: "auth error", className: "bad" };
  if (status === "ok" || (!status && item.ok)) return { label: "ok", className: "ok" };
  return { label: status || "pending", className: "warn" };
}

function formatPeriod(milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) return "";
  if (milliseconds >= 3600000) return `${Number((milliseconds / 3600000).toFixed(1))} hr`;
  return `${Number((milliseconds / 60000).toFixed(1))} min`;
}

function renderIntelSourceStatus(source) {
  const sources = Array.isArray(source.intel_sources) ? source.intel_sources : [];
  const schedule = source.intel_schedule;
  const hourly = String(schedule?.cron || "").match(/^([0-5]?\d) \* \* \* \*$/);
  $("intel-schedule").textContent = schedule
    ? `${hourly ? `Hourly at :${hourly[1].padStart(2, "0")} UTC` : schedule.cron ? `Cron ${schedule.cron} (UTC)` : "Scheduled"} via ${schedule.runner === "github-actions" ? "GitHub Actions" : schedule.runner || "reported scheduler"}${schedule.workflow ? ` (${schedule.workflow})` : ""}`
    : "Intel schedule not reported";
  $("intel-source-list").innerHTML = Object.keys(INTEL_SOURCES).map((key) => {
    const item = sources.find((entry) => entry?.source === key) || { source: key, status: "pending" };
    const health = intelSourceState(item);
    const details = item.details || {};
    const checked = item.last_checked_at || item.checked_at || details.last_checked_at;
    const next = item.next_poll_at || details.next_poll_at;
    const cooldown = item.cooldown_until || details.cooldown_until;
    const period = formatPeriod(details.interval_hours != null ? Number(details.interval_hours) * 3600000
      : Number(details.period_ms ?? details.poll_interval_ms ?? details.interval_ms));
    const error = item.errors?.[0];
    const note = details.note || (typeof error === "string" ? error : error?.message) || "";
    return `<div class="source-row ${health.className}" data-intel-source="${key}">
      <span>${escapeHtml(sourceLabel(key))}</span><strong>${escapeHtml(health.label)}</strong>
      <small>Last check: ${checked ? escapeHtml(formatTime(checked)) : "Not reported"}</small>
      <small>Next poll: ${next ? escapeHtml(formatTime(next)) : health.label === "unconfigured" ? "Not scheduled" : "Not reported"}</small>
      ${cooldown ? `<small>Cooldown until: ${escapeHtml(formatTime(cooldown))}</small>` : ""}
      ${period ? `<small>Provider interval: ${escapeHtml(period)}</small>` : ""}
      ${note ? `<small>${escapeHtml(note)}</small>` : ""}
    </div>`;
  }).join("");
}

async function renderSourceStatus() {
  try {
    const response = await fetch(CT_SOURCE_STATUS_URL);
    if (!response.ok) throw new Error("source check failed");
    const status = await response.json();

    const source = status.status && typeof status.status === "object" ? status.status : status;
    const sources = (source.display_sources || source.sources || []).filter((item) => !Object.hasOwn(INTEL_SOURCES, item.source));
    renderIntelSourceStatus(source);
    const okCount = sources.filter((item) => item.ok || item.status === "ok").length;
    const health = source.health || source.overall;
    const primaryActive = sources.some((item) => item.source === "direct_ct" && item.ok)
      || sources.some((item) => item.source === "static_ct" && item.ok);

    if (health === "healthy") {
      $("source-status").textContent = "Monitoring active";
    } else if (health === "stale") {
      $("source-status").textContent = "Scan overdue";
    } else if (health === "down") {
      $("source-status").textContent = "Scan failed";
    } else if (primaryActive) {
      $("source-status").textContent = "Primary sources active";
    } else if (health === "partial" || okCount > 0) {
      $("source-status").textContent = "Partial coverage";
    } else if (source.errors?.length) {
      $("source-status").textContent = "Source degraded";
    } else {
      $("source-status").textContent = "waiting for scan";
    }

    $("source-list").innerHTML = sources.length
      ? sources.map((item) => {
        const state = sourceState(item);
        const label = item.label || item.description || sourceLabel(item.source);
        return `
        <div class="source-row ${state.className}">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(state.label)}</strong>
          <small>${escapeHtml(sourceDetail(item))}</small>
          <small>Last check: ${escapeHtml(formatTime(item.last_checked_at || item.checked_at))}</small>
          ${item.next_poll_at ? `<small>Next attempt: ${escapeHtml(formatTime(item.next_poll_at))}</small>` : ""}
          ${item.details?.next_retry_at ? `<small>Paused logs retry after: ${escapeHtml(formatTime(item.details.next_retry_at))}</small>` : ""}
        </div>
      `;
      }).join("")
      : '<div class="source-row"><span>Waiting for first scan</span><strong>pending</strong><small>No CT scan details reported</small></div>';
  } catch (_error) {
    $("source-status").textContent = "scan status unknown";
    $("source-list").innerHTML = '<div class="source-row bad"><span>Status API</span><strong>unavailable</strong><small>Could not load source health</small></div>';
    $("intel-schedule").textContent = "Intel schedule unavailable";
    $("intel-source-list").innerHTML = '<div class="source-row bad"><span>Intel status API</span><strong>unavailable</strong><small>Could not load intel source health</small></div>';
  }
}

function openFindingDetails(finding) {
  const dialog = $("finding-dialog");
  const body = $("dialog-body");
  if (!dialog || !body) return;

  const signalsRows = (finding.signals || []).map((s) => `
    <tr>
      <td><code>${escapeHtml(s.type)}</code></td>
      <td><strong>+${escapeHtml(s.points || 0)}</strong></td>
      <td>${escapeHtml(signalText(s))}</td>
    </tr>
  `).join("");

  body.innerHTML = `
    <div class="dialog-header">
      <div>
        <p class="eyebrow dark">Triage Investigation</p>
        <h2 id="finding-dialog-title">${escapeHtml(finding.registrable)}</h2>
      </div>
      <button type="button" class="btn-close" id="close-dialog-btn" aria-label="Close finding details">&times;</button>
    </div>

    <div class="dialog-summary">
      <div class="summary-badge severity ${escapeHtml(finding.severity)}">
        CT ${escapeHtml(finding.severity).toUpperCase()} (${escapeHtml(finding.score)} pts)
      </div>
      <div class="summary-info">
        <span>Observed: ${escapeHtml(formatTime(finding.observed_at))}</span>
        <span>Issuer: ${escapeHtml(finding.issuer || "Unknown CA")}</span>
        <span>SANs: ${escapeHtml((finding.domains || []).length)}</span>
      </div>
    </div>

    ${renderPriority(finding)}
    ${renderIntelEvidence(finding)}

    <section class="dialog-section">
      <h3>Analyst Actions</h3>
      <div class="dialog-actions">
        <button type="button" id="copy-triage-btn" class="btn-secondary">Copy Triage Report</button>
      </div>
      <p class="muted-text">Live probing is performed by analysts off-platform; this dashboard never fetches a suspected hostile host from production.</p>
    </section>

    <section class="dialog-section">
      <h3>Triggered Scoring Signals</h3>
      <table class="signals-table">
        <thead>
          <tr><th>Signal</th><th>Points</th><th>Detail</th></tr>
        </thead>
        <tbody>
          ${signalsRows || "<tr><td colspan='3'>No signals recorded</td></tr>"}
        </tbody>
      </table>
    </section>

    <section class="dialog-section">
      <h3>Certificate Identity & SANs</h3>
      <p><strong>Domains:</strong> <code>${escapeHtml((finding.domains || []).join(", "))}</code></p>
      <p><strong>Serial:</strong> <code>${escapeHtml(finding.cert_serial || "N/A")}</code></p>
      <p><strong>Issuer DN SHA256:</strong> <code>${escapeHtml(finding.cert_issuer_dn_sha256 || "N/A")}</code></p>
    </section>
  `;

  dialog.showModal();

  $("close-dialog-btn").onclick = () => dialog.close();


  $("copy-triage-btn").onclick = () => {
    const evidence = intelEvidence(finding).map((item) =>
      `  * ${sourceLabel(item.source)}: ${intelVerdict(item)}; host ${item.domain}; observed ${item.observed_at}; expires ${item.expires_at}; ${intelProviderUrl(item.source_ref, item.source) || "Provider reference unavailable"}`
    ).join("\n");
    const report = `# Triage Report: ${finding.registrable}\n- CT score: ${finding.score} (${finding.severity})\n- Priority: ${priorityScore(finding)} (intel +${finding.intel_priority_boost === 10 ? 10 : 0})\n- Intel hits: ${intelHitCount(finding)}\n${evidence}\n- Issuer: ${finding.issuer}\n- Observed: ${finding.observed_at}\n- Signals:\n${(finding.signals || []).map((s) => `  * ${s.type} (+${s.points})`).join("\n")}`;
    navigator.clipboard.writeText(report);
    $("copy-triage-btn").textContent = "Copied!";
    setTimeout(() => { $("copy-triage-btn").textContent = "Copy Triage Report"; }, 2000);
  };
}

function exportFindingsJson() {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredFindings(), null, 2));
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `sgcertwatch_findings_${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

function exportFindingsCsv() {
  const findings = filteredFindings();
  const headers = ["registrable", "score", "severity", "issuer", "observed_at", "matched_brands", "domains"];
  const rows = findings.map((f) => [
    `"${f.registrable}"`,
    f.score,
    `"${f.severity}"`,
    `"${(f.issuer || "").replaceAll('"', '""')}"`,
    `"${f.observed_at}"`,
    `"${(f.matched_brands || []).join(";")}"`,
    `"${(f.domains || []).join(";")}"`
  ]);
  const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", encodeURI(csvContent));
  downloadAnchor.setAttribute("download", `sgcertwatch_findings_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

function render() {
  renderCategories();
  $("category-filter").value = state.category;
  renderTable();
}

async function loadData() {
  try {
    const entries = await Promise.all(Object.entries(files).map(async ([key, path]) => {
      const response = await fetch(path);
      if (!response.ok) throw new Error(`Failed to load ${path}`);
      return [key, await response.json()];
    }));

    state.data = Object.fromEntries(entries);
    renderSummary();
    render();
    renderFindings();
    renderSourceStatus();
  } catch (error) {
    $("data-status").textContent = error.message;
    $("data-status").classList.add("error");
  }
}

$("search").addEventListener("input", (event) => {
  state.query = event.target.value.trim().toLowerCase();
  renderTable();
});

$("category-filter").addEventListener("change", (event) => {
  state.category = event.target.value;
  renderTable();
});

$("finding-search").addEventListener("input", (event) => {
  state.findingQuery = event.target.value.trim().toLowerCase();
  renderFindingList();
});

$("severity-filter").addEventListener("change", (event) => {
  state.findingSeverity = event.target.value;
  state.findings = [];
  $("feed-status").textContent = "Loading feed";
  $("finding-list").innerHTML = '<li class="watch-card finding-card">Loading findings</li>';
  renderFindings();
});

$("export-json-btn").addEventListener("click", exportFindingsJson);
$("export-csv-btn").addEventListener("click", exportFindingsCsv);

$("finding-list").addEventListener("click", (event) => {
  const card = event.target.closest("[data-finding-index]");
  if (!card) return;
  const idx = parseInt(card.dataset.findingIndex, 10);
  const findings = filteredFindings();
  if (findings[idx]) {
    openFindingDetails(findings[idx]);
  }
});

$("finding-list").addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-finding-index]")) {
    event.preventDefault();
    event.target.click();
  }
});

document.querySelectorAll("[data-dataset]").forEach((element) => {
  element.addEventListener("click", () => setDataset(element.dataset.dataset));
  element.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      setDataset(element.dataset.dataset);
    }
  });
});

loadData();
setInterval(renderFindings, 60000);
setInterval(renderSourceStatus, 60000);

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

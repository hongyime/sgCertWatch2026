import { visiblePoller } from "./refresh.js";

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
  feedError: false,
  selectedFindingId: null,
  historicalSearch: { active: false, cursor: null, hasMore: false }
};

// Populated once lib/ui/reviewer-session.js resolves (see bottom of file).
let reviewerSession = null;

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

// "category:<id>" and "verdict:<id>" are reserved sentinel query values used
// by the built-in preset views (lib/ui/saved-views.js PRESET_VIEWS) so that
// "Government"/"Banks" match real watchlist.json brand category membership
// and "Provider-reported phishing" matches a real intel verdict, instead of
// a hardcoded English word that may never appear in any finding's fields.
const CATEGORY_QUERY_RE = /^category:([a-z0-9_-]+)$/i;
const VERDICT_QUERY_RE = /^verdict:([a-z0-9_-]+)$/i;

function matchesFindingQuery(finding, query) {
  if (!query) return true;
  const categoryMatch = query.match(CATEGORY_QUERY_RE);
  if (categoryMatch) {
    const category = categoryMatch[1].toLowerCase();
    const brands = state.data?.watchlist?.brands || [];
    const brandIds = new Set(
      brands.filter((b) => String(b.category).toLowerCase() === category).map((b) => b.id)
    );
    return (finding.matched_brands || []).some((b) => brandIds.has(b));
  }
  const verdictMatch = query.match(VERDICT_QUERY_RE);
  if (verdictMatch) {
    const verdict = verdictMatch[1].toLowerCase();
    return intelEvidence(finding).some((item) => intelVerdict(item) === verdict);
  }
  const searchTarget = `${finding.registrable} ${(finding.domains || []).join(" ")} ${(finding.matched_brands || []).join(" ")} ${(finding.matched_schemes || []).join(" ")}`.toLowerCase();
  return searchTarget.includes(query);
}

function filteredFindings() {
  return (state.findings || []).filter((f) => {
    const sevMatch = state.findingSeverity === "watch"
      ? priorityScore(f) >= 70
      : (!state.findingSeverity || f.severity === state.findingSeverity);
    return sevMatch && matchesFindingQuery(f, state.findingQuery);
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
    if (button.dataset.view === view) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  });
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === view);
  });
}

async function renderSummary() {
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
  if (pending.length) {
    const { renderReviewCard } = await import('./lib/ui/findings-list.js');
    $("pending-list").innerHTML = pending.map(renderReviewCard).join("");
  } else {
    $("pending-list").innerHTML = '<li class="watch-card review-card"><div class="watch-card-head"><strong>No parked domains</strong><span class="review-badge ok">clear</span></div><p>Nothing is waiting for manual ownership review.</p></li>';
  }
  $("data-status").textContent = `Watchlist loaded at ${new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" })}`;
}

async function renderFindingList() {
  if (state.feedError || (state.feedLoading && !state.findings.length)) return;
  const findings = filteredFindings();
  const totalLoaded = state.findings.length;
  $('feed-status').textContent = !state.feedConfigured ? 'Database not connected'
    : state.historicalSearch.active
      ? (findings.length ? `${findings.length} of ${totalLoaded} from stored history match` : 'No matches in stored history')
      : findings.length ? `${findings.length} of ${totalLoaded} loaded findings match`
        : state.findingSeverity === 'watch' ? 'No domains at priority 70 or above' : 'No matches in loaded findings';

  const isDesktop = typeof window !== 'undefined' && window.innerWidth >= 1024;
  const container = $('finding-list-container');

  if (isDesktop && container) {
    const old = container.querySelector('.finding-list-table');
    if (old) old.remove();
    $('finding-list').style.display = 'none';
    const { renderFindingTableBody } = await import('./lib/ui/findings-list.js');
    const table = document.createElement('table');
    table.className = 'finding-list-table';
    table.innerHTML = renderFindingTableBody(findings, state.selectedFindingId, Boolean(reviewerSession?.currentToken()));
    container.appendChild(table);
  } else {
    if (container) {
      const old = container.querySelector('.finding-list-table');
      if (old) old.remove();
      $('finding-list').style.display = '';
    }
    if (findings.length) {
      const { renderFindingCard } = await import('./lib/ui/findings-list.js');
      $('finding-list').innerHTML = findings.map((f, idx) => renderFindingCard(f, idx)).join('');
    } else {
      $('finding-list').innerHTML = '<li class="watch-card finding-card"><div class="watch-card-head"><strong>No matching findings</strong><span class="review-badge ok">clear</span></div><p>No alerts match current search/filter criteria.</p></li>';
    }
  }

  // Refresh or stale-notice for the selected finding
  if (state.selectedFindingId && isDesktop) {
    const selected = findings.find((f) => f.id === state.selectedFindingId);
    if (selected) {
      openDetailPanel(selected);
    } else {
      const panel = $('detail-panel');
      const inner = $('detail-panel-inner');
      if (panel && inner) {
        panel.hidden = false;
        inner.innerHTML = `<div class="detail-stale-notice">Selected finding is no longer in the current view. <button type="button" id="close-stale-btn">Dismiss</button></div>`;
        const dismissBtn = inner.querySelector('#close-stale-btn');
        if (dismissBtn) dismissBtn.onclick = closeDetailPanel;
      }
    }
  }
}

async function renderFindings(signal) {
  const request = ++state.findingsRequest;
  const view = state.findingSeverity === "watch" ? "&view=watch" : "";
  state.feedLoading = true;
  state.feedError = false;
  $("finding-list").setAttribute("aria-busy", "true");
  $("export-json-btn").disabled = true;
  $("export-csv-btn").disabled = true;
  try {
    const response = await fetch(`/api/findings?limit=50${view}`, { signal });
    if (response.status === 503) {
      const recovery = await response.json().catch(() => null);
      signal.throwIfAborted();
      if (recovery?.error === "storage_recovery" && recovery.maintenance === true) {
        findingsPoller.pauseAutomatic();
        throw Object.assign(new Error("Database recovery in progress"), { maintenance: true });
      }
    }
    if (!response.ok) throw new Error("Feed unavailable");
    const payload = await response.json();
    signal.throwIfAborted();
    // A slow response from an earlier filter must not replace the current view.
    if (request !== state.findingsRequest) return false;
    const findings = Array.isArray(payload.findings) ? payload.findings : [];
    state.findings = findings;
    state.feedConfigured = Boolean(payload.storage_configured);
    state.feedLoading = false;
    $("feed-health").textContent = payload.storage_configured ? "Live database connected" : "Database not connected";
    $("feed-count").textContent = findings.length;
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });

    await renderFindingList();
    return true;
  } catch (error) {
    if (request !== state.findingsRequest || (signal.aborted && signal.reason?.name !== "TimeoutError")) return false;
    state.findings = [];
    state.feedLoading = false;
    state.feedError = true;
    $("feed-status").textContent = error.message;
    $("feed-health").textContent = error.maintenance ? "Database recovery in progress" : "Feed check failed";
    $("feed-count").textContent = "—";
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });
    $("finding-list").innerHTML = error.maintenance
      ? '<li class="watch-card finding-card"><div class="watch-card-head"><strong>Stored history is temporarily unavailable</strong><span class="review-badge">recovery</span></div><p>New collection is paused while database recovery is arranged. Automatic refresh is paused on this page. Reload later to check again.</p></li>'
      : '<li class="watch-card finding-card"><div class="watch-card-head"><strong>Could not load alerts</strong><span class="review-badge">unavailable</span></div><p>The findings API did not respond on this page load. The next automatic refresh will check again.</p></li>';
    return false;
  } finally {
    if (request === state.findingsRequest) {
      state.feedLoading = false;
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

function renderMonitorOperations(source, unavailable = false) {
  const operations = source.operations || {};
  const time = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) ? formatTime(value) : "Not reported";
  const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : "Not reported";
  const external = source.schedule?.last_external_trigger_at;
  $("ct-scheduler").textContent = unavailable ? "Unavailable"
    : time(external) !== "Not reported" ? `GitHub Actions; external trigger observed ${time(external)}`
    : "GitHub Actions fallback; external trigger not observed";
  $("ct-last-start").textContent = time(operations.last_started_at);
  $("ct-last-success").textContent = time(operations.last_success_at);
  $("ct-next-due").textContent = time(operations.next_due_at);
  const runtime = operations.runtime_ms;
  $("ct-runtime").textContent = Number.isFinite(runtime) && runtime >= 0
    ? `${Math.floor(runtime / 60000)}m ${Math.floor(runtime / 1000) % 60}s${operations.state === "running" ? " elapsed" : ""}` : "Not reported";
  $("ct-run-state").textContent = unavailable ? "Unavailable"
    : ({ running: "Running", completed: "Completed", failed: "Failed" })[operations.state] || "Pending";
  $("ct-freshness").textContent = unavailable ? "Unavailable" : ({
    fresh: "Fresh", warning: "Warning (>30 min)", critical: "Critical (>60 min)"
  })[operations.freshness] || "No successful scan reported";
  $("ct-freshness").dataset.level = operations.freshness || "unknown";
  const lag = source.cursor_lag;
  $("ct-cursor-lag").textContent = lag?.measured_logs > 0 && count(lag.lag_entries) !== "Not reported"
    ? `${count(lag.lag_entries)} entries across ${count(lag.measured_logs)} measured ${lag.measured_logs === 1 ? "log" : "logs"}` : "Not measured";
  $("ct-run").textContent = [operations.run_id, operations.trigger].filter(Boolean).join(" / ") || "Not reported";
}

function renderCoverageStrip(source, unavailable = false) {
  const operations = source.operations || {};

  function formatSgt(value) {
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) return "Not reported";
    return new Date(value).toLocaleString("en-SG", {
      timeZone: "Asia/Singapore",
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    });
  }

  // Collection state — derived only from operations fields, never from storage_configured
  let collectionText;
  if (unavailable) {
    collectionText = "Unknown";
  } else if (operations.state === "running") {
    collectionText = "Scan running";
  } else if (operations.state === "completed") {
    collectionText = `Last scan: ${formatSgt(operations.last_success_at)}`;
  } else {
    // absent, "pending", "failed", or any unrecognised state
    collectionText = "Collection paused";
  }

  // Last CT scan time
  const lsText = `Last CT scan: ${formatSgt(operations.last_success_at)}`;

  // Evidence freshness
  const freshnessMap = {
    fresh: "Fresh",
    warning: "Warning \u2014 scan overdue",
    critical: "Critical \u2014 scan overdue",
  };
  const freshnessText = unavailable ? "Unknown" : (freshnessMap[operations.freshness] || "Unknown");

  const collectionEl = $("coverage-collection");
  const lastScanEl = $("coverage-last-scan");
  const evidenceEl = $("coverage-evidence");
  if (collectionEl) collectionEl.textContent = collectionText;
  if (lastScanEl) lastScanEl.textContent = lsText;
  if (evidenceEl) evidenceEl.textContent = `Evidence: ${freshnessText}`;
}

async function renderSourceStatus(signal) {
  try {
    const response = await fetch(CT_SOURCE_STATUS_URL, { signal });
    if (response.status === 503) {
      const recovery = await response.json().catch(() => null);
      signal.throwIfAborted();
      if (recovery?.error === "storage_recovery" && recovery.maintenance === true) {
        statusPoller.pauseAutomatic();
        throw Object.assign(new Error("Database recovery in progress"), { maintenance: true });
      }
    }
    if (!response.ok) throw new Error("source check failed");
    const status = await response.json();
    signal.throwIfAborted();

    const source = status.status && typeof status.status === "object" ? status.status : status;
    const sources = (source.display_sources || source.sources || []).filter((item) => !Object.hasOwn(INTEL_SOURCES, item.source));
    renderIntelSourceStatus(source);
    renderMonitorOperations(source);
    renderCoverageStrip(source);
    const okCount = sources.filter((item) => item.ok || item.status === "ok").length;
    const health = source.health || source.overall;
    const primaryActive = sources.some((item) => item.source === "direct_ct" && item.ok)
      || sources.some((item) => item.source === "static_ct" && item.ok);

    $("source-status").dataset.level = health === "down" ? "critical" : source.operations?.freshness || "unknown";
    if (health === "down" || source.operations?.state === "failed") {
      $("source-status").textContent = "Scan failed";
    } else if (health === "stale") {
      $("source-status").textContent = source.operations?.freshness === "critical" ? "Scan overdue (critical)"
        : source.operations?.freshness === "warning" ? "Scan overdue (warning)" : "Scan overdue";
    } else if (source.operations?.state === "running") {
      $("source-status").textContent = "Scan running";
    } else if (health === "pending") {
      $("source-status").textContent = "waiting for scan";
    } else if (health === "healthy") {
      $("source-status").textContent = "Monitoring active";
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
    return true;
  } catch (error) {
    if (signal.aborted && signal.reason?.name !== "TimeoutError") return false;
    renderMonitorOperations({}, true);
    renderCoverageStrip({}, true);
    $("source-status").dataset.level = "unknown";
    $("source-status").textContent = error.maintenance ? "Collection paused · database recovery" : "scan status unknown";
    $("source-list").innerHTML = error.maintenance
      ? '<div class="source-row warn"><span>Database recovery</span><strong>paused</strong><small>Source history is temporarily unavailable. Automatic refresh is paused on this page.</small></div>'
      : '<div class="source-row bad"><span>Status API</span><strong>unavailable</strong><small>Could not load source health</small></div>';
    $("intel-schedule").textContent = error.maintenance ? "Intel collection paused" : "Intel schedule unavailable";
    $("intel-source-list").innerHTML = error.maintenance
      ? '<div class="source-row warn"><span>Database recovery</span><strong>paused</strong><small>New collection is paused. Reload later to check again.</small></div>'
      : '<div class="source-row bad"><span>Intel status API</span><strong>unavailable</strong><small>Could not load intel source health</small></div>';
    return false;
  }
}

function buildDialogBodyHtml(finding) {
  const signalsRows = (finding.signals || []).map((s) => `
    <tr>
      <td><code>${escapeHtml(s.type)}</code></td>
      <td><strong>+${escapeHtml(s.points || 0)}</strong></td>
      <td>${escapeHtml(signalText(s))}</td>
    </tr>
  `).join("");
  return `
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
        <button type="button" id="print-report-btn" class="btn-secondary">Print report</button>
      </div>
      <p class="muted-text">Live probing is performed by analysts off-platform; this dashboard never fetches a suspected hostile host from production.</p>
    </section>
    <section class="dialog-section">
      <h3>Triggered Scoring Signals</h3>
      <table class="signals-table">
        <thead><tr><th>Signal</th><th>Points</th><th>Detail</th></tr></thead>
        <tbody>${signalsRows || "<tr><td colspan='3'>No signals recorded</td></tr>"}</tbody>
      </table>
    </section>
    <section class="dialog-section">
      <h3>Certificate Identity &amp; SANs</h3>
      <p><strong>Domains:</strong> <code>${escapeHtml((finding.domains || []).join(", "))}</code></p>
      <p><strong>Serial:</strong> <code>${escapeHtml(finding.cert_serial || "N/A")}</code></p>
      <p><strong>Issuer DN SHA256:</strong> <code>${escapeHtml(finding.cert_issuer_dn_sha256 || "N/A")}</code></p>
    </section>
  `;
}

/**
 * Append impersonation, timeline and related-findings sections to a
 * detail panel or dialog body after the synchronous body is rendered.
 * Fires async so the initial render is never delayed.
 * @param {object} finding
 * @param {Element} container — inner panel or dialog-body element
 */
async function enhanceDetailPanel(finding, container) {
  try {
    const [
      { buildTimeline, renderTimeline },
      { renderRelated },
      { explainImpersonation, renderImpersonation },
    ] = await Promise.all([
      import('./lib/ui/evidence-timeline.js'),
      import('./lib/ui/related-findings.js'),
      import('./lib/ui/impersonation.js'),
    ]);

    if (!container.isConnected) return;

    let extraHtml = '';

    // Impersonation explanation (only if brand signals present and data loaded)
    if (state.data && (finding.signals || []).some((s) => s.type?.startsWith('brand'))) {
      const expls = explainImpersonation(
        finding,
        state.data.watchlist.brands,
        state.data.allowlist.entries
      );
      if (expls.length) {
        extraHtml += `<section class="dialog-section" aria-labelledby="imp-hd">
          <h3 id="imp-hd">Brand Impersonation Analysis</h3>
          ${renderImpersonation(expls, escapeHtml)}
        </section>`;
      }
    }

    // Evidence timeline
    const events = buildTimeline(finding);
    extraHtml += `<section class="dialog-section" aria-labelledby="timeline-hd">
      <h3 id="timeline-hd">Evidence Timeline</h3>
      ${renderTimeline(events, true)}
    </section>`;

    // Related findings in loaded set
    extraHtml += `<section class="dialog-section" aria-labelledby="related-hd">
      <h3 id="related-hd">Related Findings (loaded)</h3>
      ${renderRelated(finding, state.findings, escapeHtml)}
    </section>`;

    // Analyst review (Task 9) — requires sign-in; loaded async after the
    // synchronous body renders, matching the pattern for the sections above.
    if (reviewerSession?.currentToken()) {
      extraHtml += `<section class="dialog-section" aria-labelledby="review-hd">
        <h3 id="review-hd">Analyst Review</h3>
        <div id="${reviewSectionElId(finding.id)}" class="review-content">Loading review state…</div>
      </section>`;
    } else {
      extraHtml += `<section class="dialog-section" aria-labelledby="review-hd">
        <h3 id="review-hd">Analyst Review</h3>
        <p class="muted-text">Sign in to review this finding.</p>
      </section>`;
    }

    if (!container.isConnected) return;
    const extra = document.createElement('div');
    extra.className = 'dialog-extra-sections';
    extra.innerHTML = extraHtml;
    container.appendChild(extra);
    if (reviewerSession?.currentToken()) {
      void loadReviewPanel(finding, container);
    }
  } catch {
    // Module load or render error — extra sections unavailable
  }
}
function wireCopyButton(finding, btn) {
  if (!btn) return;
  btn.onclick = async () => {
    const evidence = intelEvidence(finding).map((item) =>
      `  * ${sourceLabel(item.source)}: ${intelVerdict(item)}; host ${item.domain}; observed ${item.observed_at}; expires ${item.expires_at}; ${intelProviderUrl(item.source_ref, item.source) || "Provider reference unavailable"}`
    ).join("\n");
    const report = `# Triage Report: ${finding.registrable}\n- CT score: ${finding.score} (${finding.severity})\n- Priority: ${priorityScore(finding)} (intel +${finding.intel_priority_boost === 10 ? 10 : 0})\n- Intel hits: ${intelHitCount(finding)}\n${evidence}\n- Issuer: ${finding.issuer}\n- Observed: ${finding.observed_at}\n- Signals:\n${(finding.signals || []).map((s) => `  * ${s.type} (+${s.points})`).join("\n")}`;
    try {
      await navigator.clipboard.writeText(report);
      btn.textContent = "Copied!";
    } catch {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => { btn.textContent = "Copy Triage Report"; }, 2000);
  };
}

function reviewSectionElId(findingId) {
  return `review-content-${String(findingId).replace(/[^a-zA-Z0-9_-]/g, '')}`;
}

function renderReviewMessage(container, findingId, message) {
  const target = container.querySelector(`#${reviewSectionElId(findingId)}`);
  if (target) target.innerHTML = `<p class="muted-text">${escapeHtml(message)}</p>`;
}

async function loadReviewPanel(finding, container) {
  const token = reviewerSession?.currentToken();
  if (!token) return;
  try {
    const resp = await fetch(`/api/reviews?finding_id=${encodeURIComponent(finding.id)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!container.isConnected) return;
    if (resp.status === 401) {
      renderReviewMessage(container, finding.id, 'Session expired. Sign in again.');
      return;
    }
    if (!resp.ok) {
      renderReviewMessage(container, finding.id, 'Could not load review state.');
      return;
    }
    const body = await resp.json();
    if (!container.isConnected) return;
    renderReviewForm(finding, container, body.review);
  } catch {
    if (container.isConnected) renderReviewMessage(container, finding.id, 'Could not load review state.');
  }
}

function renderReviewForm(finding, container, review) {
  const target = container.querySelector(`#${reviewSectionElId(finding.id)}`);
  if (!target) return;
  const status = review?.status || 'new';
  const disposition = review?.disposition || 'unassessed';
  const note = review?.note || '';
  const revision = review?.revision ?? 1;
  target.innerHTML = `
    <form class="review-form" data-revision="${escapeHtml(revision)}">
      <label>Status
        <select name="status" class="triage-select">
          <option value="new" ${status === 'new' ? 'selected' : ''}>New</option>
          <option value="investigating" ${status === 'investigating' ? 'selected' : ''}>Investigating</option>
          <option value="resolved" ${status === 'resolved' ? 'selected' : ''}>Resolved</option>
        </select>
      </label>
      <label>Disposition
        <select name="disposition" class="triage-select">
          <option value="unassessed" ${disposition === 'unassessed' ? 'selected' : ''}>Unassessed</option>
          <option value="false_positive" ${disposition === 'false_positive' ? 'selected' : ''}>False positive</option>
          <option value="reported_phishing" ${disposition === 'reported_phishing' ? 'selected' : ''}>Reported phishing</option>
        </select>
      </label>
      <label>Note
        <textarea name="note" maxlength="2000" rows="3" class="triage-input">${escapeHtml(note)}</textarea>
      </label>
      <div class="review-actions">
        <button type="submit" class="btn-primary btn-sm">Save review</button>
        <span class="review-form-msg" role="status"></span>
      </div>
      ${review ? `<p class="muted-text review-meta">Last updated ${escapeHtml(formatTime(review.updated_at))} (revision ${escapeHtml(review.revision)})</p>` : '<p class="muted-text review-meta">No review recorded yet.</p>'}
    </form>
  `;
  const form = target.querySelector('.review-form');
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    void submitReview(finding, container, form);
  });
}

async function submitReview(finding, container, form) {
  const token = reviewerSession?.currentToken();
  const msgEl = form.querySelector('.review-form-msg');
  if (!token) {
    if (msgEl) msgEl.textContent = 'Session expired. Sign in again.';
    return;
  }
  const fd = new FormData(form);
  const payload = {
    finding_id: finding.id,
    status: fd.get('status'),
    disposition: fd.get('disposition'),
    note: fd.get('note') || '',
    revision: Number(form.dataset.revision) || 1,
    request_uuid: crypto.randomUUID(),
  };
  if (msgEl) msgEl.textContent = 'Saving…';
  try {
    const resp = await fetch('/api/reviews', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    const body = await resp.json().catch(() => ({}));
    if (resp.status === 409) {
      if (msgEl) msgEl.textContent = 'Someone else updated this review. Reloaded the latest state — please retry.';
      void loadReviewPanel(finding, container);
      return;
    }
    if (resp.status === 400 && body.error === 'disposition_required_for_resolved') {
      if (msgEl) msgEl.textContent = 'Choose a disposition before marking Resolved.';
      return;
    }
    if (resp.status === 401) {
      if (msgEl) msgEl.textContent = 'Session expired. Sign in again.';
      return;
    }
    if (!resp.ok) {
      if (msgEl) msgEl.textContent = 'Save failed.';
      return;
    }
    if (msgEl) msgEl.textContent = 'Saved.';
    form.dataset.revision = String(body.review.revision);
    const meta = form.querySelector('.review-meta');
    if (meta) meta.textContent = `Last updated ${formatTime(body.review.updated_at)} (revision ${body.review.revision})`;
    setTimeout(() => { if (msgEl && msgEl.textContent === 'Saved.') msgEl.textContent = ''; }, 2500);
  } catch {
    if (msgEl) msgEl.textContent = 'Save failed (network).';
  }
}

// ---------------------------------------------------------------------------
// Historical search (Task 8) — bounded stored-history search beyond the
// loaded batch, backed by the already-tested search=1 API in
// api/findings.js / lib/findings-query.js.
// ---------------------------------------------------------------------------

function historicalSeverityParams() {
  if (state.findingSeverity === 'watch') return { priority_min: '70' };
  if (!state.findingSeverity) return {};
  return { severity: state.findingSeverity };
}

function showHistoricalSearchError(message) {
  const bar = $('historical-search-bar');
  const label = $('historical-search-label');
  const moreBtn = $('historical-search-more-btn');
  if (bar) bar.hidden = false;
  if (label) label.textContent = message;
  if (moreBtn) moreBtn.hidden = true;
}

function updateHistoricalSearchBar() {
  const bar = $('historical-search-bar');
  const label = $('historical-search-label');
  const moreBtn = $('historical-search-more-btn');
  if (!bar) return;
  bar.hidden = !state.historicalSearch.active;
  if (label) label.textContent = `Searching stored history — ${state.findings.length} loaded`;
  if (moreBtn) moreBtn.hidden = !state.historicalSearch.hasMore;
}

async function runHistoricalSearch(reset = true) {
  const q = state.findingQuery;
  if (q && q.length > 0 && q.length < 3) {
    showHistoricalSearchError('Type at least 3 characters to search stored history.');
    return;
  }
  const params = new URLSearchParams({ search: '1', limit: '50', ...historicalSeverityParams() });
  if (q) params.set('q', q);
  if (!reset && state.historicalSearch.cursor) params.set('cursor', state.historicalSearch.cursor);

  const btn = $('historical-search-btn');
  const moreBtn = $('historical-search-more-btn');
  if (btn) btn.disabled = true;
  if (moreBtn) moreBtn.disabled = true;
  try {
    const resp = await fetch(`/api/findings?${params.toString()}`);
    const body = await resp.json().catch(() => ({}));
    if (resp.status === 400 && body.error === 'cursor_invalid' && !reset) {
      // Filters changed since the cursor was issued — restart the search.
      state.historicalSearch.cursor = null;
      if (btn) btn.disabled = false;
      if (moreBtn) moreBtn.disabled = false;
      return runHistoricalSearch(true);
    }
    if (!resp.ok) {
      showHistoricalSearchError(body.message || 'Historical search failed.');
      return;
    }
    state.historicalSearch.active = true;
    state.historicalSearch.cursor = body.page?.next_cursor ?? null;
    state.historicalSearch.hasMore = Boolean(body.page?.has_more);
    state.findings = reset ? (body.findings || []) : [...state.findings, ...(body.findings || [])];
    state.feedConfigured = Boolean(body.storage_configured);
    updateHistoricalSearchBar();
    await renderFindingList();
  } catch {
    showHistoricalSearchError('Historical search failed (network).');
  } finally {
    if (btn) btn.disabled = false;
    if (moreBtn) moreBtn.disabled = false;
  }
}

function exitHistoricalSearch() {
  clearTimeout(historicalSearchDebounce);
  state.historicalSearch.active = false;
  state.historicalSearch.cursor = null;
  state.historicalSearch.hasMore = false;
  const bar = $('historical-search-bar');
  if (bar) bar.hidden = true;
  findingsPoller.refresh();
}

function openDetailPanel(finding) {
  const panel = $("detail-panel");
  const inner = $("detail-panel-inner");
  if (!panel || !inner) return;
  state.selectedFindingId = finding.id;
  inner.innerHTML = buildDialogBodyHtml(finding);
  panel.hidden = false;
  const closeBtn = inner.querySelector("#close-dialog-btn");
  if (closeBtn) closeBtn.onclick = closeDetailPanel;
  const printBtn = inner.querySelector("#print-report-btn");
  if (printBtn) printBtn.onclick = () => window.print();
  wireCopyButton(finding, inner.querySelector("#copy-triage-btn"));
  void enhanceDetailPanel(finding, inner);
}

function closeDetailPanel() {
  const panel = $("detail-panel");
  if (panel) panel.hidden = true;
  state.selectedFindingId = null;
}

function openFindingDetails(finding) {
  const dialog = $("finding-dialog");
  const body = $("dialog-body");
  if (!dialog || !body) return;
  body.innerHTML = buildDialogBodyHtml(finding);
  dialog.showModal();
  const closeBtn = body.querySelector("#close-dialog-btn");
  if (closeBtn) closeBtn.onclick = () => dialog.close();
  const printBtn = body.querySelector("#print-report-btn");
  if (printBtn) printBtn.onclick = () => window.print();
  wireCopyButton(finding, body.querySelector("#copy-triage-btn"));
  void enhanceDetailPanel(finding, body);
}

async function exportFindingsJson() {
  const { toJson } = await import('./lib/ui/report.js');
  const findings = filteredFindings();
  const scope = `Loaded findings (${findings.length} of ${state.findings.length})`;
  const data = toJson(findings, scope);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sgcertwatch_findings_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

async function exportFindingsCsv() {
  const { toCsv } = await import('./lib/ui/report.js');
  const findings = filteredFindings();
  const scope = `Loaded findings (${findings.length} of ${state.findings.length})`;
  const data = toCsv(findings, scope);
  const blob = new Blob([data], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sgcertwatch_findings_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
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

let historicalSearchDebounce = null;
$("finding-search").addEventListener("input", (event) => {
  state.findingQuery = event.target.value.trim().toLowerCase();
  if (state.historicalSearch.active) {
    clearTimeout(historicalSearchDebounce);
    historicalSearchDebounce = setTimeout(() => { void runHistoricalSearch(true); }, 300);
    return;
  }
  renderFindingList();
});

$("severity-filter").addEventListener("change", (event) => {
  state.findingSeverity = event.target.value;
  if (state.historicalSearch.active) {
    void runHistoricalSearch(true);
    return;
  }
  state.findings = [];
  $("feed-status").textContent = "Loading feed";
  $("finding-list").innerHTML = '<li class="watch-card finding-card">Loading findings</li>';
  findingsPoller.refresh();
});

$("export-json-btn").addEventListener("click", exportFindingsJson);
$("export-csv-btn").addEventListener("click", exportFindingsCsv);

$('historical-search-btn')?.addEventListener('click', () => {
  clearTimeout(historicalSearchDebounce);
  void runHistoricalSearch(true);
});
$('historical-search-more-btn')?.addEventListener('click', () => { void runHistoricalSearch(false); });
$('historical-search-exit-btn')?.addEventListener('click', exitHistoricalSearch);

// Handle clicks on both mobile cards (#finding-list) and desktop table buttons (#finding-list-container)
document.addEventListener("click", (event) => {
  // Desktop: [data-open-detail] button in table
  const detailBtn = event.target.closest("[data-open-detail]");
  if (detailBtn) {
    const id = detailBtn.dataset.openDetail;
    const finding = filteredFindings().find((f) => f.id === id);
    if (finding) openDetailPanel(finding);
    return;
  }
  // Mobile: [data-finding-index] card in list
  const card = event.target.closest("[data-finding-index]");
  if (!card) return;
  const idx = parseInt(card.dataset.findingIndex, 10);
  const findings = filteredFindings();
  if (findings[idx]) openFindingDetails(findings[idx]);
});

document.addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-finding-index]")) {
    event.preventDefault();
    event.target.click();
  }
});

// ---------------------------------------------------------------------------
// Saved views
// ---------------------------------------------------------------------------

function applyFilter(filter) {
  state.findingQuery = filter.query || "";
  state.findingSeverity = filter.severity || "watch";
  const searchEl = $("finding-search");
  const severityEl = $("severity-filter");
  if (searchEl) searchEl.value = state.findingQuery;
  if (severityEl) severityEl.value = state.findingSeverity;
  state.findings = [];
  $("feed-status").textContent = "Loading feed";
  $("finding-list").innerHTML = '<li class="watch-card finding-card">Loading findings</li>';
  findingsPoller.refresh();
}

function showViewsMsg(text, ms = 2000) {
  const el = $("saved-views-msg");
  if (!el) return;
  el.textContent = text;
  setTimeout(() => { if (el.textContent === text) el.textContent = ""; }, ms);
}

async function renderSavedViews() {
  const { loadViews, PRESET_VIEWS } = await import('./lib/ui/saved-views.js');
  const list = $("saved-views-list");
  if (!list) return;
  const saved = loadViews();
  const all = [...PRESET_VIEWS, ...saved];
  list.innerHTML = all.map((v, i) => {
    const isPreset = i < PRESET_VIEWS.length;
    const active = v.filter.query === state.findingQuery && v.filter.severity === state.findingSeverity;
    return `<span class="saved-view-item">
      <button type="button" class="saved-view-btn${active ? ' active' : ''}" data-view-idx="${i}" data-view-preset="${isPreset}">${escapeHtml(v.name)}</button>
      ${!isPreset ? `<button type="button" class="saved-view-delete" data-delete-view="${escapeHtml(v.name)}" aria-label="Delete view ${escapeHtml(v.name)}">&times;</button>` : ''}
    </span>`;
  }).join("");
}

$("save-view-btn")?.addEventListener("click", async () => {
  const name = prompt("Save view as:");
  if (!name || !name.trim()) return;
  const trimmed = name.trim().slice(0, 60);
  const { saveView } = await import('./lib/ui/saved-views.js');
  const result = saveView(trimmed, { query: state.findingQuery, severity: state.findingSeverity });
  if (result.ok) {
    showViewsMsg("Saved");
    renderSavedViews();
  } else {
    showViewsMsg(result.reason === "limit_reached" ? "Max 20 views" : "Save failed");
  }
});

$("copy-view-link-btn")?.addEventListener("click", async () => {
  const { encodeFilter } = await import('./lib/ui/saved-views.js');
  const qs = encodeFilter({ query: state.findingQuery, severity: state.findingSeverity });
  const url = `${location.origin}${location.pathname}${qs ? '?' + qs : ''}`;
  try {
    await navigator.clipboard.writeText(url);
    showViewsMsg("Link copied");
  } catch {
    showViewsMsg("Copy failed");
  }
});

$("saved-views-list")?.addEventListener("click", async (event) => {
  const deleteBtn = event.target.closest("[data-delete-view]");
  if (deleteBtn) {
    const { deleteView } = await import('./lib/ui/saved-views.js');
    deleteView(deleteBtn.dataset.deleteView);
    renderSavedViews();
    return;
  }
  const viewBtn = event.target.closest("[data-view-idx]");
  if (!viewBtn) return;
  const idx = parseInt(viewBtn.dataset.viewIdx, 10);
  const { loadViews, PRESET_VIEWS } = await import('./lib/ui/saved-views.js');
  const all = [...PRESET_VIEWS, ...loadViews()];
  if (all[idx]) {
    applyFilter(all[idx].filter);
    renderSavedViews();
  }
});

// Restore filter from URL on load
(async () => {
  const search = location.search;
  if (search) {
    const { decodeFilter } = await import('./lib/ui/saved-views.js');
    const filter = decodeFilter(search.slice(1));
    if (filter.query || filter.severity !== "watch") {
      applyFilter(filter);
    }
  }
  renderSavedViews();
})();

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
const findingsPoller = visiblePoller(renderFindings, 120000);
const statusPoller = visiblePoller(renderSourceStatus, 60000);
findingsPoller.refresh();
statusPoller.refresh();

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});
setView(state.view);

// ---------------------------------------------------------------------------
// Analyst sign-in (Task 9) — memory-only session, same-origin password
// grant proxied through api/reviewer-session.js. Backed by the already-
// tested lib/ui/reviewer-session.js singleton.
// ---------------------------------------------------------------------------

function reviewerSignInErrorMessage(code) {
  const messages = {
    invalid_credentials: 'Incorrect email or password.',
    not_a_reviewer: 'This account is not an authorized reviewer.',
    reviewer_not_configured: 'Analyst sign-in is not configured yet.',
    auth_unavailable: 'Sign-in service unavailable. Try again shortly.',
    auth_stale: 'Sign-in was interrupted. Try again.',
  };
  return messages[code] || 'Sign-in failed.';
}

function updateReviewerAuthUI() {
  const user = reviewerSession?.currentUser?.();
  const signinBtn = $('reviewer-signin-btn');
  const signinForm = $('reviewer-signin-form');
  const signedInBox = $('reviewer-signed-in');
  const signedInLabel = $('reviewer-signed-in-label');
  if (user) {
    if (signinBtn) signinBtn.hidden = true;
    if (signinForm) signinForm.hidden = true;
    if (signedInBox) signedInBox.hidden = false;
    if (signedInLabel) signedInLabel.textContent = `Signed in as ${user.id.slice(0, 8)}…`;
  } else {
    if (signinBtn) signinBtn.hidden = false;
    if (signinForm) signinForm.hidden = true;
    if (signedInBox) signedInBox.hidden = true;
  }
  // Re-render the desktop table's Review column and any open detail view
  // now that sign-in state changed. The mobile dialog is modal and blocks
  // interaction with the sign-in control while open, so it needs no refresh.
  void renderFindingList();
  if (state.selectedFindingId) {
    const panel = $('detail-panel');
    if (panel && !panel.hidden) {
      const selected = filteredFindings().find((f) => f.id === state.selectedFindingId);
      if (selected) openDetailPanel(selected);
    }
  }
}

$('reviewer-signin-btn')?.addEventListener('click', () => {
  $('reviewer-signin-btn').hidden = true;
  const form = $('reviewer-signin-form');
  if (form) { form.hidden = false; $('reviewer-email')?.focus(); }
});

$('reviewer-signin-cancel')?.addEventListener('click', () => {
  const form = $('reviewer-signin-form');
  if (form) form.hidden = true;
  const btn = $('reviewer-signin-btn');
  if (btn) btn.hidden = false;
  const err = $('reviewer-signin-error');
  if (err) err.textContent = '';
});

$('reviewer-signin-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const errorEl = $('reviewer-signin-error');
  if (errorEl) errorEl.textContent = '';
  if (!reviewerSession) {
    if (errorEl) errorEl.textContent = 'Still loading, try again.';
    return;
  }
  const email = $('reviewer-email')?.value.trim() ?? '';
  const password = $('reviewer-password')?.value ?? '';
  try {
    await reviewerSession.signIn(email, password);
    const pwField = $('reviewer-password');
    if (pwField) pwField.value = '';
    updateReviewerAuthUI();
  } catch (err) {
    if (errorEl) errorEl.textContent = reviewerSignInErrorMessage(err.message);
  }
});

$('reviewer-signout-btn')?.addEventListener('click', async () => {
  await reviewerSession?.signOut();
  updateReviewerAuthUI();
});

(async () => {
  const { reviewerSession: session } = await import('./lib/ui/reviewer-session.js');
  reviewerSession = session;
  reviewerSession.onChange(() => updateReviewerAuthUI());
  updateReviewerAuthUI();
})();

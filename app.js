const files = {
  watchlist: "/watchlist.json",
  keywords: "/keywords.json",
  allowlist: "/allowlist.json",
  schemes: "/schemes.json"
};

const CT_SOURCE_STATUS_URL = "/api/source-status";

const state = {
  data: null,
  dataset: "brands",
  query: "",
  category: "",
  findings: []
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

function sourceLabel(source) {
  const labels = {
    certstream: "Live stream",
    direct_ct: "Direct CT logs",
    crtsh: "crt.sh backup"
  };
  return labels[source] || source;
}

function sourceState(item) {
  if (item.ok && item.details?.state === "standby") {
    return { label: "standby", className: "standby" };
  }
  if (item.ok) {
    return { label: "ok", className: "ok" };
  }
  return { label: "degraded", className: "warn" };
}

function sourceDetail(item) {
  const checked = `${item.scanned_entries || 0} checked`;
  const matched = `${item.matched || 0} matches`;
  const note = item.details?.note || item.errors?.[0]?.message || "";
  return note ? `${checked} - ${matched} - ${note}` : `${checked} - ${matched}`;
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
  if (signal.type?.startsWith("brand")) return `${signal.display || signal.brand} name`;
  if (signal.type === "tld:mismatch") return `unusual .${signal.actual} ending`;
  if (signal.type === "kw") return `${signal.token} keyword`;
  if (signal.type === "scheme") return `${signal.display || signal.scheme} scheme`;
  return signal.type || "matched rule";
}

function renderReasons(signals = []) {
  const reasons = unique(signals.map(signalText)).slice(0, 4);
  return reasons.length ? tokenList(reasons) : "";
}

function renderFindingCard(finding) {
  const domains = (finding.domains || []).slice(0, 3).join(", ");
  const sources = (finding.sources || []).map(sourceLabel).join(", ") || "unknown";
  return `
    <li class="watch-card finding-card">
      <div class="watch-card-head">
        <strong>${escapeHtml(finding.registrable)}</strong>
        <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)} ${escapeHtml(finding.score)}</span>
      </div>
      <p>${escapeHtml(domains || "No domain names stored")}</p>
      ${renderReasons(finding.signals)}
      <div class="watch-meta">
        <span>${escapeHtml(finding.source_count || 0)} source${finding.source_count === 1 ? "" : "s"}: ${escapeHtml(sources)}</span>
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
        <td>${row.source ? `<a href="${escapeHtml(row.source)}">${escapeHtml(row.source)}</a>` : ""}</td>
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
        <td>${row.source ? `<a href="${escapeHtml(row.source)}">${escapeHtml(row.source)}</a>` : ""}</td>
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
  render();

  document.querySelectorAll("[data-dataset]").forEach((element) => {
    const active = element.dataset.dataset === dataset;
    element.classList.toggle("active", active);
    if (element.hasAttribute("aria-pressed")) {
      element.setAttribute("aria-pressed", active ? "true" : "false");
    }
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

async function renderFindings() {
  try {
    const response = await fetch("/api/findings?limit=8");
    if (!response.ok) throw new Error("Feed unavailable");
    const payload = await response.json();
    const findings = payload.findings || [];
    state.findings = findings;

    $("feed-status").textContent = payload.storage_configured
      ? (findings.length ? "Latest stored alerts from Supabase" : "No suspicious certificate alerts stored yet")
      : "Database not connected";
    $("feed-health").textContent = payload.storage_configured ? "Live database connected" : "Database not connected";
    $("feed-count").textContent = findings.length;
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });

    $("finding-list").innerHTML = findings.length
      ? findings.map(renderFindingCard).join("")
      : '<li class="watch-card finding-card"><div class="watch-card-head"><strong>No live alerts yet</strong><span class="review-badge ok">clear</span></div><p>The 5-minute CT scan will show suspicious domains here after a match is found.</p></li>';
  } catch (error) {
    $("feed-status").textContent = error.message;
    $("feed-health").textContent = "Feed check failed";
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });
    $("finding-list").innerHTML = '<li class="watch-card finding-card"><div class="watch-card-head"><strong>Could not load alerts</strong><span class="review-badge">unavailable</span></div><p>The findings API did not respond on this page load. The next automatic refresh will check again.</p></li>';
  }
}

async function renderSourceStatus() {
  try {
    const response = await fetch(CT_SOURCE_STATUS_URL);
    if (!response.ok) throw new Error("source check failed");
    const status = await response.json();

    const source = status.status || status;
    const sources = source.sources || [];
    const okCount = sources.filter((item) => item.ok).length;

    if (source.health === "healthy") {
      $("source-status").textContent = "Monitoring active";
    } else if (source.health === "partial" || okCount > 0) {
      $("source-status").textContent = "Partial coverage";
    } else if (source.errors?.length) {
      $("source-status").textContent = "Source degraded";
    } else {
      $("source-status").textContent = "waiting for scan";
    }

    $("source-list").innerHTML = sources.length
      ? sources.map((item) => {
        const state = sourceState(item);
        return `
        <div class="source-row ${state.className}">
          <span>${escapeHtml(item.label || sourceLabel(item.source))}</span>
          <strong>${escapeHtml(state.label)}</strong>
          <small>${escapeHtml(sourceDetail(item))}</small>
        </div>
      `;
      }).join("")
      : '<div class="source-row"><span>Waiting for first scan</span><strong>pending</strong><small>Runs every 5 minutes</small></div>';
  } catch (_error) {
    $("source-status").textContent = "scan status unknown";
    $("source-list").innerHTML = '<div class="source-row bad"><span>Status API</span><strong>unavailable</strong><small>Could not load source health</small></div>';
  }
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

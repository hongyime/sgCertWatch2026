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

function searchable(row) {
  return JSON.stringify(row).toLowerCase();
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
  $("allowlist-status").textContent = unverifiedAllowlist === 0 ? "green" : `${unverifiedAllowlist} unverified`;
  $("scheme-status").textContent = unverifiedSchemes === 0 ? "green" : `${unverifiedSchemes} unverified`;
  $("pending-status").textContent = pending.length === 0 ? "none" : `${pending.length} parked`;
  $("pending-list").innerHTML = pending.map((entry) => `
    <li>
      <strong>${escapeHtml(entry.registrable)}</strong>
      <span>${escapeHtml(entry.brand)} is not suppressing alerts because ownership/current status is not strong enough.</span>
    </li>
  `).join("");
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
      ? findings.map((finding) => `
        <li class="finding">
          <strong>${escapeHtml(finding.registrable)}</strong>
          ${escapeHtml((finding.domains || []).slice(0, 2).join(", "))}
          <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)} ${escapeHtml(finding.score)}</span>
        </li>
      `).join("")
      : '<li class="finding">No live alerts yet. The scheduled CT scan is running in GitHub Actions and will appear here after a match is stored.</li>';
  } catch (error) {
    $("feed-status").textContent = error.message;
    $("feed-health").textContent = "Feed check failed";
    $("last-feed-check").textContent = new Date().toLocaleTimeString("en-SG", { hour: "2-digit", minute: "2-digit" });
    $("finding-list").innerHTML = '<li class="finding">Could not load the live alert feed.</li>';
  }
}

async function renderSourceStatus() {
  try {
    const response = await fetch(CT_SOURCE_STATUS_URL);
    if (!response.ok) throw new Error("source check failed");
    const status = await response.json();

    const source = status.status || status;

    if (source.ok) {
      $("source-status").textContent = `${source.scanned_entries || 0} checked`;
      return;
    }

    if (source.errors?.length) {
      $("source-status").textContent = "poll errors";
      return;
    }

    $("source-status").textContent = "waiting for first poll";
  } catch (_error) {
    $("source-status").textContent = "source unknown";
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

const files = {
  watchlist: "/watchlist.json",
  keywords: "/keywords.json",
  allowlist: "/allowlist.json",
  schemes: "/schemes.json"
};

const state = {
  data: null,
  dataset: "brands",
  query: "",
  category: ""
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
  $("table-title").textContent = state.dataset[0].toUpperCase() + state.dataset.slice(1);
  $("result-count").textContent = `${rows.length} result${rows.length === 1 ? "" : "s"}`;

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
  $("pending-status").textContent = `${pending.length} non-suppressing`;
  $("pending-list").innerHTML = pending.map((entry) => `<li><strong>${escapeHtml(entry.registrable)}</strong>: ${escapeHtml(entry.reason)}</li>`).join("");
  $("data-status").textContent = `Data loaded from JSON seed files`;
}

async function renderFindings() {
  try {
    const response = await fetch("/api/findings?limit=8");
    if (!response.ok) throw new Error("Feed unavailable");
    const payload = await response.json();
    const findings = payload.findings || [];

    $("feed-status").textContent = payload.storage_configured
      ? `${findings.length} latest finding${findings.length === 1 ? "" : "s"}`
      : "Persistence not configured";

    $("finding-list").innerHTML = findings.length
      ? findings.map((finding) => `
        <li class="finding">
          <strong>${escapeHtml(finding.registrable)}</strong>
          ${escapeHtml((finding.domains || []).slice(0, 2).join(", "))}
          <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)} ${escapeHtml(finding.score)}</span>
        </li>
      `).join("")
      : '<li class="finding">No stored findings yet.</li>';
  } catch (error) {
    $("feed-status").textContent = error.message;
    $("finding-list").innerHTML = '<li class="finding">No stored findings yet.</li>';
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
  } catch (error) {
    $("data-status").textContent = error.message;
    $("data-status").classList.add("error");
  }
}

$("search").addEventListener("input", (event) => {
  state.query = event.target.value.trim().toLowerCase();
  renderTable();
});

$("dataset-filter").addEventListener("change", (event) => {
  state.dataset = event.target.value;
  state.category = "";
  render();
});

$("category-filter").addEventListener("change", (event) => {
  state.category = event.target.value;
  renderTable();
});

loadData();

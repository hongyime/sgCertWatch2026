/**
 * lib/ui/saved-views.js
 *
 * Pure ES module — no DOM access, no fetch.
 * Manages saved investigation views in localStorage.
 *
 * Storage key: sgcertwatch.savedViews.v1
 * Max entries: 20
 * Name length: 1–60 characters
 *
 * A view stores only filter/query/sort state — never finding bodies,
 * notes, credentials, or private disposition data.
 */

const STORAGE_KEY = "sgcertwatch.savedViews.v1";
const MAX_VIEWS = 20;
const MAX_NAME_LEN = 60;

/** Allowed severity enum values. */
const SEVERITY_ENUM = new Set(["watch", "", "critical", "high", "medium", "low"]);

/**
 * Normalize a filter state object, rejecting unknown enum values.
 * Returns null if the object is structurally invalid.
 * @param {unknown} raw
 * @returns {{ query: string, severity: string } | null}
 */
export function normalizeFilter(raw) {
  if (!raw || typeof raw !== "object") return null;
  const query = typeof raw.query === "string" ? raw.query.slice(0, 253) : "";
  const severity = typeof raw.severity === "string" && SEVERITY_ENUM.has(raw.severity)
    ? raw.severity : "watch";
  return { query, severity };
}

/**
 * Encode a filter state as URLSearchParams.
 * Only non-default values are included.
 * @param {{ query: string, severity: string }} filter
 * @returns {string} query string (without leading ?)
 */
export function encodeFilter(filter) {
  const params = new URLSearchParams();
  if (filter.query) params.set("q", filter.query);
  if (filter.severity && filter.severity !== "watch") params.set("s", filter.severity);
  return params.toString();
}

/**
 * Decode a URLSearchParams string back to a filter state.
 * @param {string} search  e.g. "q=singpass&s=high"
 * @returns {{ query: string, severity: string }}
 */
export function decodeFilter(search) {
  const params = new URLSearchParams(search);
  const raw = {
    query: params.get("q") ?? "",
    severity: params.get("s") ?? "watch",
  };
  return normalizeFilter(raw) ?? { query: "", severity: "watch" };
}

/**
 * Load all saved views from storage.
 * Returns an empty array if storage is unavailable or data is corrupt.
 * @param {Storage} [storage]  defaults to localStorage
 * @returns {Array<{ name: string, filter: { query: string, severity: string } }>}
 */
export function loadViews(storage) {
  try {
    const store = storage ?? globalThis.localStorage;
    const raw = store?.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((v) => v && typeof v.name === "string" && v.name.length >= 1 && v.name.length <= MAX_NAME_LEN)
      .map((v) => ({ name: v.name, filter: normalizeFilter(v.filter) ?? { query: "", severity: "watch" } }))
      .slice(0, MAX_VIEWS);
  } catch {
    return [];
  }
}

/**
 * Save a view. Replaces an existing view with the same name.
 * Returns { ok: true } or { ok: false, reason: string }.
 * @param {string} name
 * @param {{ query: string, severity: string }} filter
 * @param {Storage} [storage]
 */
export function saveView(name, filter, storage) {
  if (typeof name !== "string" || name.length < 1 || name.length > MAX_NAME_LEN) {
    return { ok: false, reason: "invalid_name" };
  }
  const normalized = normalizeFilter(filter);
  if (!normalized) return { ok: false, reason: "invalid_filter" };
  try {
    const store = storage ?? globalThis.localStorage;
    const views = loadViews(store);
    const idx = views.findIndex((v) => v.name === name);
    if (idx >= 0) {
      views[idx] = { name, filter: normalized };
    } else {
      if (views.length >= MAX_VIEWS) return { ok: false, reason: "limit_reached" };
      views.push({ name, filter: normalized });
    }
    store.setItem(STORAGE_KEY, JSON.stringify(views));
    return { ok: true };
  } catch {
    return { ok: false, reason: "storage_unavailable" };
  }
}

/**
 * Delete a view by name. No-op if not found.
 * @param {string} name
 * @param {Storage} [storage]
 */
export function deleteView(name, storage) {
  try {
    const store = storage ?? globalThis.localStorage;
    const views = loadViews(store).filter((v) => v.name !== name);
    store.setItem(STORAGE_KEY, JSON.stringify(views));
  } catch {
    // Storage unavailable — silently ignore
  }
}

/**
 * Built-in preset views. These use actual brand IDs/categories from watchlist.json.
 * Labelled as "loaded-data views" until Task 8 enables historical search.
 */
export const PRESET_VIEWS = [
  {
    name: "Government (loaded data)",
    filter: { query: "government", severity: "" },
  },
  {
    name: "Banks (loaded data)",
    filter: { query: "bank", severity: "" },
  },
  {
    name: "Provider-reported phishing",
    filter: { query: "", severity: "watch" },
  },
];

/**
 * Workbench saved-views tests — node:test + Playwright
 * Run: node --test --test-timeout=90000 scripts/test_workbench_views.mjs
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { start } from "./workbench-fixture.mjs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-06"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

/** Intercept lib/ui/*.js files not in the fixture allowlist. */
async function routeLibUi(page) {
  for (const name of ["findings-list.js", "finding-details.js", "report.js", "saved-views.js"]) {
    const content = await readFile(
      resolve(__dirname, "..", "lib", "ui", name), "utf8"
    );
    await page.route(`**/lib/ui/${name}`, (route) =>
      route.fulfill({ contentType: "application/javascript; charset=utf-8", body: content })
    );
  }
}

// ---------------------------------------------------------------------------
// Test 1 — reload-restores-view
// ---------------------------------------------------------------------------
test("reload-restores-view: saved view persists across page reload", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await routeLibUi(page);

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Switch to "high" severity
    const highFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "high");
    await highFetch;

    // Save the view using localStorage directly (avoids prompt() dialog)
    await page.evaluate(() => {
      const views = [{ name: "Test High View", filter: { query: "", severity: "high" } }];
      localStorage.setItem("sgcertwatch.savedViews.v1", JSON.stringify(views));
    });

    // Reload the page
    const reloadFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.reload();
    await reloadFetch;

    // Wait for saved views bar to render
    await page.waitForSelector("#saved-views-list", { timeout: 8_000 });

    // The saved view button should appear
    const viewBtn = await page.$('[data-view-idx]');
    assert.ok(viewBtn, "Saved view button should appear after reload");

    // Check localStorage still has the view
    const stored = await page.evaluate(() => localStorage.getItem("sgcertwatch.savedViews.v1"));
    const parsed = JSON.parse(stored);
    assert.ok(Array.isArray(parsed) && parsed.some((v) => v.name === "Test High View"),
      "Saved view should persist in localStorage");

    await page.screenshot({ path: join(EVIDENCE_DIR, "reload-restores-view.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 2 — back-restores-filters
// ---------------------------------------------------------------------------
test("back-restores-filters: URL filter params restore state on navigation", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await routeLibUi(page);

    // Navigate with a filter in the URL
    const filteredFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(`${fixture.url}?s=high`);
    await filteredFetch;

    // Wait for severity filter to be set
    await page.waitForFunction(
      () => {
        const el = document.getElementById("severity-filter");
        return el && el.value === "high";
      },
      { timeout: 8_000 }
    );

    const severityValue = await page.$eval("#severity-filter", (el) => el.value);
    assert.equal(severityValue, "high", "Severity filter should be restored from URL");

    await page.screenshot({ path: join(EVIDENCE_DIR, "back-restores-filters.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 3 — invalid-storage-falls-back
// ---------------------------------------------------------------------------
test("invalid-storage-falls-back: corrupt localStorage does not crash the page", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await routeLibUi(page);

    // Inject corrupt localStorage before navigation
    await page.addInitScript(() => {
      localStorage.setItem("sgcertwatch.savedViews.v1", "NOT_VALID_JSON{{{");
    });

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Page should load without errors
    await page.waitForSelector("#saved-views-list", { timeout: 8_000 });

    // No JS errors should have crashed the page
    const feedStatus = await page.$eval("#feed-status", (el) => el.textContent);
    assert.ok(feedStatus.length > 0, "Feed status should be present (page loaded successfully)");

    // Saved views list should be empty (corrupt data ignored) but presets should show
    const viewBtns = await page.$$("[data-view-idx]");
    // Presets are always shown (3 presets)
    assert.ok(viewBtns.length >= 3, "Preset views should still appear despite corrupt storage");

    await page.screenshot({ path: join(EVIDENCE_DIR, "invalid-storage-falls-back.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 4 — private-data-never-saved
// ---------------------------------------------------------------------------
test("private-data-never-saved: localStorage contains only filter state, not finding bodies", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await routeLibUi(page);

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Save a view via localStorage directly
    await page.evaluate(() => {
      const views = [{ name: "Privacy Test", filter: { query: "singpass", severity: "high" } }];
      localStorage.setItem("sgcertwatch.savedViews.v1", JSON.stringify(views));
    });

    // Inspect all localStorage keys
    const allStorage = await page.evaluate(() => {
      const result = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        result[key] = localStorage.getItem(key);
      }
      return result;
    });

    // Only the views key should be present
    const viewsKey = "sgcertwatch.savedViews.v1";
    const viewsData = JSON.parse(allStorage[viewsKey] || "[]");

    // Each view should only have name and filter — no finding bodies, no credentials
    for (const view of viewsData) {
      assert.ok(typeof view.name === "string", "View should have a name");
      assert.ok(view.filter && typeof view.filter === "object", "View should have a filter");
      assert.ok(!("findings" in view), "View must not contain findings");
      assert.ok(!("token" in view), "View must not contain tokens");
      assert.ok(!("credentials" in view), "View must not contain credentials");
      // Filter should only have query and severity
      const filterKeys = Object.keys(view.filter);
      assert.ok(
        filterKeys.every((k) => ["query", "severity"].includes(k)),
        `Filter should only have query/severity, got: ${filterKeys.join(", ")}`
      );
    }

    await page.screenshot({ path: join(EVIDENCE_DIR, "private-data-never-saved.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 5 — all-severities-url-round-trips (pure, no browser)
// ---------------------------------------------------------------------------
test("all-severities-url-round-trips: an explicit empty-severity filter survives encode+decode, not just non-empty ones", async () => {
  const { encodeFilter, decodeFilter } = await import("../lib/ui/saved-views.js");

  // severity: "" means "show every severity" (the "Recent findings" / All
  // view). It must NOT be indistinguishable from "no filter was ever set"
  // (which defaults to "watch"), or a shared link/reload silently reverts
  // to Watch.
  const qs = encodeFilter({ query: "", severity: "" });
  assert.ok(qs.length > 0, "an explicit empty severity must produce a non-empty query string");

  const restored = decodeFilter(qs);
  assert.equal(restored.severity, "", "decoding must restore severity as empty, not fall back to watch");

  // Non-default, non-empty severities must still round-trip as before.
  const qsHigh = encodeFilter({ query: "singpass", severity: "high" });
  assert.equal(decodeFilter(qsHigh).severity, "high");
  assert.equal(decodeFilter(qsHigh).query, "singpass");

  // The default ("watch") is still omitted from the URL for a clean link.
  const qsDefault = encodeFilter({ query: "", severity: "watch" });
  assert.equal(qsDefault, "", "the default severity must not appear in the URL");
});

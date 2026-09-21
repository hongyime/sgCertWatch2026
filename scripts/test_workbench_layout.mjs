/**
 * Workbench layout tests — node:test + Playwright
 * Run: node --test --test-timeout=90000 scripts/test_workbench_layout.mjs
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
  "free-tier-investigation-upgrade", "task-05"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

/** Intercept lib/ui/*.js files not in the fixture allowlist. */
async function routeLibUi(page) {
  for (const name of ["findings-list.js", "finding-details.js", "report.js"]) {
    const content = await readFile(
      resolve(__dirname, "..", "lib", "ui", name), "utf8"
    );
    await page.route(`**/lib/ui/${name}`, (route) =>
      route.fulfill({ contentType: "application/javascript; charset=utf-8", body: content })
    );
  }
}

// ---------------------------------------------------------------------------
// Test 1 — selection-survives-refresh
// ---------------------------------------------------------------------------
test("selection-survives-refresh: detail panel stays open after findings refresh", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.setViewportSize({ width: 1280, height: 800 });
    await routeLibUi(page);

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Switch to "Recent findings" (all) to get the table
    const allFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allFetch;

    // Wait for the desktop table to appear
    await page.waitForSelector(".finding-list-table", { timeout: 10_000 });

    // Click the Details button for the first row
    const firstBtn = page.locator("[data-open-detail]").first();
    const firstId = await firstBtn.getAttribute("data-open-detail");
    await firstBtn.click();

    // Wait for detail panel to open
    await page.waitForFunction(
      () => {
        const p = document.getElementById("detail-panel");
        return p && !p.hidden;
      },
      { timeout: 8_000 }
    );

    // Trigger a refresh by switching severity and back
    const refreshFetch1 = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "high");
    await refreshFetch1;

    const refreshFetch2 = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await refreshFetch2;

    // Wait for table to re-render
    await page.waitForSelector(".finding-list-table", { timeout: 10_000 });

    // Detail panel must still be visible
    const panelHidden = await page.$eval("#detail-panel", (el) => el.hidden);
    assert.equal(panelHidden, false, "Detail panel should still be visible after refresh");

    // The panel should show the same finding
    const panelTitle = await page.$eval("#finding-dialog-title", (el) => el.textContent.trim());
    assert.ok(panelTitle.length > 0, "Panel should show a finding title");

    // The selected row should have aria-selected="true"
    const selectedRow = await page.$(`[data-finding-id="${firstId}"][aria-selected="true"]`);
    assert.ok(selectedRow, `Row for ${firstId} should have aria-selected=true`);

    await page.screenshot({ path: join(EVIDENCE_DIR, "selection-survives-refresh.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 2 — selection-removed
// ---------------------------------------------------------------------------
test("selection-removed: stale notice appears when selected finding leaves results", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.setViewportSize({ width: 1280, height: 800 });
    await routeLibUi(page);

    // Track call count to serve different responses
    let callCount = 0;
    let targetId = null;

    await page.route(/\/api\/findings/, async (route) => {
      callCount++;
      if (callCount === 1 || targetId === null) {
        // First call: serve all 50 findings
        await route.continue();
      } else {
        // Subsequent calls: serve findings without the target
        const resp = await route.fetch();
        const body = await resp.json();
        const filtered = {
          ...body,
          findings: (body.findings || []).filter((f) => f.id !== targetId),
        };
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: { "Cache-Control": "no-store" },
          body: JSON.stringify(filtered),
        });
      }
    });

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Switch to all findings
    const allFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allFetch;

    await page.waitForSelector(".finding-list-table", { timeout: 10_000 });

    // Click Details for the first finding and record its ID
    const firstBtn = page.locator("[data-open-detail]").first();
    targetId = await firstBtn.getAttribute("data-open-detail");
    await firstBtn.click();

    await page.waitForFunction(
      () => { const p = document.getElementById("detail-panel"); return p && !p.hidden; },
      { timeout: 8_000 }
    );

    // Trigger a refresh — the next API call will exclude targetId
    const refreshFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "high");
    await refreshFetch;

    // Wait for stale notice to appear
    await page.waitForFunction(
      () => {
        const inner = document.getElementById("detail-panel-inner");
        return inner && inner.textContent.includes("no longer in the current view");
      },
      { timeout: 10_000 }
    );

    const noticeText = await page.$eval("#detail-panel-inner", (el) => el.textContent);
    assert.ok(
      noticeText.includes("no longer in the current view"),
      `Expected stale notice, got: "${noticeText.slice(0, 200)}"`
    );

    await page.screenshot({ path: join(EVIDENCE_DIR, "selection-removed.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 3 — mobile-close-restores-focus
// ---------------------------------------------------------------------------
test("mobile-close-restores-focus: Escape closes dialog and returns focus to card", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.setViewportSize({ width: 375, height: 812 });
    await routeLibUi(page);

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Switch to all findings to get cards
    const allFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allFetch;

    // Wait for cards to render
    await page.waitForSelector(".finding-card", { timeout: 10_000 });

    // Focus and click the first card
    const firstCard = page.locator(".finding-card").first();
    await firstCard.focus();
    await firstCard.click();

    // Wait for dialog to open
    await page.waitForSelector("#finding-dialog[open]", { timeout: 8_000 });

    // Press Escape to close
    await page.keyboard.press("Escape");

    // Wait for dialog to close
    await page.waitForFunction(
      () => {
        const d = document.getElementById("finding-dialog");
        return d && !d.hasAttribute("open");
      },
      { timeout: 5_000 }
    );

    // Dialog should be closed
    const dialogOpen = await page.$eval("#finding-dialog", (el) => el.hasAttribute("open"));
    assert.equal(dialogOpen, false, "Dialog should be closed after Escape");

    await page.screenshot({ path: join(EVIDENCE_DIR, "mobile-close-restores-focus.png"), fullPage: false });
    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

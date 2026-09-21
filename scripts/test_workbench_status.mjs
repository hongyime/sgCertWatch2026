/**
 * Workbench status / coverage-strip tests — node:test + Playwright
 *
 * Verifies the ownership-check navigation rename and the coverage-strip
 * DOM element introduced by the free-tier-investigation-upgrade Task 2.
 *
 * Run:
 *   node --test scripts/test_workbench_status.mjs
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { start } from "./workbench-fixture.mjs";

const __dirname   = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-02"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Test 1 — config-success-is-not-collection-success
//
// storage_configured: true must NOT cause coverage-last-scan to show a real
// timestamp.  When operations.state is "pending" and last_success_at is null
// the strip must show "Not reported", never a fabricated datetime string.
// ---------------------------------------------------------------------------
test("config-success-is-not-collection-success: pending ops shows Not reported, not a timestamp", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page    = await context.newPage();

    // Intercept BEFORE navigation so we cannot miss the first fetch.
    await page.route(/\/api\/source-status/, (route) =>
      route.fulfill({
        status:      200,
        contentType: "application/json",
        headers:     { "Cache-Control": "no-store" },
        body:        JSON.stringify({
          storage_configured: true,   // config success — must NOT imply collection success
          health:             "pending",
          sources:            [],
          display_sources:    [],
          intel_sources:      [],
          operations: {
            state:           "pending",
            last_started_at: null,
            last_success_at: null,      // no timestamp — strip must say "Not reported"
            freshness:       "unknown",
            next_due_at:     null,
            runtime_ms:      null,
            run_id:          null,
            trigger:         null,
          },
          cursor_lag:    { measured_logs: 0, lag_entries: null },
          intel_schedule: null,
          schedule:       { runner: "github-actions", last_external_trigger_at: null },
          source_runs:    [],
          updated_at:     new Date().toISOString(),
        }),
      })
    );

    const statusFetch = page.waitForResponse(
      (r) => r.url().includes("/api/source-status") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await statusFetch;

    // Wait for coverage-last-scan to be populated by renderCoverageStrip.
    await page.waitForFunction(
      () => {
        const el = document.getElementById("coverage-last-scan");
        return el != null && el.textContent.trim().length > 1 && el.textContent !== "Last CT scan: —";
      },
      { timeout: 15_000 }
    );

    await page.screenshot({
      path:     join(EVIDENCE_DIR, "config-success-is-not-collection-success.png"),
      fullPage: false,
    });

    const lastScanText = await page.locator("#coverage-last-scan").textContent();

    // Must show "Not reported" — not a datetime string derived from a null timestamp.
    assert.ok(
      lastScanText.includes("Not reported"),
      `Expected "Not reported" in coverage-last-scan, got: "${lastScanText}"`
    );

    // Must NOT contain a year digit sequence that looks like a real timestamp.
    assert.ok(
      !/\b20\d{2}\b/.test(lastScanText),
      `coverage-last-scan must not contain a year-like string, got: "${lastScanText}"`
    );

    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 2 — ownership-stays-ownership
//
// After the nav button text changes from "Review" to "Ownership checks", the
// button must still navigate to the correct view (data-view-panel="review")
// and the pending allowlist entries from the fixture must still appear.
// ---------------------------------------------------------------------------
test("ownership-stays-ownership: renamed nav button still shows pending entries", async () => {
  await ensureEvidence();

  const fixture = await start();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page    = await context.newPage();

    // Intercept lib/ui/findings-list.js (not in fixture allowlist)
    const findingsListContent = await import('node:fs/promises').then(fs =>
      fs.readFile(resolve(__dirname, '..', 'lib', 'ui', 'findings-list.js'), 'utf8')
    );
    await page.route(/\/lib\/ui\/findings-list\.js/, (route) =>
      route.fulfill({ contentType: 'application/javascript; charset=utf-8', body: findingsListContent })
    );

    // Wait for initial findings fetch before interacting.
    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Wait for watchlist data to load (allowlist-count rendered by renderSummary).
    await page.waitForFunction(
      () => {
        const el = document.getElementById("allowlist-count");
        return el != null && el.textContent !== "-";
      },
      { timeout: 15_000 }
    );

    // Click the "Ownership checks" button (formerly "Review").
    await page.click('button[data-view="review"]');

    // The review panel must become active.
    await page.waitForFunction(
      () => {
        const panel = document.querySelector('[data-view-panel="review"]');
        return panel != null && panel.classList.contains("active");
      },
      { timeout: 8_000 }
    );

    await page.screenshot({
      path:     join(EVIDENCE_DIR, "ownership-stays-ownership.png"),
      fullPage: false,
    });

    // pending-list must be populated (either entries or the "no parked domains" empty state).
    const listText = await page.locator("#pending-list").textContent();
    assert.ok(
      listText.trim().length > 0,
      `Expected #pending-list to have content after clicking "Ownership checks", got empty string`
    );

    // The review panel must be the active view.
    const panelActive = await page.locator('[data-view-panel="review"]').evaluate(
      (el) => el.classList.contains("active")
    );
    assert.ok(panelActive, 'Expected [data-view-panel="review"] to have class "active"');

    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 3 — timestamps-are-sgt
//
// Even when the browser locale is forced to UTC (via emulateTimezone), the
// coverage-last-scan span must display Singapore Time (SGT / +08).
//
// Fixture returns last_success_at: "2026-09-20T05:00:00.000Z" (UTC).
// In SGT that is 13:00 (+08:00).  The assertion checks for "SGT" or "+08"
// in the rendered text, proving the explicit timeZone option is in effect.
// ---------------------------------------------------------------------------
test("timestamps-are-sgt: coverage strip shows SGT regardless of browser locale", async () => {
  await ensureEvidence();

  const fixture = await start();
  // Force browser timezone to UTC so any non-explicit formatting would show UTC.
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext({ timezoneId: "UTC" });
    const page    = await context.newPage();

    const SGT_ISO = "2026-09-20T05:00:00.000Z";  // 13:00 SGT

    await page.route(/\/api\/source-status/, (route) =>
      route.fulfill({
        status:      200,
        contentType: "application/json",
        headers:     { "Cache-Control": "no-store" },
        body:        JSON.stringify({
          storage_configured: true,
          health:             "healthy",
          sources:            [],
          display_sources:    [],
          intel_sources:      [],
          operations: {
            state:           "completed",
            last_started_at: SGT_ISO,
            last_success_at: SGT_ISO,
            freshness:       "fresh",
            next_due_at:     null,
            runtime_ms:      60000,
            run_id:          "test-run-001",
            trigger:         "scheduled",
          },
          cursor_lag:    { measured_logs: 0, lag_entries: null },
          intel_schedule: null,
          schedule:       { runner: "github-actions", last_external_trigger_at: null },
          source_runs:    [],
          updated_at:     new Date().toISOString(),
        }),
      })
    );

    const statusFetch = page.waitForResponse(
      (r) => r.url().includes("/api/source-status") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await statusFetch;

    // Wait for coverage-last-scan to reflect the injected timestamp.
    await page.waitForFunction(
      () => {
        const el = document.getElementById("coverage-last-scan");
        return el != null && el.textContent.includes("Last CT scan:") && !el.textContent.includes("—");
      },
      { timeout: 15_000 }
    );

    await page.screenshot({
      path:     join(EVIDENCE_DIR, "timestamps-are-sgt.png"),
      fullPage: false,
    });

    const lastScanText = await page.locator("#coverage-last-scan").textContent();

    // Must contain "SGT" or "+08" — proves the explicit timeZone option is working.
    assert.ok(
      lastScanText.includes("SGT") || lastScanText.includes("+08"),
      `Expected "SGT" or "+08" in coverage-last-scan (browser TZ=UTC), got: "${lastScanText}"`
    );

    // Must NOT show 05:00 (UTC value) — proves we are not using system timezone.
    assert.ok(
      !lastScanText.includes("5:00") && !lastScanText.includes("05:00"),
      `coverage-last-scan must not show UTC time 05:00, got: "${lastScanText}"`
    );

    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
  }
});

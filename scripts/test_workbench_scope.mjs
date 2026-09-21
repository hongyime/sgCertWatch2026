/**
 * Workbench scope tests — node:test + Playwright
 *
 * Tests the honest-scope UI labels introduced by the free-tier-investigation
 * upgrade.  Chromium is launched once (before) and closed once (after) to
 * avoid per-test startup overhead; each test opens its own BrowserContext.
 *
 * Run:
 *   node --test scripts/test_workbench_scope.mjs
 */

import assert from "node:assert/strict";
import { test, before, after } from "node:test";
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { start } from "./workbench-fixture.mjs";

const __dirname   = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-01"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Shared resources — one browser + one fixture server for all tests.
// This avoids repeated Chromium launch overhead.
// ---------------------------------------------------------------------------
let browser;
let fixture;

before(async () => {
  fixture = await start();
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close().catch(() => {});
  await fixture?.close().catch(() => {});
});

// ---------------------------------------------------------------------------
// Test 1 — loaded-scope
//
// Proves that when a user searches for a hostname that is in the generator
// (record-075.test) but not in the 50 loaded findings, the UI says
// "No matches in loaded findings" rather than any copy that implies the
// domain is absent from all stored history.
// ---------------------------------------------------------------------------
test("loaded-scope: no-match label mentions loaded scope, not global absence", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();

    // --- 1. Navigate and wait for the initial findings fetch -----------------
    // Register the response watcher BEFORE navigation so we cannot miss it.
    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // --- 2. Switch severity to "All" (value="") ------------------------------
    // The "No matches in loaded findings" copy only appears in non-watch mode.
    // Register the watcher before triggering the select change.
    const allModeFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allModeFetch;

    // --- 3. Fill the search input with a term not present in the loaded 50 --
    // record-075.test is the 51st entry in generateFindings — never served by
    // /api/findings, so it won't match any loaded finding.
    await page.fill("#finding-search", "record-075.test");

    // --- 4. Wait for the scope-honest no-match message -----------------------
    // NOTE: waitForFunction(fn, arg, options) — pass null as arg so that the
    // options object is correctly interpreted as options, not as the arg.
    await page.waitForFunction(
      () => {
        const s = document.getElementById("feed-status");
        return s != null && s.textContent.includes("No matches in loaded findings");
      },
      null,
      { timeout: 8_000 }
    );

    // --- 5. Screenshot evidence ----------------------------------------------
    await page.screenshot({
      path:     join(EVIDENCE_DIR, "loaded-scope.png"),
      fullPage: false,
    });

    // --- 6. Assertion --------------------------------------------------------
    const statusText = await page.locator("#feed-status").textContent();

    assert.ok(
      statusText.includes("No matches in loaded findings"),
      `Expected scope-aware no-match message, got: "${statusText}"`
    );
  } finally {
    await context?.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 2 — recovery-is-not-zero
//
// When /api/findings returns a 503 storage_recovery response the UI must show
// an explicit unavailability/paused message — not "0 findings", not a clear
// empty state that would mislead the user into thinking there is no data.
// ---------------------------------------------------------------------------
test("recovery-is-not-zero: 503 recovery shows unavailable copy, not empty state", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();

    // Intercept /api/findings before navigation and return the canonical
    // storage-recovery 503 body that app.js checks for maintenance mode.
    await page.route(/\/api\/findings/, (route) =>
      route.fulfill({
        status:      503,
        contentType: "application/json",
        headers:     { "Cache-Control": "no-store" },
        body:        JSON.stringify({ error: "storage_recovery", maintenance: true }),
      })
    );

    await page.goto(fixture.url);

    // Wait for the maintenance card to appear in the findings list.
    // NOTE: waitForFunction(fn, arg, options) — pass null as arg.
    await page.waitForFunction(
      () => {
        const list = document.getElementById("finding-list");
        return list != null && list.textContent.includes("temporarily unavailable");
      },
      null,
      { timeout: 15_000 }
    );

    // Screenshot evidence
    await page.screenshot({
      path:     join(EVIDENCE_DIR, "recovery-is-not-zero.png"),
      fullPage: false,
    });

    const listText = await page.locator("#finding-list").textContent();

    // --- Assertions ----------------------------------------------------------

    // Must show the maintenance/unavailability copy.
    assert.ok(
      listText.includes("temporarily unavailable") || listText.includes("paused"),
      `Expected maintenance copy in finding-list, got: "${listText.slice(0, 300)}"`
    );

    // Must NOT imply "0 findings" or a clean empty state.
    assert.ok(
      !listText.includes("0 findings"),
      `Must not display "0 findings" during storage recovery, got: "${listText.slice(0, 300)}"`
    );
  } finally {
    await context?.close().catch(() => {});
  }
});

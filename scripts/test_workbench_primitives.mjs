/**
 * Workbench primitives tests — node:test + Playwright
 *
 * Tests the visual primitives and accessibility additions introduced by
 * the free-tier-investigation-upgrade Wave 2 / Task 4:
 *
 *   1. escaping          — finding card escapes HTML in the registrable field
 *   2. keyboard-navigation — skip-link, aria-current nav, and tab order
 *   3. no-network-expansion — no requests leave 127.0.0.1
 *
 * Chromium is launched once (before) and closed once (after) to avoid
 * per-test startup overhead; each test opens its own BrowserContext.
 *
 * Run:
 *   node --test --test-timeout=60000 scripts/test_workbench_primitives.mjs
 */

import assert from "node:assert/strict";
import { test, before, after } from "node:test";
import { mkdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { start } from "./workbench-fixture.mjs";

const __dirname   = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-04"
);
const FINDINGS_LIST_PATH = resolve(__dirname, "..", "lib", "ui", "findings-list.js");

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

/**
 * Intercept the browser's request for lib/ui/findings-list.js and serve the
 * real file content.  The fixture ALLOWLIST does not include lib/ui/*.js, so
 * without this interception the dynamic import inside renderFindingList would
 * fail with a 404.
 */
async function routeFindingsList(page) {
  const content = await readFile(FINDINGS_LIST_PATH, "utf-8");
  await page.route(/\/lib\/ui\/findings-list\.js/, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/javascript; charset=utf-8",
      body: content,
    })
  );
}

// ---------------------------------------------------------------------------
// Test 1 — escaping
//
// Injects a finding whose registrable contains a raw <script> tag.  The card
// must show the literal string in DOM text, not execute the script.
// Uses mobile viewport (375 px) so the app renders cards, not the desktop
// table (which uses a different element structure).
// ---------------------------------------------------------------------------
test("escaping: malicious registrable renders as literal text, not executed", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();

    // Mobile viewport — app renders cards at < 1024 px
    await page.setViewportSize({ width: 375, height: 812 });

    await routeFindingsList(page);

    const maliciousRegistrable = "<script>alert(1)</script>";

    await page.route(/\/api\/findings/, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Cache-Control": "no-store" },
        body: JSON.stringify({
          storage_configured: true,
          findings: [{
            id:                   "test-xss-001",
            registrable:          maliciousRegistrable,
            score:                80,
            severity:             "high",
            priority_score:       80,
            signals:              [],
            matched_brands:       ["test"],
            domains:              ["evil.test"],
            observed_at:          new Date().toISOString(),
            issuer:               "Let's Encrypt",
            sources:              ["direct_ct"],
            source_count:         1,
            intel_evidence:       [],
            intel_hit_count:      0,
            intel_priority_boost: 0,
          }],
        }),
      })
    );

    await page.goto(fixture.url);

    // Wait for the rendered card — the dynamic import of findings-list.js
    // must complete before the card appears in the DOM.
    // NOTE: waitForFunction(fn, arg, options) — pass null as arg so that the
    // options object is correctly interpreted as options, not as the arg.
    await page.waitForFunction(
      () => {
        const list = document.getElementById("finding-list");
        return list !== null && list.querySelector(".finding-card strong") !== null;
      },
      null,
      { timeout: 15_000 }
    );

    await page.screenshot({
      path:     join(EVIDENCE_DIR, "escaping.png"),
      fullPage: false,
    });

    // The DOM text content must be the literal string, not an empty string or
    // a half-parsed injection artefact.
    const cardText = await page.locator(".finding-card strong").first().textContent();
    assert.strictEqual(
      cardText,
      maliciousRegistrable,
      `Expected literal XSS string in card text, got: "${cardText}"`
    );
  } finally {
    await context?.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 2 — keyboard-navigation
//
// Verifies:
//   • First Tab focuses the skip-link.
//   • Second Tab reaches the first nav button.
//   • The active nav button carries aria-current="page".
//   • Finding cards are keyboard-reachable (tabindex="0").
//
// Uses mobile viewport (375 px) so the app renders cards with tabindex="0",
// not the desktop table which uses a different focusability model.
// ---------------------------------------------------------------------------
test("keyboard-navigation: skip-link, aria-current, and finding cards reachable via Tab", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();

    // Mobile viewport — app renders cards at < 1024 px
    await page.setViewportSize({ width: 375, height: 812 });

    await routeFindingsList(page);

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Wait for finding cards to be rendered so we can check their tab
    // reachability later in the assertion.
    // NOTE: waitForFunction(fn, arg, options) — pass null as arg.
    await page.waitForFunction(
      () => document.querySelector(".finding-card[tabindex='0']") !== null,
      null,
      { timeout: 15_000 }
    );

    // --- First Tab: skip-link -----------------------------------------------
    await page.keyboard.press("Tab");

    const focusedClass = await page.evaluate(
      () => document.activeElement?.className ?? ""
    );
    assert.ok(
      focusedClass.includes("skip-link"),
      `Expected skip-link to be focused after first Tab, got class: "${focusedClass}"`
    );

    const skipLinkText = await page.locator(".skip-link").textContent();
    assert.strictEqual(
      skipLinkText,
      "Skip to main content",
      `Expected skip-link text to be "Skip to main content", got: "${skipLinkText}"`
    );

    await page.screenshot({
      path:     join(EVIDENCE_DIR, "keyboard-navigation.png"),
      fullPage: false,
    });

    // --- Second Tab: first nav button ----------------------------------------
    await page.keyboard.press("Tab");
    const navButtonView = await page.evaluate(
      () => document.activeElement?.dataset?.view ?? ""
    );
    assert.ok(
      navButtonView,
      `Expected a [data-view] nav button to be focused after second Tab, got: "${navButtonView}"`
    );

    // --- aria-current on the active nav button --------------------------------
    const ariaCurrentCount = await page.locator("[aria-current='page']").count();
    assert.strictEqual(
      ariaCurrentCount,
      1,
      `Expected exactly 1 element with aria-current="page", found: ${ariaCurrentCount}`
    );

    // --- Finding cards are keyboard-reachable (tabindex="0") -----------------
    const tabbableCards = await page.locator(".finding-card[tabindex='0']").count();
    assert.ok(
      tabbableCards > 0,
      `Expected finding cards to have tabindex="0", found: ${tabbableCards}`
    );
  } finally {
    await context?.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 3 — no-network-expansion
//
// Registers a request listener before navigation and asserts that every
// network request issued by the page goes to 127.0.0.1 only.
// ---------------------------------------------------------------------------
test("no-network-expansion: all requests stay on 127.0.0.1 (the fixture)", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();

    await routeFindingsList(page);

    const externalRequests = [];
    page.on("request", (request) => {
      try {
        const hostname = new URL(request.url()).hostname;
        if (hostname !== "127.0.0.1") {
          externalRequests.push(request.url());
        }
      } catch {
        // Ignore non-URL entries (e.g. data: URIs, about:blank navigations).
      }
    });

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Give any lazy-loaded resources a moment to fire.
    await new Promise((resolve) => setTimeout(resolve, 2_000));

    await page.screenshot({
      path:     join(EVIDENCE_DIR, "no-network-expansion.png"),
      fullPage: false,
    });

    assert.strictEqual(
      externalRequests.length,
      0,
      `Expected zero requests outside 127.0.0.1, found: ${externalRequests.join(", ")}`
    );
  } finally {
    await context?.close().catch(() => {});
  }
});

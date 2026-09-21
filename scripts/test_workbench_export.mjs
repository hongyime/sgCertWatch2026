/**
 * Workbench export tests — node:test + Playwright
 *
 * Chromium is launched once (before) and closed once (after) to avoid
 * per-test startup overhead; each test opens its own BrowserContext.
 *
 * Run: node --test scripts/test_workbench_export.mjs
 */
import assert from "node:assert/strict";
import { test, before, after } from "node:test";
import { mkdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { start } from "./workbench-fixture.mjs";
import { toCsv } from "../lib/ui/report.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-03"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Shared resources — one browser + one fixture server for all tests.
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

/** Minimal RFC 4180 CSV parser — returns array of row objects keyed by header. */
function parseCsv(text) {
  // Split into cells respecting quoted fields
  function splitRow(line) {
    const cells = [];
    let cur = "", inQ = false;
    for (let i = 0; i <= line.length; i++) {
      const ch = line[i];
      if (inQ) {
        if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
        else if (ch === '"') inQ = false;
        else cur += (ch ?? "");
      } else {
        if (ch === '"') inQ = true;
        else if (ch === "," || ch === undefined) { cells.push(cur); cur = ""; }
        else cur += ch;
      }
    }
    return cells;
  }

  // Split text into logical lines (respecting quoted newlines)
  const lines = [];
  let cur = "", inQ = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQ) {
      if (ch === '"' && text[i + 1] === '"') { cur += '""'; i++; }
      else if (ch === '"') { inQ = false; cur += ch; }
      else cur += ch;
    } else {
      if (ch === '"') { inQ = true; cur += ch; }
      else if (ch === "\n") { lines.push(cur); cur = ""; }
      else if (ch === "\r" && text[i + 1] === "\n") { lines.push(cur); cur = ""; i++; }
      else cur += ch;
    }
  }
  if (cur) lines.push(cur);

  const rows = lines.filter(Boolean).map(splitRow);
  const headers = rows[0];
  return rows.slice(1).map((r) =>
    Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ""]))
  );
}

// ---------------------------------------------------------------------------
// Test 1 — csv-roundtrip
// ---------------------------------------------------------------------------
test("csv-roundtrip: special chars, Unicode, formula injection survive round-trip", async () => {
  await ensureEvidence();

  const finding = {
    id: "test-001",
    registrable: "=cmd|' /C calc'!A0",
    score: 85,
    severity: "high",
    priority_score: 85,
    intel_priority_boost: 0,
    issuer: 'Let\'s "Encrypt", CA',
    observed_at: "2026-09-20T05:00:00.000Z",
    sources: ["direct_ct", "static_ct"],
    matched_brands: ["singpass"],
    domains: ["sin\u0261pass-login.test", "www.sin\u0261pass-login.test"],
    cert_serial: "abc123",
    cert_issuer_dn_sha256: "deadbeef",
    intel_hit_count: 1,
    intel_evidence: [{
      source: "urlscan",
      verdict: "phishing",
      domain: "sin\u0261pass-login.test",
      observed_at: "2026-09-19T00:00:00.000Z",
      expires_at: "2026-10-19T00:00:00.000Z",
      source_ref: "https://urlscan.io/result/abc/",
    }],
  };

  const csv = toCsv([finding], "test-scope");
  const rows = parseCsv(csv);

  assert.equal(rows.length, 1, "should have exactly one data row");
  const row = rows[0];

  // Formula injection: registrable starts with = so must be tab-prefixed
  assert.ok(
    row.registrable.startsWith("\t"),
    `registrable must start with tab, got: ${JSON.stringify(row.registrable)}`
  );
  assert.ok(row.registrable.includes("=cmd"), "formula content preserved after tab prefix");

  // Issuer with embedded quotes and comma
  assert.ok(row.issuer.includes("Encrypt"), "issuer content preserved");

  // Unicode domain
  assert.ok(row.domains.includes("sin\u0261pass"), "Unicode domain preserved");

  // Intel evidence JSON round-trips
  const evidence = JSON.parse(row.intel_evidence_summary);
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].verdict, "phishing");

  // Scope and time present
  assert.equal(row.export_scope, "test-scope");
  assert.ok(row.export_time, "export_time present");
});

// ---------------------------------------------------------------------------
// Test 2 — export-scope-matches-selection
// ---------------------------------------------------------------------------
test("export-scope-matches-selection: CSV registrables match visible findings", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    // Use mobile viewport so cards render (not the desktop table)
    await page.setViewportSize({ width: 375, height: 812 });
    // Intercept lib/ui/report.js (not in fixture allowlist)
    await page.route("**/lib/ui/report.js", async (route) => {
      const content = await readFile(
        resolve(__dirname, "..", "lib", "ui", "report.js"), "utf8"
      );
      await route.fulfill({
        contentType: "application/javascript; charset=utf-8",
        body: content,
      });
    });

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Switch to "Recent findings" (all) mode
    const allFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allFetch;

    // Wait for cards to render before querying
    await page.waitForSelector(".finding-card strong", { timeout: 15_000 });

    // Get registrables from DOM — at mobile width, cards render with <strong>
    const domRegistrables = await page.$$eval(
      ".finding-card strong",
      (els) => els.map((e) => e.textContent.trim())
    );
    assert.ok(domRegistrables.length > 0, "should have visible findings");

    // Trigger CSV download
    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 15_000 }),
      page.click("#export-csv-btn"),
    ]);

    const downloadPath = await download.path();
    const csvText = await readFile(downloadPath, "utf8");
    const rows = parseCsv(csvText);

    // Extract registrables from CSV (tab-prefixed ones need trimming)
    const csvRegistrables = rows.map((r) => r.registrable.replace(/^\t/, ""));

    // Every DOM registrable should appear in CSV
    for (const reg of domRegistrables) {
      assert.ok(
        csvRegistrables.includes(reg),
        `DOM registrable "${reg}" missing from CSV`
      );
    }
    assert.equal(
      csvRegistrables.length, domRegistrables.length,
      "CSV row count matches DOM count"
    );

    await page.screenshot({
      path: join(EVIDENCE_DIR, "export-scope-matches.png"),
      fullPage: false,
    });
  } finally {
    await context?.close().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Test 3 — copy-denied
// ---------------------------------------------------------------------------
test("copy-denied: clipboard failure shows inline error, not silent success", async () => {
  await ensureEvidence();

  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();
    // Use mobile viewport so cards render (not the desktop table)
    await page.setViewportSize({ width: 375, height: 812 });

    // Override clipboard API to always reject BEFORE page scripts run
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: () => Promise.reject(new Error("Clipboard denied")),
        },
      });
    });

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(fixture.url);
    await initialFetch;

    // Switch to all findings mode
    const allFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allFetch;

    // Click first finding card to open dialog
    await page.click(".finding-card");
    await page.waitForSelector("#finding-dialog[open]", { timeout: 8_000 });

    // Click copy button
    await page.click("#copy-triage-btn");

    // Wait for failure feedback
    // NOTE: waitForFunction(fn, arg, options) — pass null as arg.
    await page.waitForFunction(
      () => {
        const btn = document.getElementById("copy-triage-btn");
        return btn && (
          btn.textContent.includes("failed") ||
          btn.textContent.includes("Failed") ||
          btn.textContent.includes("error")
        );
      },
      null,
      { timeout: 8_000 }
    );

    const btnText = await page.locator("#copy-triage-btn").textContent();
    assert.ok(
      btnText.toLowerCase().includes("fail") || btnText.toLowerCase().includes("error"),
      `Expected failure copy on button, got: "${btnText}"`
    );

    await page.screenshot({
      path: join(EVIDENCE_DIR, "copy-denied.png"),
      fullPage: false,
    });
  } finally {
    await context?.close().catch(() => {});
  }
});

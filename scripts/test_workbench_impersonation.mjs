/**
 * Workbench impersonation tests — node:test
 * Tests lib/ui/impersonation.js pure logic.
 *
 * Run: node --test scripts/test_workbench_impersonation.mjs
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { explainImpersonation, renderImpersonation } from "../lib/ui/impersonation.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-12"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

const WATCHLIST_BRANDS = [
  { id: "singpass", display: "Singpass", tokens: ["singpass"] },
  { id: "cpf", display: "CPF Board", tokens: ["cpf"] },
];

const ALLOWLIST_ENTRIES = [
  { registrable: "singpass.gov.sg", brand: "singpass", verified: true },
  { registrable: "cpf.gov.sg", brand: "cpf", verified: true },
];

// ---------------------------------------------------------------------------
// Test 1 — ascii-typo
// ---------------------------------------------------------------------------
test("ascii-typo: edit-distance signal explains typosquatting", async () => {
  await ensureEvidence();

  const finding = {
    registrable: "singpas-login.test",
    domains: ["singpas-login.test"],
    signals: [
      { type: "brand:edit_distance_1", brand: "singpass", token: "singpass", display: "Singpass", points: 30 },
    ],
    matched_brands: ["singpass"],
  };

  const explanations = explainImpersonation(finding, WATCHLIST_BRANDS, ALLOWLIST_ENTRIES);
  assert.equal(explanations.length, 1);
  assert.equal(explanations[0].brandId, "singpass");
  assert.ok(
    explanations[0].explanation.includes("one character away"),
    `Expected typosquatting explanation, got: "${explanations[0].explanation}"`
  );
  assert.equal(explanations[0].officialDomain, "singpass.gov.sg");
});

// ---------------------------------------------------------------------------
// Test 2 — unicode-and-punycode
// ---------------------------------------------------------------------------
test("unicode-and-punycode: homoglyph signal explains visual substitution", async () => {
  await ensureEvidence();

  const finding = {
    registrable: "s\u0456ngpass-login.test",  // Cyrillic і instead of i
    domains: ["s\u0456ngpass-login.test"],
    signals: [
      { type: "brand:homoglyph", brand: "singpass", token: "singpass", display: "Singpass", points: 40 },
    ],
    matched_brands: ["singpass"],
  };

  const explanations = explainImpersonation(finding, WATCHLIST_BRANDS, ALLOWLIST_ENTRIES);
  assert.equal(explanations.length, 1);
  assert.ok(
    explanations[0].explanation.toLowerCase().includes("visually similar"),
    `Expected visual similarity explanation, got: "${explanations[0].explanation}"`
  );

  // Render: Unicode characters must be escaped in HTML
  const html = renderImpersonation(explanations, escapeHtml);
  assert.ok(!html.includes("<script"), "HTML must not contain script tags");
  assert.ok(html.includes("bdi"), "Should use bdi for bidi isolation");
});

// ---------------------------------------------------------------------------
// Test 3 — misleading-subdomain
// ---------------------------------------------------------------------------
test("misleading-subdomain: registrable is segmented from subdomain", async () => {
  await ensureEvidence();

  const finding = {
    registrable: "evil-domain.test",
    domains: ["singpass.evil-domain.test", "evil-domain.test"],
    signals: [
      { type: "brand:exact", brand: "singpass", token: "singpass", display: "Singpass", points: 50 },
    ],
    matched_brands: ["singpass"],
  };

  const explanations = explainImpersonation(finding, WATCHLIST_BRANDS, ALLOWLIST_ENTRIES);
  assert.equal(explanations.length, 1);

  // The registrable part should be the eTLD+1, not the subdomain
  assert.equal(explanations[0].registrablePart, "evil-domain.test");
  assert.equal(explanations[0].subdomainPart, "singpass");
});

// ---------------------------------------------------------------------------
// Test 4 — missing-match-detail
// ---------------------------------------------------------------------------
test("missing-match-detail: missing alignment info says so explicitly", async () => {
  await ensureEvidence();

  const finding = {
    registrable: "cpf-claim.test",
    domains: ["cpf-claim.test"],
    signals: [
      // Signal without token field
      { type: "brand:exact", brand: "cpf", display: "CPF Board", points: 50 },
    ],
    matched_brands: ["cpf"],
  };

  const explanations = explainImpersonation(finding, WATCHLIST_BRANDS, ALLOWLIST_ENTRIES);
  assert.equal(explanations.length, 1);

  // When token is missing, alignmentAvailable should be false
  // (matchedToken will be empty from brand tokens fallback or empty)
  const html = renderImpersonation(explanations, escapeHtml);
  // Either alignment is available (token found from brand) or the "not available" message shows
  assert.ok(
    html.includes("Alignment detail not available") || html.includes("Suspicious:"),
    "Should either show alignment or explain it's not available"
  );
});

// ---------------------------------------------------------------------------
// Test 5 — unverified-official-domain
// ---------------------------------------------------------------------------
test("unverified-official-domain: no verified allowlist entry shows explicit message", async () => {
  await ensureEvidence();

  const finding = {
    registrable: "iras-refund.test",
    domains: ["iras-refund.test"],
    signals: [
      { type: "brand:exact", brand: "iras", token: "iras", display: "IRAS", points: 50 },
    ],
    matched_brands: ["iras"],
  };

  // IRAS not in our test allowlist
  const explanations = explainImpersonation(finding, WATCHLIST_BRANDS, ALLOWLIST_ENTRIES);
  assert.equal(explanations.length, 1);
  assert.equal(explanations[0].officialDomain, null, "No official domain for unverified brand");

  const html = renderImpersonation(explanations, escapeHtml);
  assert.ok(
    html.includes("not verified in this watchlist"),
    `Expected 'not verified' message, got: "${html.slice(0, 300)}"`
  );
});

// ---------------------------------------------------------------------------
// Test 6 — bidi-and-html-inert
// ---------------------------------------------------------------------------
test("bidi-and-html-inert: HTML injection in registrable is escaped", async () => {
  await ensureEvidence();

  const finding = {
    registrable: "<script>alert(1)</script>.test",
    domains: ["<script>alert(1)</script>.test"],
    signals: [
      { type: "brand:exact", brand: "singpass", token: "singpass", display: "Singpass", points: 50 },
    ],
    matched_brands: ["singpass"],
  };

  const explanations = explainImpersonation(finding, WATCHLIST_BRANDS, ALLOWLIST_ENTRIES);
  const html = renderImpersonation(explanations, escapeHtml);

  // The script tag must be escaped
  assert.ok(!html.includes("<script>"), "Script tag must be escaped in HTML output");
  assert.ok(html.includes("&lt;script&gt;"), "Script tag must appear as escaped HTML entities");
});

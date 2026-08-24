import assert from "node:assert/strict";
import { generateDailyDigest, formatDigestMarkdown } from "../lib/reports/daily-digest.js";

const mockFindings = [
  {
    registrable: "dbs-login.top",
    score: 85,
    severity: "high",
    matched_brands: ["DBS Bank"],
    matched_schemes: [],
    issuer: "Let'\''s Encrypt"
  },
  {
    registrable: "ocbc-verify.xyz",
    score: 95,
    severity: "critical",
    matched_brands: ["OCBC Bank"],
    matched_schemes: ["CDC Vouchers"],
    issuer: "ZeroSSL"
  },
  {
    registrable: "benign-sample.com",
    score: 20,
    severity: "low",
    matched_brands: [],
    matched_schemes: [],
    issuer: "DigiCert"
  }
];

const mockSourceRuns = [
  { scanned_entries: 500, ok: true },
  { scanned_entries: 350, ok: true },
  { scanned_entries: 0, ok: false }
];

// 1. Test generateDailyDigest calculations
const digest = generateDailyDigest({
  findings: mockFindings,
  sourceRuns: mockSourceRuns,
  observedDate: new Date("2026-08-24T00:00:00Z")
});

assert.equal(digest.date, "2026-08-24", "Digest date matches");
assert.equal(digest.total_findings, 3, "Counts total findings");
assert.equal(digest.critical_count, 1, "Counts critical findings");
assert.equal(digest.high_count, 1, "Counts high findings");
assert.equal(digest.low_count, 1, "Counts low findings");
assert.equal(digest.alert_count, 2, "Actionable alerts (>= 70) count is 2");
assert.equal(digest.sources_scanned, 850, "Aggregates scanned certs across runs");
assert.equal(digest.sources_ok, 2, "Counts successful source runs");
assert.equal(digest.top_brands["DBS Bank"], 1, "Tracks DBS Bank");
assert.equal(digest.top_brands["CDC Vouchers"], 1, "Tracks CDC Vouchers scheme");
assert.equal(digest.top_tlds["top"], 1, "Tracks .top TLD");

// 2. Test formatDigestMarkdown output
const markdown = formatDigestMarkdown(digest);
assert.ok(markdown.includes("sgCertWatch Daily Security Digest — 2026-08-24"), "Markdown title has date");
assert.ok(markdown.includes("Scanned CT Certificates: 850"), "Markdown shows scanned certs");
assert.ok(markdown.includes("Actionable Alerts (Score >= 70): 2"), "Markdown shows actionable alerts");
assert.ok(markdown.includes("DBS Bank: 1 findings"), "Markdown lists top brands");
assert.ok(markdown.includes(".top: 1"), "Markdown lists top TLDs");

console.log("Daily digest tests passed.");

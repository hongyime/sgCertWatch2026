import assert from "node:assert/strict";
import { loadData } from "../lib/data.js";
import { scoreCertificate } from "../lib/scoring.js";
import { enrichDomain } from "../lib/domain/enrichment.js";
import { dispatchNotifications } from "../lib/notify.js";
import { generateDailyDigest, formatDigestMarkdown } from "../lib/reports/daily-digest.js";

console.log("Starting sgCertWatch End-to-End Pipeline Verification...");

// 1. Data load verification
const data = loadData();
assert.ok(data.watchlist.brands.length >= 70, "Watchlist loaded with >= 70 brands");
assert.ok(data.keywords.keywords.length >= 50, "Keywords loaded with >= 50 keywords");
assert.ok(data.allowlist.entries.length >= 65, "Allowlist loaded with >= 65 entries");
assert.ok(data.schemes.schemes.length >= 10, "Schemes loaded with >= 10 schemes");

// 2. Score simulated suspicious CT log entry
const suspiciousCert = {
  dns_names: ["dbs-secure-login.top", "login.dbs-secure-login.top"],
  issuer: "Let's Encrypt Authority X3",
  not_before: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  entry_type: "x509",
  source: {
    source: "direct_ct",
    log_name: "Let's Encrypt Oak 2026",
    log_operator: "ISRG",
    cert_index: 998877
  }
};

const finding = scoreCertificate(suspiciousCert, data);
assert.ok(finding, "Certificate matches detection rules");
assert.equal(finding.registrable, "dbs-secure-login.top", "Registrable domain extracted");
assert.ok(finding.score >= 70, `Score is high/critical (${finding.score} >= 70)`);
assert.ok(finding.signals.some((s) => s.type.startsWith("brand")), "Brand signal triggered");
assert.ok(finding.signals.some((s) => s.type === "tld_high_risk"), "TLD high risk signal triggered");
assert.ok(finding.signals.some((s) => s.type === "issuer_free_dv"), "Free DV issuer signal triggered");

// 3. Active capture & enrichment probe simulation
const mockFetch = async (url) => {
  if (url.startsWith("https://dbs-secure-login.top")) {
    return {
      status: 200,
      url: "https://dbs-secure-login.top/auth",
      headers: {
        get: (h) => (h.toLowerCase() === "server" ? "nginx" : "text/html")
      },
      text: async () => "<!DOCTYPE html><html><head><title>DBS iBanking Login</title></head><body></body></html>"
    };
  }
  if (url.startsWith("https://rdap.org")) {
    return {
      ok: true,
      json: async () => ({
        events: [{ eventAction: "registration", eventDate: "2026-08-23T00:00:00Z" }],
        status: ["active"],
        entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "NameSilo"]]] }]
      })
    };
  }
  throw new Error("Network error");
};

const enrichment = await enrichDomain(finding.registrable, { timeoutMs: 500, fetch: mockFetch });
assert.equal(enrichment.live, true, "Enrichment confirms domain is live");
assert.equal(enrichment.http.title, "DBS iBanking Login", "Extracted phishing title");
assert.equal(enrichment.rdap.registrar, "NameSilo", "Extracted registrar");

finding.enrichment = enrichment;

// 4. Multi-channel notification dispatch simulation
let notifiedChannels = 0;
const mockNotifyFetch = async (_url) => {
  notifiedChannels += 1;
  return { ok: true };
};

const notifySummary = await dispatchNotifications([finding], {
  env: {
    TELEGRAM_BOT_TOKEN: "mock_token",
    TELEGRAM_CHAT_ID: "mock_chat"
  },
  fetch: mockNotifyFetch,
  skipDedupe: true
});

assert.equal(notifySummary.candidates, 1, "Finding qualified for alert");
assert.equal(notifySummary.telegram, 1, "Dispatched to Telegram");
assert.equal(notifySummary.discord, undefined, "Discord removed per DECISION-01/16R");
assert.equal(notifiedChannels, 1, "Only Telegram HTTP call completed");

// 5. Daily digest reporting simulation
const digest = generateDailyDigest({
  findings: [finding],
  sourceRuns: [{ source: "direct_ct", scanned_entries: 1000, ok: true }],
  observedDate: new Date()
});

assert.equal(digest.total_findings, 1, "Digest includes finding");
assert.equal(digest.alert_count, 1, "Digest counts 1 alert");
assert.equal(digest.top_brands["dbs"] || digest.top_brands["DBS Bank"], 1, "Digest tracks DBS Bank as targeted");

const markdown = formatDigestMarkdown(digest);
assert.ok(markdown.includes("sgCertWatch Daily Security Digest"), "Markdown digest generated");

console.log("End-to-End Pipeline Verification passed completely!");

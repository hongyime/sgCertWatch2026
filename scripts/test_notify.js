import assert from "node:assert/strict";
import {
  shouldAlert,
  formatTelegramMessage,
  sendTelegramAlert,
  selectDedupeEligible,
  dispatchNotifications
} from "../lib/notify.js";

const sampleFinding = {
  id: "test-finding-1",
  registrable: "dbs-security-auth.top",
  score: 85,
  severity: "high",
  observed_at: "2026-08-24T08:00:00Z",
  issuer: "Let's Encrypt",
  domains: ["dbs-security-auth.top", "login.dbs-security-auth.top"],
  matched_brands: ["DBS Bank"],
  matched_schemes: [],
  signals: [
    { type: "brand:exact", points: 50, brand: "dbs", display: "DBS Bank" },
    { type: "tld_high_risk", points: 12, tld: "top" },
    { type: "kw:security", points: 10, token: "security" }
  ]
};

// 1. Threshold check
assert.equal(shouldAlert(sampleFinding, 70), true, "Score 85 qualifies for alert");
assert.equal(shouldAlert({ score: 40 }, 70), false, "Score 40 does not qualify");
assert.equal(shouldAlert({ score: 90, suppressed: true }, 70), false, "Suppressed finding does not alert");

// 2. Telegram formatter defangs hostile indicators
const tgText = formatTelegramMessage(sampleFinding);
assert.ok(tgText.includes("dbs-security-auth[.]top"), "Domain is defanged in Telegram message");
assert.ok(!tgText.includes("dbs-security-auth.top"), "Raw domain must not appear clickable");
assert.ok(tgText.includes("HIGH (85 pts)"), "Severity and score included");
assert.ok(tgText.includes("DBS Bank"), "Brand included");

// 3. Telegram dispatch with mock fetch
let tgCalled = false;
const mockTgFetch = async (url, options) => {
  tgCalled = true;
  assert.ok(url.includes("bot12345/sendMessage"), "Telegram bot endpoint invoked");
  const body = JSON.parse(options.body);
  assert.equal(body.chat_id, "chat987", "Telegram chat_id sent");
  return { ok: true };
};
await sendTelegramAlert(sampleFinding, { botToken: "12345", chatId: "chat987", fetchImpl: mockTgFetch });
assert.equal(tgCalled, true, "Telegram alert sent successfully");

// 4. 72-hour per-registrable dedupe
const alerted = new Set(["dbs-security-auth.top"]);
const eligible = selectDedupeEligible([sampleFinding, { registrable: "fresh-lure.top" }], alerted);
assert.equal(eligible.length, 1, "Already-alerted registrable is deduped within window");
assert.equal(eligible[0].registrable, "fresh-lure.top", "Fresh registrable passes dedupe");
assert.equal(
  selectDedupeEligible([{ registrable: "x.com" }], new Set()).length,
  1,
  "Empty alert log dedupes nothing"
);

// 5. Telegram-only orchestration with dedupe integration
let calls = 0;
const summary = await dispatchNotifications(
  [sampleFinding, { id: "low-1", score: 30, registrable: "low.com" }],
  {
    env: { TELEGRAM_BOT_TOKEN: "tok", TELEGRAM_CHAT_ID: "chat" },
    fetch: async () => { calls += 1; return { ok: true }; },
    skipDedupe: true
  }
);
assert.equal(summary.candidates, 1, "Only score >= 70 candidate considered");
assert.equal(summary.telegram, 1, "Dispatched to Telegram once");
assert.equal(summary.discord, undefined, "Discord channel removed per DECISION-01/16R");
assert.equal(summary.webhook, undefined, "Generic webhook channel removed per DECISION-01/16R");

console.log("Notification dispatcher tests passed.");

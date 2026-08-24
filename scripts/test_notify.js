import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  shouldAlert,
  formatTelegramMessage,
  formatDiscordEmbed,
  sendTelegramAlert,
  sendDiscordAlert,
  sendGenericWebhook,
  dispatchNotifications
} from "../lib/notify.js";

const sampleFinding = {
  id: "test-finding-1",
  registrable: "dbs-security-auth.top",
  score: 85,
  severity: "high",
  observed_at: "2026-08-24T08:00:00Z",
  issuer: "Let'\''s Encrypt",
  domains: ["dbs-security-auth.top", "login.dbs-security-auth.top"],
  matched_brands: ["DBS Bank"],
  matched_schemes: [],
  signals: [
    { type: "brand:exact", points: 50, brand: "dbs", display: "DBS Bank" },
    { type: "tld_high_risk", points: 12, tld: "top" },
    { type: "kw:security", points: 10, token: "security" }
  ]
};

// 1. Test threshold check
assert.equal(shouldAlert(sampleFinding, 70), true, "Score 85 qualifies for alert");
assert.equal(shouldAlert({ score: 40 }, 70), false, "Score 40 does not qualify");
assert.equal(shouldAlert({ score: 90, suppressed: true }, 70), false, "Suppressed finding does not alert");

// 2. Test Telegram formatter
const tgText = formatTelegramMessage(sampleFinding);
assert.ok(tgText.includes("dbs-security-auth.top"), "Telegram message includes domain");
assert.ok(tgText.includes("HIGH (85 pts)"), "Telegram message includes severity & score");
assert.ok(tgText.includes("DBS Bank"), "Telegram message includes brand");

// 3. Test Discord embed formatter
const discordPayload = formatDiscordEmbed(sampleFinding);
assert.ok(discordPayload.embeds?.[0], "Discord payload has embed");
assert.equal(discordPayload.embeds[0].color, 0xf59e0b, "High severity gets orange/amber color");
assert.ok(discordPayload.embeds[0].title.includes("dbs-security-auth.top"), "Embed title includes domain");

// 4. Test Telegram alert dispatch with mock fetch
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

// 5. Test Discord webhook dispatch with mock fetch
let discordCalled = false;
const mockDiscordFetch = async (url, options) => {
  discordCalled = true;
  assert.equal(url, "https://discord.com/api/webhooks/mock/123", "Discord URL called");
  const body = JSON.parse(options.body);
  assert.ok(body.embeds?.length > 0, "Discord embed body present");
  return { ok: true };
};
await sendDiscordAlert(sampleFinding, { webhookUrl: "https://discord.com/api/webhooks/mock/123", fetchImpl: mockDiscordFetch });
assert.equal(discordCalled, true, "Discord alert sent successfully");

// 6. Test Generic webhook dispatch with HMAC verification
let webhookCalled = false;
const mockSecret = "super-secret-key-123";
const mockGenericFetch = async (url, options) => {
  webhookCalled = true;
  assert.equal(url, "https://example.com/alerts/webhook");
  const signature = options.headers["X-Signature-256"];
  const computed = crypto.createHmac("sha256", mockSecret).update(options.body).digest("hex");
  assert.equal(signature, computed, "HMAC-SHA256 signature verified");
  return { ok: true };
};
await sendGenericWebhook(sampleFinding, {
  webhookUrl: "https://example.com/alerts/webhook",
  secret: mockSecret,
  fetchImpl: mockGenericFetch
});
assert.equal(webhookCalled, true, "Generic webhook with HMAC sent successfully");

// 7. Test dispatchNotifications multi-channel orchestration
const dispatchFetch = async () => ({ ok: true });
const summary = await dispatchNotifications([sampleFinding, { id: "low-1", score: 30, registrable: "low.com" }], {
  env: {
    TELEGRAM_BOT_TOKEN: "tok",
    TELEGRAM_CHAT_ID: "chat",
    DISCORD_WEBHOOK_URL: "https://discord.com/mock",
    ALERT_WEBHOOK_URL: "https://example.com/webhook",
    ALERT_WEBHOOK_SECRET: "sec"
  },
  fetch: dispatchFetch
});
assert.equal(summary.candidates, 1, "Only score >= 70 candidate considered");
assert.equal(summary.telegram, 1, "Dispatched to Telegram");
assert.equal(summary.discord, 1, "Dispatched to Discord");
assert.equal(summary.webhook, 1, "Dispatched to Generic Webhook");

console.log("Notification dispatcher tests passed.");

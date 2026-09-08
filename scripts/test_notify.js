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
  return Response.json({ ok: true, result: { message_id: 42, chat: { id: 987 } } });
};
const receipt = await sendTelegramAlert(sampleFinding, { botToken: "12345", chatId: "chat987", fetchImpl: mockTgFetch });
assert.deepEqual(receipt, { sent: true, messageId: 42 });
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
    fetch: async () => { calls += 1; return Response.json({ ok: true, result: { message_id: 1, chat: { id: 1 } } }); },
    skipDedupe: true
  }
);
assert.equal(summary.candidates, 1, "Only score >= 70 candidate considered");
assert.equal(summary.telegram, 1, "Dispatched to Telegram once");
assert.equal(summary.discord, undefined, "Discord channel removed per DECISION-01/16R");
assert.equal(summary.webhook, undefined, "Generic webhook channel removed per DECISION-01/16R");
assert.deepEqual(summary.delivered_registrables, [sampleFinding.registrable]);

// A provider outage stops the batch and never marks unsent alerts delivered.
let failedCalls = 0;
const failed = await dispatchNotifications([sampleFinding, sampleFinding], {
  env: { TELEGRAM_BOT_TOKEN: "tok", TELEGRAM_CHAT_ID: "chat" },
  fetch: async (_url, options) => {
    assert.ok(options.signal instanceof AbortSignal);
    failedCalls++;
    return { ok: false, status: 503 };
  }
});
assert.equal(failedCalls, 1);
assert.equal(failed.telegram, 0);
assert.deepEqual(failed.delivered_registrables, []);
assert.equal(failed.deferred, 2);
const capped = await dispatchNotifications(Array.from({ length: 30 }, () => sampleFinding), {
  env: { TELEGRAM_BOT_TOKEN: "tok", TELEGRAM_CHAT_ID: "chat" },
  fetch: async () => Response.json({ ok: true, result: { message_id: 1, chat: { id: 1 } } })
});
assert.equal(capped.telegram, 20);
assert.equal(capped.deferred, 10);

const deliveryOptions = { botToken: "12345:secret-token", chatId: "987" };
for (const body of [{ ok: false }, { ok: true }, { ok: true, result: { message_id: 0, chat: { id: 987 } } },
  { ok: true, result: { message_id: 42 } }, { ok: true, result: { message_id: 42, chat: { id: 123 } } }]) {
  await assert.rejects(sendTelegramAlert(sampleFinding, {
    ...deliveryOptions, fetchImpl: async () => Response.json(body)
  }), /telegram_(api|invalid_receipt)/);
}
await assert.rejects(sendTelegramAlert(sampleFinding, {
  ...deliveryOptions, fetchImpl: async () => new Response("not json")
}), /telegram_invalid_json/);
await assert.rejects(sendTelegramAlert(sampleFinding, {
  ...deliveryOptions, fetchImpl: async url => { throw new Error(`request ${url} failed`); }
}), error => error.code === "telegram_network" && !error.stack.includes(deliveryOptions.botToken));
for (const httpStatus of [200, 429]) {
  await assert.rejects(sendTelegramAlert(sampleFinding, {
    ...deliveryOptions, fetchImpl: async () => Response.json({
      ok: false, error_code: 429, description: deliveryOptions.botToken, parameters: { retry_after: 90 }
    }, { status: httpStatus, headers: { "Retry-After": "120" } })
  }), error => error.rateLimited && error.retryAfterSeconds === 120 && !error.message.includes(deliveryOptions.botToken));
}
for (const bodyMode of ["malformed", "stalled", "aborted"]) {
  await assert.rejects(sendTelegramAlert(sampleFinding, {
    ...deliveryOptions, timeoutMs: 20,
    fetchImpl: async (_url, { signal }) => ({
      ok: false, status: 429, headers: new Headers({ "Retry-After": "7200" }),
      json: bodyMode === "malformed" ? async () => { throw new SyntaxError(deliveryOptions.botToken); }
        : () => new Promise((_resolve, reject) => {
          if (bodyMode === "aborted") signal.addEventListener("abort", () => reject(new Error(deliveryOptions.botToken)), { once: true });
        })
    })
  }), error => error.code === "telegram_http_429" && error.rateLimited && error.retryAfterSeconds === 7200
    && !error.stack.includes(deliveryOptions.botToken));
}
await assert.rejects(sendTelegramAlert(sampleFinding, {
  ...deliveryOptions, timeoutMs: 20,
  fetchImpl: async () => ({ ok: false, status: 429,
    headers: new Headers({ "Retry-After": new Date(Date.now() + 7200000).toUTCString() }),
    json: () => new Promise(() => {}) })
}), error => error.rateLimited && error.retryAfterSeconds >= 7190 && error.retryAfterSeconds <= 7200);
await assert.rejects(sendTelegramAlert(sampleFinding, {
  ...deliveryOptions, fetchImpl: async () => Response.json({ ok: false, error_code: 429,
    parameters: { retry_after: 7200 } }, { status: 429, headers: { "Retry-After": "120" } })
}), error => error.rateLimited && error.retryAfterSeconds === 7200);
await assert.rejects(sendTelegramAlert(sampleFinding, {
  ...deliveryOptions, timeoutMs: 20,
  fetchImpl: async () => ({ ok: true, json: () => new Promise(() => {}) })
}), /telegram_timeout/);
await assert.rejects(sendTelegramAlert(sampleFinding, {
  ...deliveryOptions, timeoutMs: 20, fetchImpl: () => new Promise(() => {})
}), /telegram_timeout/);
assert.deepEqual(await sendTelegramAlert(sampleFinding, { botToken: "", chatId: "" }), {
  sent: false, reason: "unconfigured"
});

console.log("Notification dispatcher tests passed.");

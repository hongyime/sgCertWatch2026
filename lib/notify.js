import crypto from "node:crypto";
import { defangHost } from "./defang.js";
const ALERT_MIN_SCORE = 70;

export function shouldAlert(finding, minScore = ALERT_MIN_SCORE) {
  if (!finding || finding.suppressed) return false;
  return (finding.score || 0) >= minScore;
}

export function formatTelegramMessage(finding) {
  const brandList = [...(finding.matched_brands || []), ...(finding.matched_schemes || [])].join(", ") || "Suspect Lure";
  const signals = (finding.signals || [])
    .slice(0, 5)
    .map((s) => `  • ${s.type || "signal"} (+${s.points || 0})`)
    .join("\n");

  return [
    `🚨 *sgCertWatch Alert: Potential Scam Domain*`,
    ``,
    `*Domain:* \`${defangHost(finding.registrable)}\``,
    `*Severity:* ${finding.severity.toUpperCase()} (${finding.score} pts)`,
    `*Matched:* ${brandList}`,
    `*Issuer:* ${defangHost(finding.issuer || "Unknown CA")}`,
    `*Observed:* ${finding.observed_at}`,
    ``,
    `*Top Signals:*`,
    signals || "  • None recorded",
    ``,
    `🔍 View on sgCertWatch: hXXps://sgcertwatch[.]vercel[.]app`
  ].join("\n");
}

export async function sendTelegramAlert(finding, { botToken, chatId, fetchImpl = globalThis.fetch, timeoutMs = 8000 }) {
  if (!botToken || !chatId || !fetchImpl) return { sent: false, reason: "unconfigured" };
  const text = formatTelegramMessage(finding);
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

  const resp = await fetchImpl(url, {
    signal: AbortSignal.timeout(timeoutMs),
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      disable_web_page_preview: true
    })
  });

  if (!resp.ok) {
    void resp.body?.cancel().catch(() => {});
    throw new Error(`Telegram API HTTP ${resp.status}`);
  }
  void resp.body?.cancel().catch(() => {});
  return { sent: true };
}

export function selectDedupeEligible(findings, alertedWithin72h = new Set()) {
  return (findings || []).filter((f) => f?.registrable && !alertedWithin72h.has(f.registrable));
}

export async function dispatchNotifications(findings, options = {}) {
  const env = options.env || process.env;
  const fetchImpl = options.fetch || globalThis.fetch;
  const minScore = options.minScore || ALERT_MIN_SCORE;
  const deduped = options.skipDedupe
    ? (findings || [])
    : selectDedupeEligible(findings, options.alertedWithin72h || new Set());

  const alertCandidates = deduped.filter((f) => shouldAlert(f, minScore));
  const suppressedByDedupe = (findings || []).length - alertCandidates.length;
  const summary = {
    candidates: alertCandidates.length,
    suppressed_by_dedupe: suppressedByDedupe,
    telegram: 0,
    delivered_registrables: [],
    deferred: 0,
    errors: []
  };

  if (!alertCandidates.length) return summary;

  const telegramToken = env.TELEGRAM_BOT_TOKEN;
  const telegramChatId = env.TELEGRAM_CHAT_ID;
  if (!telegramToken || !telegramChatId) return summary;
  const deadline = Date.now() + 30000;

  for (const finding of alertCandidates.slice(0, 20)) {
    if (Date.now() >= deadline) break;
    if (telegramToken && telegramChatId) {
      try {
        await sendTelegramAlert(finding, { botToken: telegramToken, chatId: telegramChatId, fetchImpl,
          timeoutMs: Math.max(1, Math.min(8000, deadline - Date.now())) });
        summary.telegram += 1;
        summary.delivered_registrables.push(finding.registrable);
      } catch (err) {
        summary.errors.push({ channel: "telegram", domain: finding.registrable, error: err.message });
        break;
      }
    }
  }

  summary.deferred = alertCandidates.length - summary.telegram;
  return summary;
}

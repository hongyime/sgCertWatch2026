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
    `*Severity:* ${String(finding.severity || "high").toUpperCase()} (${finding.score} pts)`,
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

export class TelegramDeliveryError extends Error {
  constructor(code, { retryAfterSeconds = 0, rateLimited = false } = {}) {
    super(code);
    this.name = "TelegramDeliveryError";
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
    this.rateLimited = rateLimited;
  }
}

export async function sendTelegramAlert(finding, { botToken, chatId, fetchImpl = globalThis.fetch, timeoutMs = 8000 }) {
  if (!botToken || !chatId || !fetchImpl) return { sent: false, reason: "unconfigured" };
  const text = formatTelegramMessage(finding);
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

  const controller = new AbortController();
  let timer;
  let httpFailure;
  // Race the entire exchange, including JSON: custom transports may ignore abort.
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(httpFailure || new TelegramDeliveryError("telegram_timeout"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([timeout, (async () => {
      const resp = await fetchImpl(url, {
        signal: controller.signal,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Plain text prevents certificate-controlled Markdown from breaking sends.
        body: JSON.stringify({ chat_id: chatId, text: text.slice(0, 4000), disable_web_page_preview: true })
      });
      const status = Number.isInteger(resp.status) && resp.status >= 100 && resp.status <= 599 ? resp.status : 500;
      const header = resp.headers?.get?.("retry-after");
      const headerSeconds = header && /^\d+(\.\d+)?$/.test(header) ? Number(header)
        : header ? Math.max(0, (Date.parse(header) - Date.now()) / 1000) : 0;
      // Preserve observed backoff even if the error body stalls or cannot be parsed.
      if (!resp.ok) httpFailure = new TelegramDeliveryError(`telegram_http_${status}`, {
        retryAfterSeconds: Math.ceil(Number.isFinite(headerSeconds) ? headerSeconds : 0), rateLimited: status === 429
      });
      let body;
      try { body = await resp.json(); } catch {
        if (resp.ok) throw new TelegramDeliveryError("telegram_invalid_json");
      }
      const apiCode = Number.isInteger(body?.error_code) && body.error_code >= 100 && body.error_code <= 599
        ? body.error_code : status;
      if (!resp.ok || body?.ok !== true) {
        const jsonSeconds = Number(body?.parameters?.retry_after);
        const retryAfterSeconds = Math.ceil(Math.max(
          Number.isFinite(headerSeconds) ? headerSeconds : 0,
          Number.isFinite(jsonSeconds) && jsonSeconds > 0 ? jsonSeconds : 0));
        throw new TelegramDeliveryError(`telegram_${resp.ok ? "api" : "http"}_${resp.ok ? apiCode : status}`, {
          retryAfterSeconds, rateLimited: status === 429 || apiCode === 429
        });
      }
      const messageId = body.result?.message_id;
      const receiptChatId = body.result?.chat?.id;
      if (!Number.isSafeInteger(messageId) || messageId <= 0 || !Number.isSafeInteger(receiptChatId) || receiptChatId === 0
        || (/^-?\d+$/.test(String(chatId)) && String(receiptChatId) !== String(chatId))) {
        throw new TelegramDeliveryError("telegram_invalid_receipt");
      }
      return { sent: true, messageId };
    })()]);
  } catch (error) {
    // Fetch exceptions can contain the request URL (and bot token). Never forward them.
    throw error instanceof TelegramDeliveryError ? error : httpFailure || new TelegramDeliveryError("telegram_network");
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
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

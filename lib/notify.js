import crypto from "node:crypto";

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
    `*Domain:* \`${finding.registrable}\``,
    `*Severity:* ${finding.severity.toUpperCase()} (${finding.score} pts)`,
    `*Matched:* ${brandList}`,
    `*Issuer:* ${finding.issuer || "Unknown CA"}`,
    `*Observed:* ${finding.observed_at}`,
    ``,
    `*Top Signals:*`,
    signals || "  • None recorded",
    ``,
    `🔍 [View on sgCertWatch](https://sgcertwatch.vercel.app)`
  ].join("\n");
}

export function formatDiscordEmbed(finding) {
  const colorMap = {
    critical: 0xe02424,
    high: 0xf59e0b,
    medium: 0x3b82f6,
    low: 0x6b7280
  };

  const brandList = [...(finding.matched_brands || []), ...(finding.matched_schemes || [])].join(", ") || "Suspect Lure";
  const signals = (finding.signals || [])
    .slice(0, 5)
    .map((s) => `• \`${s.type}\` (+${s.points || 0})`)
    .join("\n");

  return {
    embeds: [
      {
        title: `🚨 sgCertWatch: ${finding.registrable}`,
        description: `Potential Singapore scam domain detected in Certificate Transparency logs.`,
        url: "https://sgcertwatch.vercel.app",
        color: colorMap[finding.severity] || 0xe02424,
        fields: [
          { name: "Score", value: `${finding.score} (${finding.severity.toUpperCase()})`, inline: true },
          { name: "Target", value: brandList, inline: true },
          { name: "Issuer", value: finding.issuer || "Unknown CA", inline: true },
          { name: "Key Signals", value: signals || "None recorded" },
          { name: "Observed At", value: finding.observed_at || new Date().toISOString() }
        ],
        footer: {
          text: "sgCertWatch early warning engine"
        },
        timestamp: new Date().toISOString()
      }
    ]
  };
}

export async function sendTelegramAlert(finding, { botToken, chatId, fetchImpl = globalThis.fetch }) {
  if (!botToken || !chatId || !fetchImpl) return { sent: false, reason: "unconfigured" };
  const text = formatTelegramMessage(finding);
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

  const resp = await fetchImpl(url, {
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
    const errText = await resp.text().catch(() => "");
    throw new Error(`Telegram API HTTP ${resp.status}: ${errText}`);
  }
  return { sent: true };
}

export async function sendDiscordAlert(finding, { webhookUrl, fetchImpl = globalThis.fetch }) {
  if (!webhookUrl || !fetchImpl) return { sent: false, reason: "unconfigured" };
  const payload = formatDiscordEmbed(finding);

  const resp = await fetchImpl(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => "");
    throw new Error(`Discord Webhook HTTP ${resp.status}: ${errText}`);
  }
  return { sent: true };
}

export async function sendGenericWebhook(finding, { webhookUrl, secret, fetchImpl = globalThis.fetch }) {
  if (!webhookUrl || !fetchImpl) return { sent: false, reason: "unconfigured" };
  const body = JSON.stringify({
    event: "finding.alert",
    timestamp: new Date().toISOString(),
    finding
  });

  const headers = {
    "Content-Type": "application/json",
    "User-Agent": "sgCertWatch-Notifier/2.0"
  };

  if (secret) {
    const signature = crypto.createHmac("sha256", secret).update(body).digest("hex");
    headers["X-Signature-256"] = signature;
  }

  const resp = await fetchImpl(webhookUrl, {
    method: "POST",
    headers,
    body
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => "");
    throw new Error(`Generic Webhook HTTP ${resp.status}: ${errText}`);
  }
  return { sent: true };
}

export async function dispatchNotifications(findings, options = {}) {
  const env = options.env || process.env;
  const fetchImpl = options.fetch || globalThis.fetch;
  const minScore = options.minScore || ALERT_MIN_SCORE;

  const alertCandidates = (findings || []).filter((f) => shouldAlert(f, minScore));
  const summary = {
    candidates: alertCandidates.length,
    telegram: 0,
    discord: 0,
    webhook: 0,
    errors: []
  };

  if (!alertCandidates.length) return summary;

  const telegramToken = env.TELEGRAM_BOT_TOKEN;
  const telegramChatId = env.TELEGRAM_CHAT_ID;
  const discordWebhook = env.DISCORD_WEBHOOK_URL;
  const genericWebhook = env.ALERT_WEBHOOK_URL;
  const webhookSecret = env.ALERT_WEBHOOK_SECRET;

  for (const finding of alertCandidates) {
    if (telegramToken && telegramChatId) {
      try {
        await sendTelegramAlert(finding, { botToken: telegramToken, chatId: telegramChatId, fetchImpl });
        summary.telegram += 1;
      } catch (err) {
        summary.errors.push({ channel: "telegram", domain: finding.registrable, error: err.message });
      }
    }

    if (discordWebhook) {
      try {
        await sendDiscordAlert(finding, { webhookUrl: discordWebhook, fetchImpl });
        summary.discord += 1;
      } catch (err) {
        summary.errors.push({ channel: "discord", domain: finding.registrable, error: err.message });
      }
    }

    if (genericWebhook) {
      try {
        await sendGenericWebhook(finding, { webhookUrl: genericWebhook, secret: webhookSecret, fetchImpl });
        summary.webhook += 1;
      } catch (err) {
        summary.errors.push({ channel: "webhook", domain: finding.registrable, error: err.message });
      }
    }
  }

  return summary;
}

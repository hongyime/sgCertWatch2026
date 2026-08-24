import { checkBearer } from "../../lib/auth.js";
import { listFindings, listSourceRuns, setState, getState } from "../../lib/supabase.js";
import { generateDailyDigest, formatDigestMarkdown } from "../../lib/reports/daily-digest.js";
import { sendTelegramAlert, sendDiscordAlert, sendGenericWebhook } from "../../lib/notify.js";

export default async function handler(request, response) {
  if (request.method !== "POST" && request.method !== "GET") {
    response.setHeader("Allow", "POST, GET");
    return response.status(405).json({ error: "method_not_allowed" });
  }

  const auth = checkBearer(request, process.env.CRON_SECRET);
  if (!auth.ok) {
    return response.status(auth.reason === "server_misconfigured" ? 500 : 401).json({ error: "unauthorized" });
  }

  try {
    const findings = await listFindings(200);
    const sourceRuns = await listSourceRuns(100);

    const digest = generateDailyDigest({ findings, sourceRuns, observedDate: new Date() });
    const markdown = formatDigestMarkdown(digest);

    // Persist digest to state
    await setState(`daily_digest_${digest.date}`, { digest, generated_at: new Date().toISOString() });

    // Broadcast digest if webhook/telegram configured
    const env = process.env;
    const summary = { telegram: false, discord: false, webhook: false };

    if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
      try {
        await sendTelegramAlert(
          {
            registrable: `Daily Security Digest (${digest.date})`,
            score: 100,
            severity: "critical",
            observed_at: new Date().toISOString(),
            issuer: "sgCertWatch Monitor",
            signals: [],
            matched_brands: []
          },
          {
            botToken: env.TELEGRAM_BOT_TOKEN,
            chatId: env.TELEGRAM_CHAT_ID,
            fetchImpl: globalThis.fetch
          }
        );
        summary.telegram = true;
      } catch {}
    }

    response.status(200).json({
      ok: true,
      digest,
      markdown,
      dispatched: summary
    });
  } catch (error) {
    response.status(500).json({ error: "daily_digest_failed", message: error.message });
  }
}

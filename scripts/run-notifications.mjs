import { pathToFileURL } from "node:url";
import { drainNotificationOutbox, retryDeadNotifications, publishNotificationOutboxStatus } from "../lib/notification-outbox.js";

// Independent service worker: node scripts/run-notifications.mjs [drain]
// Recover explicit dead letters: node scripts/run-notifications.mjs retry <id> [<id> ...]
// Read IDs through service-role SELECT on notification_outbox where state = 'dead'.
// Configuration: NOTIFICATION_MAX_JOBS (100), NOTIFICATION_MAX_RUN_MS (120000),
// NOTIFICATION_LEASE_SECONDS (60), NOTIFICATION_SPACING_MS (1100),
// NOTIFICATION_BACKOFF_BASE_SECONDS (30), NOTIFICATION_BACKOFF_MAX_SECONDS (21600),
// NOTIFICATION_MAX_ATTEMPTS (8). Telegram Retry-After overrides the backoff cap.
// NOTIFICATIONS_ENABLED=true by default; false disables enqueue/drain without deleting
// any jobs. Parent may pass enabled:false to enqueue until a channel is provisioned.
// Unconfigured Telegram also leaves jobs intact; SQL bounds unfinished jobs at 10,000.
export async function runNotifications(args = process.argv.slice(2), options = {}) {
  const [command = "drain", ...ids] = args;
  if (command === "retry") return retryDeadNotifications(ids, options);
  if (command !== "drain" || ids.length) throw new Error("Usage: run-notifications.mjs [drain | retry <id> ...]");
  const startedAt = new Date().toISOString();
  let result;
  try {
    result = await drainNotificationOutbox(options);
  } catch {
    // Only preflight failures throw; the drain preserves progress for in-flight failures.
    result = { state: "failed", claimed: 0, telegram: 0, retried: 0, dead: 0,
      errors: [{ error: "notification_worker_failed" }] };
  }
  // The publisher whitelists the shape; payloads, identifiers, recipients and error strings
  // never enter the public state. Missing config still publishes freshness/counts.
  const status = await publishNotificationOutboxStatus(result, startedAt, options);
  return { ...result, state: status.state, status };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await runNotifications();
    console.log(JSON.stringify(result));
    if (result.errors?.length) process.exitCode = 1;
  } catch {
    console.error("Notification outbox command failed; jobs remain durable. Check service configuration and migration.");
    process.exitCode = 1;
  }
}

import { pathToFileURL } from "node:url";
import { drainNotificationOutbox, retryDeadNotifications, publishNotificationOutboxStatus } from "../lib/notification-outbox.js";

// Export retained only for historical outbox regression tests; the CLI is retired.
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
  console.log(JSON.stringify({ state: "retired", reason: "Notification delivery has been removed" }));
}

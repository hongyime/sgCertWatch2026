import { createHash, randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { configured, serviceHeaders, setState } from "./supabase.js";
import { sendTelegramAlert, shouldAlert, TelegramDeliveryError } from "./notify.js";

// Integration: await enqueueNotificationAlerts(savedFindings, { minScore }) BEFORE
// committing CT cursors. Dispatch independently with drainNotificationOutbox().
// All eligible findings are batched, including when Telegram is unconfigured.
// SQL retains <=10,000 unfinished jobs; full/error responses throw and block cursors.
// Delivery is at least once; a send/ack crash may cause a duplicate after lease expiry.
const SUPABASE_URL = process.env.SUPABASE_URL;
const RPC_TIMEOUT_MS = 10000;

function integer(value, fallback, min, max, name) {
  const parsed = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`Invalid ${name}`);
  return parsed;
}

async function serviceRpc(name, args, { fetchImpl = globalThis.fetch, timeoutMs = RPC_TIMEOUT_MS } = {}) {
  if (!configured("service")) throw new Error("Supabase service credentials are required for notification outbox");
  const headers = serviceHeaders();
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error("Notification outbox RPC timeout")); }, timeoutMs);
      }),
      (async () => {
        const response = await fetchImpl(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
          method: "POST", headers, body: JSON.stringify(args), signal: controller.signal
        });
        if (!response.ok) throw new Error("Notification outbox RPC failed");
        return response.json();
      })()
    ]);
  } catch {
    // Database responses/transport errors can contain credentials or job payloads.
    throw new Error(`Notification outbox ${name} failed`);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

function rpcFor(options) {
  return options.rpc || ((name, args) => serviceRpc(name, args, {
    fetchImpl: options.dbFetch || globalThis.fetch, timeoutMs: options.rpcTimeoutMs ?? RPC_TIMEOUT_MS
  }));
}

function enabledFor(options) {
  const value = options.enabled ?? (options.env || process.env).NOTIFICATIONS_ENABLED ?? true;
  if ([true, "true", "1"].includes(value)) return true;
  if ([false, "false", "0"].includes(value)) return false;
  throw new Error("Invalid notifications enabled flag");
}

export function notificationIdentity(finding) {
  if (typeof finding?.id !== "string" || !finding.id.trim()) throw new Error("Notification requires stable finding.id");
  return createHash("sha256").update(JSON.stringify(["telegram", finding.id])).digest("hex");
}

function notificationJob(finding) {
  const registrable = String(finding.registrable || "").toLowerCase().replace(/\.$/, "");
  if (registrable.length > 253 || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(registrable)) {
    throw new Error("Notification requires a valid registrable");
  }
  const strings = (value) => (Array.isArray(value) ? value : []).slice(0, 20).map(item => String(item).slice(0, 100));
  // Persist only formatting inputs, with bounded size and no runtime configuration.
  const payload = {
    registrable, score: finding.score, severity: String(finding.severity || "high").slice(0, 20),
    issuer: String(finding.issuer || "Unknown CA").slice(0, 300),
    observed_at: String(finding.observed_at || "").slice(0, 40),
    matched_brands: strings(finding.matched_brands), matched_schemes: strings(finding.matched_schemes),
    signals: (Array.isArray(finding.signals) ? finding.signals : []).slice(0, 5).map(signal => ({
      type: String(signal?.type || "signal").slice(0, 100), points: Number(signal?.points) || 0
    }))
  };
  return { id: notificationIdentity(finding), registrable, payload };
}

/** Returns { candidates, queued, deduped }. Partial-batch failure throws; replay is idempotent. */
export async function enqueueNotificationAlerts(findings, options = {}) {
  if (!enabledFor(options)) return { candidates: 0, queued: 0, deduped: 0, state: "disabled" };
  if (!Array.isArray(findings)) throw new Error("Notification findings must be an array");
  const minScore = integer(options.minScore, 70, 0, 1000, "minScore");
  const maxAttempts = integer(options.maxAttempts ?? (options.env || process.env).NOTIFICATION_MAX_ATTEMPTS,
    8, 1, 100, "maxAttempts");
  const jobs = findings.filter(finding => shouldAlert(finding, minScore)).map(notificationJob);
  const result = { candidates: jobs.length, queued: 0, deduped: 0 };
  const rpc = rpcFor(options);
  for (let offset = 0; offset < jobs.length; offset += 200) {
    options.assertOwned?.();
    const batch = jobs.slice(offset, offset + 200);
    const response = await rpc("notification_outbox_enqueue", { p_jobs: batch, p_max_attempts: maxAttempts });
    if (!Number.isInteger(response?.queued) || !Number.isInteger(response?.deduped)
      || response.queued < 0 || response.deduped < 0 || response.queued + response.deduped !== batch.length) {
      throw new Error("Invalid notification enqueue receipt");
    }
    result.queued += response.queued;
    result.deduped += response.deduped;
    options.assertOwned?.();
  }
  return result;
}

/** Claims one job at a time; all deferred work and retry schedules stay in SQL. */
export async function drainNotificationOutbox(options = {}) {
  const env = options.env || process.env;
  const result = { state: "idle", claimed: 0, telegram: 0, retried: 0, dead: 0, errors: [] };
  if (!enabledFor(options)) return { ...result, state: "disabled" };
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return { ...result, state: "unconfigured" };
  const maxJobs = integer(options.maxJobs ?? env.NOTIFICATION_MAX_JOBS, 100, 1, 10000, "maxJobs");
  const maxRunMs = integer(options.maxRunMs ?? env.NOTIFICATION_MAX_RUN_MS, 120000, 1, 600000, "maxRunMs");
  const timeoutMs = integer(options.timeoutMs, 8000, 1, 60000, "timeoutMs");
  const rpcTimeoutMs = integer(options.rpcTimeoutMs, RPC_TIMEOUT_MS, 1, 60000, "rpcTimeoutMs");
  const leaseSeconds = integer(options.leaseSeconds ?? env.NOTIFICATION_LEASE_SECONDS, 60,
    Math.max(15, Math.ceil((timeoutMs + 2 * rpcTimeoutMs + 5000) / 1000)), 3600, "leaseSeconds");
  const spacingMs = integer(options.spacingMs ?? env.NOTIFICATION_SPACING_MS, 1100, 0, 60000, "spacingMs");
  const baseSeconds = integer(options.baseSeconds ?? env.NOTIFICATION_BACKOFF_BASE_SECONDS, 30, 1, 86400, "baseSeconds");
  const maxSeconds = integer(options.maxSeconds ?? env.NOTIFICATION_BACKOFF_MAX_SECONDS, 21600,
    baseSeconds, 604800, "maxSeconds");
  const rpc = rpcFor(options);
  const wait = options.sleep || sleep;
  const now = options.now || Date.now;
  const deadline = now() + maxRunMs;
  let emptyClaim = false;
  try {
    while (result.claimed < maxJobs && now() + timeoutMs + 3 * rpcTimeoutMs < deadline) {
      // New token on every claim prevents a previous attempt from acking a reclaimed job.
      const owner = randomUUID();
      const rows = await rpc("notification_outbox_claim", {
        p_owner: owner, p_lease_seconds: leaseSeconds, p_spacing_ms: spacingMs
      });
      if (!Array.isArray(rows) || rows.length > 1) throw new Error("Invalid notification claim receipt");
      if (!rows.length) {
        emptyClaim = true;
        break;
      }
      const job = rows[0];
      result.claimed++;
      let receipt;
      try {
        receipt = await sendTelegramAlert(job.payload, {
          botToken: env.TELEGRAM_BOT_TOKEN, chatId: env.TELEGRAM_CHAT_ID,
          fetchImpl: options.fetch || globalThis.fetch, timeoutMs
        });
        if (!receipt.sent) throw new TelegramDeliveryError("telegram_unconfigured");
      } catch (error) {
        const safeError = error instanceof TelegramDeliveryError ? error : new TelegramDeliveryError("telegram_network");
        const state = await rpc("notification_outbox_retry", {
          p_id: job.id, p_owner: owner, p_error: safeError.code,
          p_base_seconds: baseSeconds, p_max_seconds: maxSeconds,
          p_retry_after_seconds: safeError.retryAfterSeconds, p_rate_limited: safeError.rateLimited
        });
        if (!["pending", "dead", "lease_lost"].includes(state)) throw new Error("Invalid notification retry receipt");
        result.errors.push({ id: job.id, error: safeError.code });
        if (state === "dead") result.dead++;
        if (state === "pending") result.retried++;
        if (state === "lease_lost") result.state = "lease_lost";
        if (safeError.rateLimited || state === "lease_lost") break;
        if (spacingMs && now() + spacingMs < deadline) await wait(spacingMs);
        continue;
      }
      // An ack failure is ambiguous. Leave the lease intact; do not immediately resend.
      const acked = await rpc("notification_outbox_ack", { p_id: job.id, p_owner: owner, p_message_id: receipt.messageId });
      if (acked !== true) {
        result.state = "lease_lost";
        result.errors.push({ id: job.id, error: "notification_ack_lease_lost" });
        break;
      }
      result.telegram++;
      if (result.claimed < maxJobs && spacingMs && now() + spacingMs < deadline) await wait(spacingMs);
    }
  } catch {
    // Keep confirmed progress; leave ambiguous claims leased and redact transport errors.
    result.state = result.telegram || result.retried || result.dead ? "partial" : "failed";
    result.errors.push({ error: "notification_worker_failed" });
    return result;
  }
  if (result.state === "idle") {
    result.state = !emptyClaim || result.errors.length ? "partial" : result.claimed ? "drained" : "idle";
  }
  return result;
}

/** Requeue explicit dead-letter IDs. Run the dispatcher separately after this call. */
export async function retryDeadNotifications(ids, options = {}) {
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 200
    || ids.some(id => typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id))) {
    throw new Error("Retry requires 1 to 200 explicit notification IDs");
  }
  const maxAttempts = integer(options.maxAttempts ?? (options.env || process.env).NOTIFICATION_MAX_ATTEMPTS,
    8, 1, 100, "maxAttempts");
  const count = await rpcFor(options)("notification_outbox_retry_dead", { p_ids: ids, p_max_attempts: maxAttempts });
  if (!Number.isInteger(count) || count < 0 || count > ids.length) throw new Error("Invalid notification retry receipt");
  return { retried: count };
}

/** Read-only service RPC; aggregate contains no finding or recipient identifiers. */
export async function getNotificationOutboxStatus(options = {}) {
  return rpcFor(options)("notification_outbox_status", {});
}

/** Publishes a counts-only snapshot through the existing service state writer. */
export async function publishNotificationOutboxStatus(result, startedAt, options = {}) {
  const aggregate = await getNotificationOutboxStatus(options);
  const counts = Object.fromEntries(["pending", "processing", "dead", "sent", "suppressed", "ready"].map(key =>
    [key, integer(aggregate?.[key], undefined, 0, Number.MAX_SAFE_INTEGER, `aggregate ${key}`)]));
  const timestamp = (value) => {
    if (value === null) return null;
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error("Invalid notification status timestamp");
    return new Date(value).toISOString();
  };
  if (!["idle", "drained", "partial", "lease_lost", "unconfigured", "disabled", "failed"].includes(result.state)) {
    throw new Error("Invalid notification status state");
  }
  const checkedAt = timestamp(aggregate.checked_at);
  if (!checkedAt) throw new Error("Missing notification status timestamp");
  const status = {
    schema_version: 1,
    state: result.state === "drained" && counts.pending + counts.processing > 0 ? "partial" : result.state,
    checked_at: checkedAt, started_at: timestamp(startedAt), finished_at: checkedAt,
    queued: counts.pending + counts.processing, ...counts, counts,
    oldest_pending_at: timestamp(aggregate.oldest_pending_at), next_retry_at: timestamp(aggregate.next_retry_at),
    last_sent_at: timestamp(aggregate.last_sent_at),
    run: Object.fromEntries(Object.entries({ claimed: result.claimed || 0, sent: result.telegram || 0,
      retried: result.retried || 0, dead: result.dead || 0, errors: result.errors?.length || 0 }).map(([key, value]) =>
      [key, integer(value, 0, 0, 10000, `run ${key}`)]))
  };
  await (options.setState || setState)("notifications_poll_status", status);
  return status;
}

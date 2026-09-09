import { boundedJson, retryTime, SafeError, safeCode } from "./http.mjs";

export const MINUTE = 60000;
export const TICK_MS = 5 * MINUTE;
export const LEASE_MS = 2 * MINUTE;
export const STATE_KEY = "scheduler-v1";
export const ALERT_MAX_ATTEMPTS = 5;
export const WORKFLOWS = Object.freeze([
  { name: "ingest", file: "ingest.yml", heartbeat: "ct_poll_status", interval: 15 * MINUTE, minimum: 14 * MINUTE, warning: 30 * MINUTE, critical: 60 * MINUTE },
  { name: "intel", file: "intel.yml", heartbeat: "intel_poll_status", interval: 60 * MINUTE, minimum: 55 * MINUTE, warning: 90 * MINUTE, critical: 120 * MINUTE }
]);
const ACTIVE = ["queued", "in_progress", "waiting", "pending", "requested"];
const CONCLUSIONS = ["success", "failure", "cancelled", "skipped", "neutral", "timed_out", "action_required", "stale", "startup_failure"];

function publicKey(key) {
  if (/^sb_publishable_[A-Za-z0-9_-]+$/.test(key || "")) return true;
  try {
    const parts = key.split(".");
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.role === "anon";
  } catch { return false; }
}

/** @param {import('./contracts.d.ts').SchedulerEnv} env */
export function configuration(env) {
  const errors = [];
  if (!/^[A-Za-z0-9-]{1,100}$/.test(env.GITHUB_OWNER || "")) errors.push("invalid_github_owner");
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(env.GITHUB_REPO || "")) errors.push("invalid_github_repo");
  if (!/^[A-Za-z0-9_./-]{1,200}$/.test(env.GITHUB_REF || "") || env.GITHUB_REF.includes("..")) errors.push("invalid_github_ref");
  if (!env.GITHUB_TOKEN) errors.push("missing_github_token");
  if (!env.STATUS_TOKEN || env.STATUS_TOKEN.length < 32) errors.push("invalid_status_token");
  if (env.DISPATCH_ENABLED !== undefined && !["true", "false"].includes(env.DISPATCH_ENABLED)) errors.push("invalid_dispatch_enabled");
  let webhook = false;
  if (env.ALERT_WEBHOOK_URL) {
    try {
      const url = new URL(env.ALERT_WEBHOOK_URL);
      webhook = url.protocol === "https:" && !url.username && !url.password && !url.hash;
    } catch { /* Never echo secret webhook URLs in diagnostics. */ }
    if (!webhook) errors.push("invalid_alert_webhook_url");
  }
  if (env.ALERT_WEBHOOK_SECRET && !env.ALERT_WEBHOOK_URL) errors.push("incomplete_webhook_config");
  const alertChannel = webhook ? "webhook" : "none";
  const monitoringMode = webhook ? "webhook" : "dashboard";
  let heartbeat = Boolean(env.SUPABASE_URL || env.SUPABASE_PUBLISHABLE_KEY);
  if (heartbeat) {
    let validUrl = false;
    try {
      const url = new URL(env.SUPABASE_URL);
      validUrl = url.protocol === "https:" && /^[a-z0-9-]+\.supabase\.co$/.test(url.hostname)
        && !url.username && !url.password && !url.port && url.pathname === "/" && !url.search && !url.hash;
    } catch { /* Configuration errors are deliberately constant strings. */ }
    if (!validUrl || !publicKey(env.SUPABASE_PUBLISHABLE_KEY)) {
      errors.push("invalid_public_heartbeat_config");
      heartbeat = false;
    }
  }
  return { errors, webhook, alertChannel, monitoringMode, heartbeat, heartbeatRequested: Boolean(env.SUPABASE_URL || env.SUPABASE_PUBLISHABLE_KEY),
    enabled: env.DISPATCH_ENABLED !== "false", target: `${env.GITHUB_OWNER}/${env.GITHUB_REPO}@${env.GITHUB_REF}` };
}

function initialState(now, target) {
  return { version: 2, startedAt: now, target, lastTickAt: null, lastCompletedAt: null, lastScheduledAt: null,
    lastBucket: -1, lease: null, metrics: {}, github: { retryAt: 0, failures: 0 },
    webhook: { retryAt: 0, failures: 0 }, heartbeat: { retryAt: 0, failures: 0 },
    workflows: Object.fromEntries(WORKFLOWS.map(w => [w.name, { lastSuccessAt: null, lastObservedAt: null,
      reservation: null, decision: "not_started", metrics: {} }])), incidents: {}, events: [] };
}

function migrateState(state) {
  if (state.version !== 1) return state;
  // Keep the storage key, coordinator lease, scan checkpoints and delivery records.
  // Retirement is not a recovery or a delivery acknowledgement.
  if (state.workflows.notifications || state.incidents.notifications) {
    state.retiredSubjects = { ...state.retiredSubjects, notifications: {
      workflow: state.workflows.notifications || null, incident: state.incidents.notifications || null
    } };
  }
  delete state.workflows.notifications;
  delete state.incidents.notifications;
  delete state.telegram;
  if (state.soak) {
    delete state.soak.workflows.notifications;
    // Preserve earlier evidence for inspection; a new mode needs a new observed window.
    state.soak.active = false;
  }
  state.version = 2;
  return state;
}

function count(metrics, key, amount = 1) { metrics[key] = (metrics[key] || 0) + amount; }
function event(state, now, subject, code) {
  state.events.push({ at: now, subject, code });
  state.events = state.events.slice(-48);
}
function timestamp(value, now) {
  const result = Date.parse(value);
  if (!Number.isFinite(result) || result <= 0 || result > now + MINUTE) throw new SafeError("invalid_run_timestamp");
  return Math.min(result, now);
}
function runSummary(run, now) {
  if (!Number.isSafeInteger(run.id) || run.id <= 0 || ![...ACTIVE, "completed"].includes(run.status)
    || (run.conclusion !== null && !CONCLUSIONS.includes(run.conclusion))) throw new SafeError("invalid_run_response");
  return { id: run.id, status: run.status, conclusion: run.conclusion,
    createdAt: timestamp(run.created_at, now), startedAt: timestamp(run.run_started_at || run.created_at, now),
    updatedAt: timestamp(run.updated_at, now), dispatch: run.event === "workflow_dispatch" };
}
function severity(age, warning = 30 * MINUTE, critical = 60 * MINUTE) { return age >= critical ? 2 : age >= warning ? 1 : 0; }
function age(now, value, fallback) { return Math.max(0, now - (value ?? fallback)); }
function alertRetryAt(notice, now) { return now + Math.min(60 * MINUTE, 5 * MINUTE * 2 ** Math.min(notice.attempts - 1, 4)); }

function observeActual(metrics, start, success, observedAt, baseline) {
  for (const [kind, value] of [["Start", start], ["Success", success]]) {
    if (!value || baseline == null || value < baseline) continue;
    const previous = metrics[`lastActual${kind}At`];
    if (previous && value <= previous) continue;
    if (previous) metrics[`maxActual${kind}GapMs`] = Math.max(metrics[`maxActual${kind}GapMs`] || 0, value - previous);
    else {
      metrics[`firstActual${kind}ObservedAt`] = observedAt;
      metrics[`firstActual${kind}At`] = value;
      metrics[`maxActual${kind}GapMs`] = 0;
    }
    metrics[`lastActual${kind}At`] = value;
    count(metrics, kind === "Start" ? "startsObserved" : "successesObserved");
  }
}

/** @param {import('./contracts.d.ts').TransactionStorage} storage
 * @param {import('./contracts.d.ts').SchedulerEnv} env
 * @param {import('./contracts.d.ts').RuntimeDependencies} deps */
export class SchedulerEngine {
  constructor(storage, env, deps = {}) {
    this.storage = storage;
    this.env = env;
    this.config = configuration(env);
    this.now = deps.now || Date.now;
    this.fetcher = deps.fetch || globalThis.fetch.bind(globalThis);
    this.uuid = deps.uuid || (() => crypto.randomUUID());
    this.timeoutMs = Math.min(deps.timeoutMs || 5000, 5000);
  }

  async change(callback, fence = null) {
    return this.storage.transaction(async txn => {
      const now = this.now();
      const state = await txn.get(STATE_KEY) || initialState(now, this.config.target);
      if (fence && (state.lease?.id !== fence || state.lease.until <= now)) throw new SafeError("lease_lost");
      migrateState(state);
      const result = callback(state, now);
      await txn.put(STATE_KEY, state);
      return result;
    });
  }

  async tick(scheduledAt) {
    const now = this.now();
    if (!Number.isFinite(scheduledAt) || scheduledAt > now + MINUTE || scheduledAt <= 0) throw new SafeError("invalid_tick");
    const fence = this.uuid();
    const claimed = await this.change((state, at) => {
      count(state.metrics, "ticksReceived");
      if (state.lease?.until > at) { count(state.metrics, "ticksBusy"); return false; }
      const bucket = Math.floor(at / TICK_MS);
      if (bucket <= state.lastBucket || scheduledAt <= (state.lastScheduledAt || 0)) {
        count(state.metrics, "ticksDuplicate"); return false;
      }
      if (state.lease) count(state.metrics, "abandonedTicks");
      const delay = Math.max(0, at - scheduledAt);
      state.metrics.maxScheduleDelayMs = Math.max(state.metrics.maxScheduleDelayMs || 0, delay);
      state.metrics.lastScheduleDelayMs = delay;
      if (state.lastTickAt) {
        const gap = at - state.lastTickAt;
        state.metrics.maxTickGapMs = Math.max(state.metrics.maxTickGapMs || 0, gap);
        count(state.metrics, "missedTickWindows", Math.max(0, Math.floor(gap / TICK_MS) - 1));
      }
      state.lastBucket = bucket;
      state.lastScheduledAt = scheduledAt;
      state.lastTickAt = at;
      state.lease = { id: fence, until: at + LEASE_MS };
      count(state.metrics, "ticksProcessed");
      return true;
    });
    if (!claimed) return { ok: true, skipped: "duplicate_or_busy" };
    this.fence = fence;
    this.deadline = now + 90000;
    this.requests = 0;
    const errors = [];
    try {
      const state = await this.storage.get(STATE_KEY);
      const configErrors = [...this.config.errors];
      if (state.target !== this.config.target) configErrors.push("target_changed_requires_migration");
      await this.change(s => {
        s.configErrors = configErrors;
        s.configErrorSince = configErrors.length ? s.configErrorSince ?? now : null;
        if (!configErrors.length) s.configuredSince ??= now;
        const qualified = !configErrors.length && this.config.enabled && this.config.heartbeat;
        if (qualified && (!s.soak?.active || s.soak.monitoringMode !== this.config.monitoringMode)) {
          s.soak = { active: true, activeSince: now, lastActiveTickAt: now, observedActiveMs: 0,
            maxTickGapMs: 0, unobservedGaps: 0, alertChannel: this.config.alertChannel, monitoringMode: this.config.monitoringMode,
            workflows: Object.fromEntries(WORKFLOWS.map(w => [w.name, {}])) };
        } else if (qualified) {
          const gap = now - s.soak.lastActiveTickAt;
          s.soak.maxTickGapMs = Math.max(s.soak.maxTickGapMs, gap);
          if (gap <= 2 * TICK_MS) s.soak.observedActiveMs += gap;
          else s.soak.unobservedGaps++;
          s.soak.lastActiveTickAt = now;
        } else if (s.soak) s.soak.active = false;
      }, fence);
      if (configErrors.length) errors.push("configuration_failure");
      else {
        // Actual pipeline starts must be known before fallback workflow recency is evaluated.
        if (this.config.heartbeat) {
          try { errors.push(...await this.readHeartbeat()); }
          catch (error) {
            errors.push(safeCode(error));
            await this.change((s, at) => {
              s.heartbeat.error = safeCode(error);
              s.heartbeat.errorSince ??= at;
              event(s, at, "heartbeat", s.heartbeat.error);
            }, fence);
          }
        }
        for (const workflow of WORKFLOWS) {
          try { await this.workflow(workflow); }
          catch (error) {
            errors.push(safeCode(error));
            await this.change((s, at) => {
              const w = s.workflows[workflow.name];
              w.error = safeCode(error);
              w.errorSince ??= at;
              w.decision = "error";
              count(w.metrics, "errors");
              event(s, at, workflow.name, w.error);
            }, fence);
          }
        }
      }
      await this.updateIncidents();
      for (const subject of ["ingest", "intel", "control"]) {
        try { await this.deliver(subject); }
        catch (error) { errors.push(safeCode(error)); }
      }
      await this.change((s, at) => {
        s.lastCompletedAt = at;
        s.lastTickErrors = [...new Set(errors)];
        s.metrics.lastTickDurationMs = at - now;
        s.metrics.maxTickDurationMs = Math.max(s.metrics.maxTickDurationMs || 0, at - now);
        s.metrics.lastTickRequests = this.requests;
        s.metrics.maxTickRequests = Math.max(s.metrics.maxTickRequests || 0, this.requests);
        if (errors.length) count(s.metrics, "ticksFailed");
        s.lease = null;
      }, fence);
      return { ok: errors.length === 0, errors: [...new Set(errors)] };
    } catch (error) {
      // An uncommitted reservation or failed final write remains visible on restart.
      throw new SafeError(safeCode(error));
    }
  }

  async request(scope, url, init = {}) {
    const state = await this.storage.get(STATE_KEY);
    if (state.lease?.id !== this.fence || state.lease.until <= this.now()) throw new SafeError("lease_lost");
    if (state[scope].retryAt > this.now()) throw new SafeError(`${scope}_backoff`, { retryAt: state[scope].retryAt });
    const remaining = this.deadline - this.now();
    if (remaining <= 0 || this.requests >= 36) throw new SafeError("tick_budget_exhausted");
    this.requests++;
    let response;
    try {
      response = await boundedJson(this.fetcher, url, init, Math.min(this.timeoutMs, remaining), 131072,
        scope !== "webhook");
    } catch (error) {
      await this.change((s, at) => {
        const policy = s[scope];
        policy.failures++;
        policy.retryAt = retryTime(new Headers(), at, policy.failures);
        policy.lastError = safeCode(error);
        count(s.metrics, `${scope}RequestFailures`);
      }, this.fence);
      throw error;
    }
    const failed = response.status < 200 || response.status >= 300;
    const errorStatus = response.status;
    const code = `${scope}_http_${Number.isInteger(errorStatus) ? errorStatus : 0}`;
    await this.change((s, at) => {
      const policy = s[scope];
      count(s.metrics, `${scope}Requests`);
      if (failed) {
        policy.failures++;
        // A missing/invalid individual workflow must not starve its sibling.
        // Authentication, server failures and rate limits affect the shared token.
        const sharedFailure = scope !== "github" || [401, 403, 429].includes(errorStatus) || errorStatus >= 500;
        policy.retryAt = sharedFailure
          ? retryTime(response.headers, at, policy.failures) : 0;
        policy.lastError = code;
        count(s.metrics, `${scope}RequestFailures`);
      } else {
        policy.failures = 0;
        policy.lastError = null;
        policy.retryAt = response.headers.get("x-ratelimit-remaining") === "0"
          ? retryTime(response.headers, at) : 0;
      }
    }, this.fence);
    if (failed) throw new SafeError(code, { status: errorStatus, ambiguous: init.method === "POST" && errorStatus >= 500 });
    return response;
  }

  githubUrl(workflow, suffix) {
    const { GITHUB_OWNER: owner, GITHUB_REPO: repo } = this.env;
    return new URL(`https://api.github.com/repos/${owner}/${repo}/actions/workflows/${workflow.file}/${suffix}`);
  }

  githubHeaders() {
    return { Authorization: `Bearer ${this.env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "sgcertwatch-scheduler", "Content-Type": "application/json" };
  }

  async runs(workflow, status, allBranches = false) {
    const url = this.githubUrl(workflow, "runs");
    url.searchParams.set("per_page", status ? "1" : "5");
    if (!allBranches) url.searchParams.set("branch", this.env.GITHUB_REF);
    if (status) url.searchParams.set("status", status);
    const { data } = await this.request("github", url, { headers: this.githubHeaders() });
    if (!Number.isSafeInteger(data?.total_count) || data.total_count < 0 || !Array.isArray(data?.workflow_runs)
      || data.workflow_runs.length > (status ? 1 : 5)
      || (data.total_count > 0 && data.workflow_runs.length === 0)) throw new SafeError("invalid_runs_response");
    return data.workflow_runs.map(run => runSummary(run, this.now()));
  }

  async workflow(workflow) {
    const recent = await this.runs(workflow);
    const successes = await this.runs(workflow, "success");
    if (successes.some(r => r.status !== "completed" || r.conclusion !== "success")) throw new SafeError("invalid_success_response");
    await this.change((s, at) => {
      const w = s.workflows[workflow.name];
      w.latestRun = recent[0] || null;
      w.lastObservedAt = at;
      w.activeRun = recent.find(r => ACTIVE.includes(r.status)) || null;
      w.error = null;
      w.errorSince = null;
      if (successes[0]) w.lastSuccessAt = Math.max(w.lastSuccessAt || 0, successes[0].updatedAt);
      const reservation = w.reservation;
      const observed = reservation && recent.find(r => r.dispatch && r.createdAt >= reservation.at - 1000
        && (!reservation.runId || reservation.runId === r.id));
      if (observed && ["reserved", "accepted", "unknown"].includes(reservation.state)) {
        reservation.correlation = reservation.runId ? "run_id" : "time_window";
        reservation.state = "observed";
        reservation.runId = observed.id;
        reservation.holdUntil = reservation.at + workflow.minimum;
        reservation.observedAt = at;
        w.dispatchError = null;
        w.dispatchErrorSince = null;
        count(w.metrics, "dispatchesObserved");
        w.metrics.maxDispatchVisibilityMs = Math.max(w.metrics.maxDispatchVisibilityMs || 0, at - reservation.at);
      }
    }, this.fence);
    const state = await this.storage.get(STATE_KEY);
    const current = state.workflows[workflow.name];
    const reservation = current.reservation;
    let reason = !this.config.enabled ? "dispatch_paused" : reservation?.holdUntil > this.now() ? "reservation"
      : current.retryAt > this.now() ? "dispatch_backoff" : null;
    if (!reason && reservation && reservation.state !== "rejected"
      && reservation.slot >= Math.floor(this.now() / workflow.interval)) reason = "reserved_slot";
    if (!reason && recent.some(r => ACTIVE.includes(r.status))) reason = "active_run";
    const bootstrapMissing = current.heartbeatError === "missing_heartbeat_row"
      && !current.heartbeatObservedAt && !state.heartbeat.error;
    const actualRecency = this.config.heartbeatRequested && !bootstrapMissing;
    if (!reason && actualRecency) {
      if (state.heartbeat.error || current.heartbeatError || !current.heartbeatObservedAt || current.heartbeatObservedAt < state.lastTickAt) {
        reason = "heartbeat_unavailable";
      } else if (current.heartbeat?.startedAt > this.now() - workflow.minimum) reason = "recent_actual_start";
    }
    if (!reason && !actualRecency && recent.some(r => {
      const owned = reservation?.origin === "cloudflare" && reservation.state === "observed" && r.id === reservation.runId;
      return owned ? reservation.at > this.now() - workflow.minimum
        : Math.max(r.createdAt, r.startedAt) > this.now() - workflow.interval;
    })) reason = "recent_run";
    if (!reason) {
      // Each status is queried independently so an old queued run cannot fall off page one.
      for (const status of ACTIVE) {
        const active = await this.runs(workflow, status, true);
        if (active.length) {
          reason = "active_run";
          await this.change(s => { s.workflows[workflow.name].activeRun = active[0]; }, this.fence);
          break;
        }
      }
    }
    if (reason) {
      await this.change(s => {
        const w = s.workflows[workflow.name];
        w.decision = reason;
        count(w.metrics, `skipped_${reason}`);
      }, this.fence);
      return;
    }
    // Persist before POST. A restart cannot erase an accepted-but-unrecorded dispatch.
    const reservationId = this.uuid();
    await this.change((s, at) => {
      const w = s.workflows[workflow.name];
      if (w.reservation?.holdUntil > at) throw new SafeError("reservation_conflict");
      w.reservation = { id: reservationId, at, slot: Math.floor(at / workflow.interval),
        state: "reserved", origin: "cloudflare", correlation: null,
        heartbeatBootstrap: bootstrapMissing, holdUntil: at + 2 * workflow.interval };
      if (bootstrapMissing) count(w.metrics, "heartbeatBootstrapDispatches");
      w.activeRun = null;
      w.decision = "dispatching";
      count(w.metrics, "dispatchAttempts");
    }, this.fence);
    try {
      const { status, data } = await this.request("github", this.githubUrl(workflow, "dispatches"), {
        method: "POST", headers: this.githubHeaders(), body: JSON.stringify({ ref: this.env.GITHUB_REF,
          inputs: { scheduler: "cloudflare" }, return_run_details: true })
      });
      if (status !== 204 && !(status === 200 && Number.isSafeInteger(data?.workflow_run_id) && data.workflow_run_id > 0)) {
        throw new SafeError("invalid_dispatch_response", { ambiguous: true });
      }
      await this.change((s, at) => {
        const w = s.workflows[workflow.name];
        w.reservation.state = "accepted";
        w.reservation.runId = data?.workflow_run_id || null;
        w.lastDispatchAcceptedAt = at;
        w.dispatchError = null;
        w.dispatchErrorSince = null;
        w.retryAt = 0;
        w.dispatchFailures = 0;
        w.decision = "dispatch_accepted";
        count(w.metrics, "dispatchesAccepted");
        event(s, at, workflow.name, "dispatch_accepted");
      }, this.fence);
    } catch (error) {
      await this.change((s, at) => {
        const w = s.workflows[workflow.name];
        // A lost storage acknowledgement may follow a successful POST too.
        const unknown = !(error instanceof SafeError) || error.ambiguous;
        w.reservation.state = unknown ? "unknown" : "rejected";
        if (!unknown) w.reservation.holdUntil = at;
        w.dispatchError = safeCode(error);
        w.dispatchErrorSince ??= at;
        w.dispatchFailures = (w.dispatchFailures || 0) + 1;
        w.retryAt = retryTime(new Headers(), at, w.dispatchFailures);
        count(w.metrics, unknown ? "dispatchesUnknown" : "dispatchesRejected");
      }, this.fence);
      throw error;
    }
  }

  async readHeartbeat() {
    const url = new URL("/rest/v1/ingest_state", this.env.SUPABASE_URL);
    url.searchParams.set("key", "in.(ct_poll_status,intel_poll_status)");
    const fields = ["checked_at", "last_started_at", "last_success_at", "last_external_trigger_at", "scheduler_trigger", "ok", "health"];
    url.searchParams.set("select", `key,${fields.map(field => `${field}:value->>${field}`).join(",")}`);
    url.searchParams.set("limit", "2");
    const key = this.env.SUPABASE_PUBLISHABLE_KEY;
    const headers = { apikey: key, Accept: "application/json" };
    if (!key.startsWith("sb_publishable_")) headers.Authorization = `Bearer ${key}`;
    const { data } = await this.request("heartbeat", url, { headers });
    if (!Array.isArray(data) || data.length > 2) throw new SafeError("invalid_heartbeat_response");
    const summaries = WORKFLOWS.filter(w => w.heartbeat).map(w => {
      try {
        const rows = data.filter(row => row?.key === w.heartbeat);
        if (rows.length !== 1) throw new SafeError("missing_heartbeat_row");
        const row = rows[0];
        const healthy = ![false, "false"].includes(row.ok) && !["down", "degraded"].includes(row.health);
        const checkedAt = timestamp(row.checked_at, this.now());
        const startedAt = row.last_started_at;
        // An explicitly null success is not equivalent to a legacy missing field.
        // PostgREST maps absent fields to null too, so a modern start disables fallback.
        const modern = Boolean(row.last_started_at);
        const successAt = row.last_success_at ? timestamp(row.last_success_at, this.now())
          : healthy && !modern ? checkedAt : null;
        const lastExternalTriggerAt = row.last_external_trigger_at ? timestamp(row.last_external_trigger_at, this.now()) : null;
        return { name: w.name, checkedAt, startedAt: startedAt ? timestamp(startedAt, this.now()) : null,
          successAt, healthy, lastExternalTriggerAt,
          origin: ["cloudflare", "github", "local"].includes(row.scheduler_trigger) ? row.scheduler_trigger : "unknown",
          actualSuccessAt: healthy && row.last_success_at ? successAt : null,
          source: row.last_success_at ? "last_success_at" : "checked_at_legacy" };
      } catch (error) {
        return { name: w.name, error: safeCode(error) };
      }
    });
    await this.change((s, at) => {
      s.heartbeat.lastObservedAt = at;
      s.heartbeat.error = null;
      s.heartbeat.errorSince = null;
      for (const row of summaries) {
        const w = s.workflows[row.name];
        if (row.error) {
          w.heartbeatError = row.error;
          w.heartbeatErrorSince ??= at;
          count(w.metrics, "heartbeatErrors");
          event(s, at, row.name, row.error);
          continue;
        }
        w.heartbeatError = null;
        w.heartbeatErrorSince = null;
        w.heartbeatObservedAt = at;
        w.heartbeat = row;
        if (row.successAt) w.lastHeartbeatSuccessAt = Math.max(w.lastHeartbeatSuccessAt || 0, row.successAt);
        observeActual(w.metrics, row.startedAt, row.actualSuccessAt, at, s.configuredSince);
        if (s.soak?.active) observeActual(s.soak.workflows[row.name], row.startedAt, row.actualSuccessAt, at, s.soak.activeSince);
      }
    }, this.fence);
    return summaries.filter(row => row.error).map(row => `heartbeat_${row.name}_${row.error}`);
  }

  assessment(state, workflow, now) {
    const w = state.workflows[workflow.name];
    const useHeartbeat = this.config.heartbeatRequested && Boolean(workflow.heartbeat);
    const baseline = state.configuredSince ?? state.startedAt;
    const successAgeMs = age(now, useHeartbeat ? w.lastHeartbeatSuccessAt : w.lastSuccessAt, baseline);
    const ghFresh = w.lastObservedAt !== null && now - w.lastObservedAt < 2 * TICK_MS && !w.error;
    const heartbeatFresh = !useHeartbeat || (this.config.heartbeat && w.heartbeatObservedAt
      && now - w.heartbeatObservedAt < 2 * TICK_MS && !state.heartbeat.error && !w.heartbeatError);
    const heartbeatAgeMs = useHeartbeat ? age(now, w.lastHeartbeatSuccessAt, baseline) : null;
    const latestFailed = w.latestRun?.status === "completed" && w.latestRun.conclusion !== "success"
      && w.latestRun.updatedAt >= (w.lastSuccessAt || 0);
    const level = Math.max(severity(successAgeMs, workflow.warning, workflow.critical),
      heartbeatAgeMs === null ? 0 : severity(heartbeatAgeMs, workflow.warning, workflow.critical),
      w.errorSince == null ? 0 : severity(now - w.errorSince),
      w.dispatchErrorSince == null ? 0 : severity(now - w.dispatchErrorSince),
      w.heartbeatErrorSince == null || !useHeartbeat ? 0 : severity(now - w.heartbeatErrorSince),
      state.heartbeat.errorSince == null || !useHeartbeat ? 0 : severity(now - state.heartbeat.errorSince));
    const healthy = ghFresh && heartbeatFresh && !latestFailed && !w.dispatchError && level === 0 && Boolean(w.lastSuccessAt)
      && (!useHeartbeat || (w.heartbeat?.healthy && w.lastHeartbeatSuccessAt));
    return { healthy: Boolean(healthy), level, successAgeMs, heartbeatAgeMs,
      activeRunAgeMs: w.activeRun ? now - w.activeRun.createdAt : null,
      observation: ghFresh && heartbeatFresh ? "current" : "unknown", latestFailed: Boolean(latestFailed) };
  }

  async updateIncidents() {
    await this.change((s, at) => {
      const assessments = Object.fromEntries(WORKFLOWS.map(w => [w.name, s.configuredSince == null
        ? { level: 0, healthy: false } : this.assessment(s, w, at)]));
      assessments.control = { level: s.configErrorSince == null ? 0 : severity(at - s.configErrorSince), healthy: !s.configErrors?.length };
      for (const [subject, assessment] of Object.entries(assessments)) {
        let incident = s.incidents[subject];
        if (this.config.webhook && incident?.notice?.state === "sending" && (incident.notice.leaseUntil || 0) <= at) {
          const notice = incident.notice;
          notice.state = notice.attempts >= ALERT_MAX_ATTEMPTS ? "dead_letter" : "unknown";
          notice.error = "delivery_unconfirmed_after_restart";
          notice.retryAt = Math.max(notice.retryAt || 0, alertRetryAt(notice, notice.attemptedAt));
          count(s.metrics, "alertLeasesRecovered");
          if (notice.state === "dead_letter") count(s.metrics, "alertDeadLetters");
        }
        if (assessment.level > 0) {
          if (!incident || !incident.active) {
            incident = { id: `${subject}:${at}`, active: true, since: at, level: 0, announced: false, notice: null };
            s.incidents[subject] = incident;
            count(s.metrics, "incidentsOpened");
          }
          if (assessment.level > incident.level) {
            incident.level = assessment.level;
            const kind = assessment.level === 2 ? "critical" : "warning";
            incident.notice = { key: `${incident.id}:${kind}`, kind,
              state: this.config.webhook ? "pending" : "dashboard_only", attempts: 0, retryAt: 0 };
            count(s.metrics, `${kind}Transitions`);
            event(s, at, subject, kind);
          }
        } else if (assessment.healthy && incident?.active) {
          const prior = incident.notice;
          const needsSummary = this.config.webhook && (incident.announced || prior?.attempts > 0
            || (prior && !["channel_unconfigured", "dashboard_only"].includes(prior.state)));
          incident.active = false;
          incident.recoveredAt = at;
          incident.previousNotice = prior;
          incident.notice = needsSummary
            ? { key: `${incident.id}:recovery`, kind: "recovery", state: "pending", attempts: 0,
              retryAt: prior?.retryAt || 0, priorDeliveryState: prior?.state || null,
              summary: !(incident.confirmedAlertDelivered || prior?.state === "sent") } : null;
          count(s.metrics, "recoveries");
          event(s, at, subject, "recovery");
        }
      }
    }, this.fence);
  }

  async deliver(subject) {
    const channel = this.config.alertChannel;
    if (!this.config.webhook || !["ingest", "intel", "control"].includes(subject)) return;
    const reserved = await this.change((s, at) => {
      const incident = s.incidents[subject];
      const notice = incident?.notice;
      if (!notice || ["sent", "dead_letter", "sending"].includes(notice.state)) return null;
      if (notice.retryAt > at || s[channel].retryAt > at) return null;
      const announcedBefore = incident.announced;
      notice.state = "sending";
      notice.attempts++;
      notice.attemptedAt = at;
      notice.owner = this.fence;
      notice.leaseUntil = at + LEASE_MS;
      incident.announced = true;
      return { key: notice.key, kind: notice.kind, announcedBefore, summary: notice.summary || false,
        priorDeliveryState: notice.priorDeliveryState || null, recoveredAt: incident.recoveredAt || null };
    }, this.fence);
    if (!reserved) return;
    try {
      const webhookHeaders = { "Content-Type": "application/json" };
      if (this.env.ALERT_WEBHOOK_SECRET) webhookHeaders.Authorization = `Bearer ${this.env.ALERT_WEBHOOK_SECRET}`;
      const webhookRequest = { method: "POST", headers: webhookHeaders,
        body: JSON.stringify({ schema_version: 1, source: "sgcertwatch-scheduler", event_id: reserved.key,
          subject, kind: reserved.kind, observed_at: new Date(this.now()).toISOString(),
          resolved_before_delivery: reserved.summary, prior_delivery_state: reserved.priorDeliveryState,
          recovered_at: reserved.recoveredAt ? new Date(reserved.recoveredAt).toISOString() : null }) };
      await this.request(channel, this.env.ALERT_WEBHOOK_URL, webhookRequest);
      await this.change((s, at) => {
        const notice = s.incidents[subject].notice;
        notice.state = "sent";
        notice.owner = null;
        notice.leaseUntil = null;
        notice.deliveredAt = at;
        notice.error = null;
        if (notice.kind !== "recovery") s.incidents[subject].confirmedAlertDelivered = true;
        count(s.metrics, "alertsDelivered");
      }, this.fence);
    } catch (error) {
      await this.change((s, at) => {
        const incident = s.incidents[subject];
        const notice = incident.notice;
        const unknown = !(error instanceof SafeError) || error.ambiguous;
        notice.state = notice.attempts >= ALERT_MAX_ATTEMPTS ? "dead_letter" : unknown ? "unknown" : "failed";
        notice.owner = null;
        notice.leaseUntil = null;
        notice.error = safeCode(error);
        notice.retryAt = Math.max(s[channel].retryAt || 0, alertRetryAt(notice, at));
        if (!unknown) incident.announced = reserved.announcedBefore;
        count(s.metrics, unknown ? "alertsUnknown" : "alertsFailed");
        if (notice.state === "dead_letter") count(s.metrics, "alertDeadLetters");
        event(s, at, subject, notice.error);
      }, this.fence);
      throw error;
    }
  }

  async status() {
    const state = await this.storage.get(STATE_KEY);
    const at = this.now();
    const config = { ...this.config, proactiveAlerts: this.config.alertChannel !== "none" };
    if (!state) return { ok: false, state: "not_started", at, config };
    // Read-only projection: a protected GET must never commit a migration.
    migrateState(state);
    const assessments = Object.fromEntries(WORKFLOWS.map(w => [w.name, this.assessment(state, w, at)]));
    const tickAgeMs = age(at, state.lastCompletedAt, state.startedAt);
    const alertIssues = this.config.webhook && Object.values(state.incidents).some(i => i.notice && i.notice.state !== "sent");
    const ok = Boolean(state.lastCompletedAt) && tickAgeMs < 2 * TICK_MS && !this.config.errors.length
      && state.target === this.config.target && !state.lastTickErrors?.length && !alertIssues
      && Object.values(state.incidents).every(i => !i.active)
      && Object.values(assessments).every(a => a.healthy);
    const { lease, ...visible } = state;
    return { ...visible, ok, at, config, assessments, tickAgeMs,
      soak: state.soak ? { ...state.soak, elapsedActiveMs: at - state.soak.activeSince,
        active: state.soak.active && state.soak.monitoringMode === this.config.monitoringMode && this.config.enabled && this.config.heartbeat
          && !this.config.errors.length && state.target === this.config.target && tickAgeMs < 2 * TICK_MS,
        validation: "not_evaluated", requiresIndependentVerification: true } : null,
      coordinator: { busy: Boolean(lease && lease.until > at), abandoned: Boolean(lease && lease.until <= at) } };
  }
}

import { configured, getState, listCtLogs, listSourceRuns } from "../lib/supabase.js";
import { isLogSelected } from "../lib/ct/loglist.js";
import { compileSourceHealth } from "../lib/ct/source-health.js";

const HOUR_MS = 60 * 60 * 1000;
const CT_TARGET_MS = 15 * 60 * 1000;
const CT_SOURCES = ["direct_ct", "static_ct", "certstream", "crtsh"];
const INTEL_SOURCES = [
  { source: "openphish", label: "OpenPhish", freshness: 13 * HOUR_MS },
  { source: "urlscan", label: "urlscan.io", freshness: 7 * HOUR_MS },
  { source: "urlhaus", label: "URLhaus", freshness: 7 * HOUR_MS },
  { source: "threatfox", label: "ThreatFox", freshness: 7 * HOUR_MS }
];

function latestSourceRuns(sourceRuns) {
  const bySource = new Map();
  for (const run of sourceRuns || []) {
    if (!run?.source) continue;
    const current = bySource.get(run.source);
    if (!current || Date.parse(run.checked_at || 0) > Date.parse(current.checked_at || 0)) {
      bySource.set(run.source, run);
    }
  }
  return [...bySource.values()].sort((a, b) => String(a.label || a.source).localeCompare(String(b.label || b.source)));
}

function displaySourceForRun(run, now) {
  const checkedAt = Date.parse(run.checked_at);
  const stale = !Number.isFinite(checkedAt) || now - checkedAt > HOUR_MS;
  const details = run.details || {};
  const status = stale ? "stale" : details.state === "cooldown" ? "cooldown"
    : details.state === "unconfigured" ? "unconfigured"
    : run.ok ? (details.state === "scheduled" || details.state === "standby" ? "standby" : "ok") : "degraded";
  const lastAttempt = run.source === "crtsh" && Object.hasOwn(details, "last_attempt_at")
    ? details.last_attempt_at : run.checked_at || null;
  return {
    source: run.source,
    label: run.label || run.source,
    ok: Boolean(run.ok) && !stale,
    status,
    scanned_entries: run.scanned_entries || 0,
    matched: run.matched || 0,
    persisted: run.persisted || 0,
    checked_at: lastAttempt,
    last_checked_at: lastAttempt,
    next_poll_at: details.next_poll_at || null,
    last_success_at: details.last_success_at || null,
    errors: run.errors || [],
    details
  };
}

function intelSourceRows(pollStatus, now) {
  const runs = latestSourceRuns(Array.isArray(pollStatus?.sources) ? pollStatus.sources : []);
  return INTEL_SOURCES.map(({ source, label, freshness }) => {
    const run = runs.find((row) => row.source === source);
    const checkedAt = run?.checked_at || null;
    const checkedMs = Date.parse(checkedAt);
    const nextPoll = Date.parse(run?.next_poll_at);
    let status = run?.status || (run ? (run.ok ? "ok" : "degraded") : "pending");
    const deadline = Math.max(checkedMs + freshness, Number.isFinite(nextPoll) ? nextPoll + HOUR_MS : 0);
    const awaitingRetry = ["cooldown", "auth_error"].includes(status)
      && Number.isFinite(nextPoll) && now <= nextPoll;
    if (status !== "not_configured" && status !== "pending" && !awaitingRetry
      && (!Number.isFinite(checkedMs) || now > deadline)) status = "stale";
    return {
      source,
      label,
      status,
      ok: Boolean(run?.ok) && status === "ok",
      checked_at: checkedAt,
      last_checked_at: checkedAt,
      scanned_entries: run?.scanned_entries || 0,
      matched: run?.matched || 0,
      persisted: run?.persisted || 0,
      errors: run?.errors || [],
      details: run?.details || {},
      next_poll_at: run?.next_poll_at || null
    };
  });
}

function timestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? value : null;
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function ctOperations(poll, now) {
  const started = timestamp(poll?.last_started_at);
  const checked = timestamp(poll?.checked_at);
  // A legacy successful completion is evidence; a start or row update is not.
  const success = timestamp(poll?.last_success_at) || (!Object.hasOwn(poll || {}, "last_success_at")
    && ["healthy", "partial"].includes(poll?.health) ? checked : null);
  const age = success ? Math.max(0, now - Date.parse(success)) : null;
  const freshness = age === null ? "unknown" : age > HOUR_MS ? "critical" : age > 2 * CT_TARGET_MS ? "warning" : "fresh";
  const state = ["running", "completed", "failed"].includes(poll?.state) ? poll.state
    : poll?.health === "down" ? "failed" : checked ? "completed" : "pending";
  const duration = count(poll?.duration_ms);
  const anchor = started || checked;
  return {
    state,
    last_started_at: started,
    last_success_at: success,
    checked_at: checked,
    next_due_at: anchor ? new Date(Date.parse(anchor) + CT_TARGET_MS).toISOString() : null,
    target_interval_minutes: 15,
    duration_ms: duration,
    runtime_ms: state === "running" ? (started ? Math.max(0, now - Date.parse(started)) : null) : duration,
    success_age_ms: age,
    freshness,
    run_id: typeof poll?.run_id === "string" ? poll.run_id : null,
    trigger: typeof poll?.trigger === "string" ? poll.trigger : null,
    scheduler_trigger: typeof poll?.scheduler_trigger === "string" ? poll.scheduler_trigger : null
  };
}

function measuredCursor(log, cursors) {
  const cursor = cursors[log.log_id] || cursors[log.submission_url] || cursors[log.monitoring_url];
  const tree = count(cursor?.tree_size ?? cursor?.treeSize);
  const next = count(cursor?.next_index ?? cursor?.next);
  return tree !== null && next !== null && next <= tree;
}

export default async function handler(request, response) {
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const [pollStatusRow, sourceRuns, sourceStateRow, intelResult, logsResult] = await Promise.all([
      getState("ct_poll_status"),
      listSourceRuns(24, CT_SOURCES),
      getState("ct_source_state").catch(() => null),
      getState("intel_poll_status").then((row) => ({ row }), (error) => ({ error })),
      listCtLogs().then((rows) => rows.filter((log) => isLogSelected(log)), () => [])
    ]);
    const sourceState = sourceStateRow?.value || {};
    const now = Date.now();
    const latestPoll = pollStatusRow?.value ? { ...pollStatusRow.value } : null;
    // Older CT heartbeats can still contain the retired enqueue summary.
    if (latestPoll) delete latestPoll.notifications;

    const cursors = {
      ...(sourceState?.direct_ct?.cursors || {}),
      ...(sourceState?.static_ct?.cursors || {})
    };
    const healthSummary = compileSourceHealth({
      ctLogs: logsResult.filter((log) => measuredCursor(log, cursors)),
      cursors,
      sourceRuns,
      pollStatus: latestPoll
    });
    const latestRuns = latestSourceRuns(sourceRuns);
    const displaySources = latestRuns.length
      ? latestRuns.map((run) => displaySourceForRun(run, now))
      : [];
    const operations = ctOperations(latestPoll, now);
    const health = operations.state === "failed" || latestPoll?.health === "down" ? "down"
      : ["warning", "critical"].includes(operations.freshness) ? "stale"
      : operations.freshness === "unknown" ? "pending" : latestPoll?.health || "pending";
    const measured = healthSummary.sources.filter((row) => Number.isFinite(row.lag_entries));
    const externalTrigger = timestamp(latestPoll?.last_external_trigger_at);
    const intelSources = intelSourceRows(intelResult.row?.value, now);
    if (intelResult.error) {
      for (const row of intelSources) {
        row.status = "unavailable";
        row.errors = ["Intel status could not be loaded"];
      }
    }

    response.status(200).json({
      storage_configured: configured(),
      ...healthSummary,
      health,
      operations,
      cursor_lag: {
        measured_logs: measured.length,
        lag_entries: measured.length ? measured.reduce((total, row) => total + row.lag_entries, 0) : null,
        max_lag_entries: measured.length ? Math.max(...measured.map((row) => row.lag_entries)) : null
      },
      display_sources: displaySources,
      intel_sources: intelSources,
      intel_schedule: {
        runner: "github-actions",
        workflow: "intel.yml",
        cron: "7 * * * *",
        script: "scripts/run-intel.mjs"
      },
      schedule: {
        runner: "github-actions",
        workflow: "ingest.yml",
        cron: "7,22,37,52 * * * *",
        script: "scripts/run-ingest.mjs",
        target_interval_minutes: 15,
        last_external_trigger_at: externalTrigger
      },
      source_runs: sourceRuns,
      updated_at: pollStatusRow?.updated_at || new Date().toISOString()
    });
  } catch (error) {
    response.status(500).json({ error: "source_status_failed", message: error.message });
  }
}

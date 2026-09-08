import { configured, getState, listCtLogs, listSourceRuns } from "../lib/supabase.js";
import { isLogSelected } from "../lib/ct/loglist.js";
import { compileSourceHealth } from "../lib/ct/source-health.js";

const HOUR_MS = 60 * 60 * 1000;
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
      getState("ct_source_state"),
      getState("intel_poll_status").then((row) => ({ row }), (error) => ({ error })),
      listCtLogs().then((rows) => rows.filter((log) => isLogSelected(log)), () => [])
    ]);
    const sourceState = sourceStateRow?.value || {};
    const now = Date.now();

    const healthSummary = compileSourceHealth({
      ctLogs: logsResult,
      cursors: {
        ...(sourceState?.direct_ct?.cursors || {}),
        ...(sourceState?.static_ct?.cursors || {})
      },
      sourceRuns,
      pollStatus: pollStatusRow?.value || null
    });
    const latestRuns = latestSourceRuns(sourceRuns);
    const displaySources = latestRuns.length
      ? latestRuns.map((run) => displaySourceForRun(run, now))
      : [];
    const latestPoll = pollStatusRow?.value || null;
    const pollTime = Date.parse(latestPoll?.checked_at || pollStatusRow?.updated_at);
    const stalePoll = latestPoll && (!Number.isFinite(pollTime) || now - pollTime > HOUR_MS);
    const health = stalePoll ? "stale" : latestPoll?.health || "pending";
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
        script: "scripts/run-ingest.mjs"
      },
      source_runs: sourceRuns,
      updated_at: pollStatusRow?.updated_at || new Date().toISOString()
    });
  } catch (error) {
    response.status(500).json({ error: "source_status_failed", message: error.message });
  }
}

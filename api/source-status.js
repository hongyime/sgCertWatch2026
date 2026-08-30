import { configured, getState, listSourceRuns } from "../lib/supabase.js";
import { fetchDynamicLogList } from "../lib/ct/loglist.js";
import { compileSourceHealth } from "../lib/ct/source-health.js";

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

function displaySourceForRun(run) {
  return {
    source: run.source,
    label: run.label || run.source,
    ok: Boolean(run.ok),
    status: run.ok ? "ok" : "degraded",
    scanned_entries: run.scanned_entries || 0,
    matched: run.matched || 0,
    persisted: run.persisted || 0,
    last_checked_at: run.checked_at || null,
    errors: run.errors || [],
    details: run.details || {}
  };
}

export default async function handler(request, response) {
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const pollStatusRow = await getState("ct_poll_status");
    const sourceRuns = await listSourceRuns(24);
    const sourceStateRow = await getState("ct_source_state");
    const sourceState = sourceStateRow?.value || {};

    let ctLogs = [];
    try {
      const listResult = await fetchDynamicLogList();
      ctLogs = listResult.selectedLogs;
    } catch (_err) {
      ctLogs = [];
    }

    const healthSummary = compileSourceHealth({
      ctLogs,
      cursors: {
        ...(sourceState?.direct_ct?.cursors || {}),
        ...(sourceState?.static_ct?.cursors || {})
      },
      sourceRuns,
      pollStatus: pollStatusRow?.value || null
    });
    const latestRuns = latestSourceRuns(sourceRuns);
    const displaySources = latestRuns.length
      ? latestRuns.map(displaySourceForRun)
      : [];
    const latestPoll = pollStatusRow?.value || null;
    const health = latestPoll?.health || healthSummary.overall;

    response.status(200).json({
      storage_configured: configured(),
      ...healthSummary,
      health,
      display_sources: displaySources,
      schedule: {
        runner: "github-actions",
        workflow: "ingest.yml",
        cron: "*/15 * * * *",
        script: "scripts/run-ingest.mjs"
      },
      source_runs: sourceRuns,
      updated_at: pollStatusRow?.updated_at || new Date().toISOString()
    });
  } catch (error) {
    response.status(500).json({ error: "source_status_failed", message: error.message });
  }
}

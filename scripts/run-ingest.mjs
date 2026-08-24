import { loadData } from "../lib/data.js";
import { scoreCertificate } from "../lib/scoring.js";
import { mergeSourceState, runSources } from "../lib/ct/orchestrator.js";
import { dispatchNotifications } from "../lib/notify.js";
import {
  getState,
  insertSourceRuns,
  releaseRunLock,
  setState,
  tryAcquireRunLock,
  upsertFindingSources,
  upsertFindings
} from "../lib/supabase.js";

function uniqueFindings(findings) {
  const map = new Map();
  for (const finding of findings) {
    if (!map.has(finding.id)) {
      map.set(finding.id, { ...finding });
    } else {
      const existing = map.get(finding.id);
      existing.entry_types = [...new Set([...(existing.entry_types || []), ...(finding.entry_types || [])])];
      if (Date.parse(finding.observed_at) < Date.parse(existing.observed_at)) {
        existing.observed_at = finding.observed_at;
      }
      existing.domains = [...new Set([...(existing.domains || []), ...(finding.domains || [])])];
      existing.san_count = existing.domains.length;
      if (finding.cert_serial && !existing.cert_serial) {
        existing.cert_serial = finding.cert_serial;
      }
      if (finding.cert_issuer_dn_sha256 && !existing.cert_issuer_dn_sha256) {
        existing.cert_issuer_dn_sha256 = finding.cert_issuer_dn_sha256;
      }
    }
  }
  return [...map.values()];
}

function sourceRefFor(finding, entry, source) {
  return finding.source?.source_ref
    || finding.source?.fingerprint
    || finding.source?.cert_link
    || `${source}:${finding.id}`;
}

function sourceRowsFor(scored) {
  const rows = scored.map(({ finding, entry, source }) => ({
    finding_id: finding.id,
    source,
    source_ref: sourceRefFor(finding, entry, source),
    observed_at: finding.observed_at,
    details: {
      domains: finding.domains,
      registrable: finding.registrable,
      severity: finding.severity,
      score: finding.score,
      cert_serial: finding.cert_serial || null,
      entry_types: finding.entry_types || [],
      san_count: finding.san_count || finding.domains?.length || 0,
      cert_index: finding.source?.cert_index || null,
      cert_link: finding.source?.cert_link || null,
      fingerprint: finding.source?.fingerprint || null,
      log_name: finding.source?.log_name || null,
      log_operator: finding.source?.log_operator || null
    }
  }));

  return [...rows.reduce((map, row) => {
    map.set(`${row.finding_id}|${row.source}|${row.source_ref}`, row);
    return map;
  }, new Map()).values()];
}

function summarizeRun(run, matched, persisted) {
  return {
    source: run.source,
    label: run.label,
    checked_at: new Date().toISOString(),
    ok: run.ok,
    scanned_entries: run.scanned_entries,
    matched,
    persisted,
    duration_ms: run.duration_ms,
    errors: run.errors,
    details: run.details || {}
  };
}

async function runIngest() {
  const lockAcquired = await tryAcquireRunLock("ct_poll_run", 300);
  if (!lockAcquired) {
    console.log(JSON.stringify({ skipped: "run_in_progress" }));
    return;
  }

  let status;
  try {
    const data = loadData();
    const stateRow = await getState("ct_source_state");
    const sourceState = stateRow?.value || {};
    const runs = await runSources({ data, state: sourceState });

    const scored = [];
    const matchedBySource = new Map();
    for (const run of runs) {
      let matched = 0;
      for (const entry of run.entries) {
        const finding = scoreCertificate(entry, data);
        if (!finding) continue;
        matched += 1;
        scored.push({ finding, entry, source: run.source });
      }
      matchedBySource.set(run.source, matched);
    }

    const findings = uniqueFindings(scored.map((item) => item.finding));
    const persistedFindings = await upsertFindings(findings);
    const sourceRows = sourceRowsFor(scored);
    const persistedSources = await upsertFindingSources(sourceRows);

    let notifySummary = { candidates: 0, telegram: 0, discord: 0, webhook: 0, errors: [] };
    try {
      notifySummary = await dispatchNotifications(persistedFindings);
    } catch (_err) {
      // Keep going even if notification fails
    }

    const sourceSummaries = runs.map((run) => summarizeRun(
      run,
      matchedBySource.get(run.source) || 0,
      sourceRows.filter((row) => row.source === run.source).length
    ));
    await insertSourceRuns(sourceSummaries);

    const nextSourceState = mergeSourceState(sourceState, runs);
    await setState("ct_source_state", nextSourceState);

    const okSources = sourceSummaries.filter((run) => run.ok);
    status = {
      ok: okSources.length > 0,
      health: okSources.length === sourceSummaries.length ? "healthy" : (okSources.length ? "partial" : "down"),
      source: "multi-source CT polling",
      runner: "github-actions",
      checked_at: new Date().toISOString(),
      scanned_entries: sourceSummaries.reduce((total, run) => total + run.scanned_entries, 0),
      matched: findings.length,
      persisted: persistedFindings.length,
      persisted_source_sightings: persistedSources.length,
      notifications: notifySummary,
      sources: sourceSummaries,
      errors: sourceSummaries.flatMap((run) => run.errors.map((error) => ({
        source: run.source,
        ...error
      })))
    };

    await setState("ct_poll_status", status);
    console.log(JSON.stringify(status));
  } finally {
    await releaseRunLock("ct_poll_run");
  }

  if (status && status.health === "down") {
    process.exitCode = 1;
  }
}

runIngest().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

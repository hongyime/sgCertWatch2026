import { checkBearer } from "../../lib/auth.js";
import { loadData } from "../../lib/data.js";
import { scoreCertificate } from "../../lib/scoring.js";
import { mergeSourceState, runSources } from "../../lib/ct/orchestrator.js";
import {
  getState,
  insertSourceRuns,
  setState,
  upsertFindingSources,
  upsertFindings
} from "../../lib/supabase.js";

function uniqueFindings(findings) {
  return [...findings.reduce((map, finding) => map.set(finding.id, finding), new Map()).values()];
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

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return response.status(405).json({ error: "method_not_allowed" });
  }

  const auth = checkBearer(request, process.env.CRON_SECRET);
  if (!auth.ok) {
    return response.status(auth.reason === "server_misconfigured" ? 500 : 401)
      .json({ error: "unauthorized" });
  }

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

  const sourceSummaries = runs.map((run) => summarizeRun(
    run,
    matchedBySource.get(run.source) || 0,
    sourceRows.filter((row) => row.source === run.source).length
  ));
  await insertSourceRuns(sourceSummaries);

  const nextSourceState = mergeSourceState(sourceState, runs);
  await setState("ct_source_state", nextSourceState);

  const okSources = sourceSummaries.filter((run) => run.ok);
  const status = {
    ok: okSources.length > 0,
    health: okSources.length === sourceSummaries.length ? "healthy" : (okSources.length ? "partial" : "down"),
    source: "multi-source CT polling",
    checked_at: new Date().toISOString(),
    scanned_entries: sourceSummaries.reduce((total, run) => total + run.scanned_entries, 0),
    matched: findings.length,
    persisted: persistedFindings.length,
    persisted_source_sightings: persistedSources.length,
    sources: sourceSummaries,
    errors: sourceSummaries.flatMap((run) => run.errors.map((error) => ({
      source: run.source,
      ...error
    })))
  };

  await setState("ct_poll_status", status);
  response.status(200).json(status);
}

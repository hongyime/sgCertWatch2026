import { loadData } from "../lib/data.js";
import { scoreCertificate } from "../lib/scoring.js";
import { mergeSourceState, runSources } from "../lib/ct/orchestrator.js";
import { dispatchNotifications } from "../lib/notify.js";
import { summarizePrimaryHealth } from "../lib/ct/source-health.js";
import * as storage from "../lib/supabase.js";
import { pathToFileURL } from "node:url";

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

export async function runIngest({ store = storage, scan = runSources, score = scoreCertificate,
  notify = dispatchNotifications, readData = loadData } = {}) {
  const { getRecentAlertRegistrables, getServiceState, insertSourceRuns, recordAlerts,
    releaseRunLock, setState, tryAcquireRunLock, upsertFindingSources, upsertFindings } = store;
  if (!store.configured("service")) throw new Error("Supabase service credentials are required");
  // GitHub's ct-ingest concurrency group is the serialization boundary.
  const lockAcquired = await tryAcquireRunLock("ct_poll_run", 15 * 60);
  if (!lockAcquired) {
    console.log(JSON.stringify({ skipped: "run_in_progress" }));
    return;
  }

  let status;
  let stage = "sources";
  try {
    const data = readData();
    const stateRow = await getServiceState("ct_source_state");
    const sourceState = stateRow?.value || {};
    const runs = await scan({ data, state: sourceState });
    console.log(JSON.stringify({ stage: "sources_fetched", sources: runs.map((run) => ({
      source: run.source, entries: run.entries.length, scanned: run.scanned_entries, duration_ms: run.duration_ms
    })) }));

    const backupFailure = runs.find((run) => run.source === "crtsh" && !run.ok);
    const staticCooldowns = runs.find((run) => run.source === "static_ct")?.statePatch?.static_ct?.cooldowns;
    if (backupFailure?.statePatch || Object.keys(staticCooldowns || {}).length) {
      stage = "source_backoff";
      // Persist the provider pause even if scoring or later writes fail; do not advance CT cursors.
      const pausedState = mergeSourceState(sourceState, backupFailure ? [backupFailure] : []);
      if (staticCooldowns) pausedState.static_ct = { ...sourceState.static_ct, cooldowns: staticCooldowns };
      await setState("ct_source_state", pausedState);
    }

    stage = "scoring";
    const scored = [];
    const matchedBySource = new Map();
    for (const run of runs) {
      let matched = 0;
      let checked = 0;
      for (const entry of run.entries) {
        checked++;
        if (checked % 10000 === 0) console.log(JSON.stringify({ stage: "scoring", source: run.source, checked, matched }));
        const finding = score(entry, data);
        if (!finding) continue;
        matched += 1;
        scored.push({ finding, entry, source: run.source });
      }
      matchedBySource.set(run.source, matched);
    }

    const scorable = scored.filter(({ finding }) => Boolean(finding.registrable));
    if (scorable.length < scored.length) {
      console.error(`skipped ${scored.length - scorable.length} matches without a resolvable registrable domain`);
    }

    const findings = uniqueFindings(scorable.map((item) => item.finding));
    console.log(JSON.stringify({ stage: "persisting", findings: findings.length }));
    stage = "findings";
    const persistedFindings = await upsertFindings(findings);
    const sourceRows = sourceRowsFor(scorable);
    stage = "sightings";
    const persistedSources = await upsertFindingSources(sourceRows);

    const sourceSummaries = runs.map((run) => summarizeRun(
      run,
      matchedBySource.get(run.source) || 0,
      sourceRows.filter((row) => row.source === run.source).length
    ));
    stage = "checkpoint";
    const nextSourceState = mergeSourceState(sourceState, runs);
    await setState("ct_source_state", nextSourceState);
    await insertSourceRuns(sourceSummaries);

    status = {
      ...summarizePrimaryHealth(sourceSummaries),
      source: "multi-source CT polling",
      runner: "github-actions",
      checked_at: new Date().toISOString(),
      scanned_entries: sourceSummaries.reduce((total, run) => total + run.scanned_entries, 0),
      matched: findings.length,
      persisted: persistedFindings.length,
      persisted_source_sightings: persistedSources.length,
      notifications: { state: "pending", telegram: 0, errors: [] },
      sources: sourceSummaries,
      errors: sourceSummaries.flatMap((run) => run.errors.map((error) => ({
        source: run.source,
        ...error
      })))
    };

    await setState("ct_poll_status", status);
    // Notification failures must never hold completed CT progress hostage.
    try {
      const alerted72h = await getRecentAlertRegistrables(72);
      status.notifications = await notify(persistedFindings, {
        alertedWithin72h: alerted72h, minScore: data.scoring?.thresholds?.alert_min ?? 70
      });
      await recordAlerts(status.notifications.delivered_registrables || []);
    } catch (_error) {
      status.notifications = { state: "failed", telegram: 0, errors: [{ message: "Notification delivery failed" }] };
    }
    try {
      await setState("ct_poll_status", status);
    } catch (_error) {
      console.error("Notification summary save failed; completed CT checkpoint retained");
    }
    console.log(JSON.stringify(status));
  } catch (error) {
    try {
      await setState("ct_poll_status", {
        ok: false, health: "down", runner: "github-actions", checked_at: new Date().toISOString(),
        failed_stage: stage, errors: [{ message: `CT ingest failed during ${stage}; see Actions logs` }]
      });
    } catch (_statusError) {
      console.error("Failed to persist ingest failure status; dashboard freshness will expire");
    }
    throw error;
  } finally {
    await releaseRunLock("ct_poll_run");
  }

  return status;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  runIngest().then((status) => {
    if (status && !status.ok) process.exitCode = 1;
  }).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

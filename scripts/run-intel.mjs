import * as storage from "../lib/supabase.js";
import { runIntelPipeline } from "../lib/intel/pipeline.js";
import { acquireRunLease } from "../lib/run-lease.js";
import { pathToFileURL } from "node:url";

export async function runIntel({ store = storage, pipeline = runIntelPipeline, now = Date.now,
  minIntervalMs = Number(process.env.INTEL_MIN_INTERVAL_MS || 0), leaseOptions = {} } = {}) {
  if (!store.configured("service")) throw new Error("Supabase service credentials are required");
  const lease = await acquireRunLease(store, { name: "intel_poll_run", leaseSeconds: 600,
    maxRunMs: 7 * 60 * 1000, ...leaseOptions });
  if (!lease) { console.log(JSON.stringify({ skipped: "run_in_progress" })); return; }
  const started = now();
  let previous = {};
  let statusLoaded = false;
  try {
    previous = (await store.getServiceState("intel_poll_status"))?.value || {};
    statusLoaded = true;
    const priorStart = Date.parse(previous.last_started_at || previous.checked_at);
    if (Number.isFinite(priorStart) && started - priorStart < minIntervalMs) {
      console.log(JSON.stringify({ skipped: "intel_not_due" })); return;
    }
    await lease.setState("intel_poll_status", { ...previous, state: "running", last_started_at: new Date(started).toISOString() });
    const stateRow = await store.getServiceState("intel_source_state");
    const candidates = await store.listIntelCandidates(500);
    const result = await pipeline({ state: stateRow?.value || {}, candidates,
      saveState: (state) => lease.setState("intel_source_state", state),
      saveEvidence: (evidence) => { lease.assertOwned(); return store.upsertIntelEvidence(evidence); } });
    const ok = !result.status.sources.some((source) => ["degraded", "auth_error", "cooldown"].includes(source.status));
    const status = { ...result.status, ok, state: "completed", last_started_at: new Date(started).toISOString(),
      last_success_at: ok ? new Date(now()).toISOString() : previous.last_success_at || null,
      duration_ms: Math.max(0, now() - started), run_id: process.env.GITHUB_RUN_ID || null,
      scheduler_trigger: process.env.SCHEDULER_TRIGGER || "github" };
    await lease.setState("intel_poll_status", status);
    lease.assertOwned();
    await store.pruneIntelEvidence();
    console.log(JSON.stringify(status));
    return status;
  } catch (error) {
    try {
      if (!statusLoaded) throw new Error("Previous intel status unavailable; preserve stored history");
      await lease.setState("intel_poll_status", { ...previous, ok: false, state: "failed",
        last_started_at: new Date(started).toISOString(), checked_at: new Date(now()).toISOString(),
        errors: [{ message: "Intel pipeline failed; see Actions logs" }] });
    } catch { console.error("Intel failure status not saved; lease or database unavailable"); }
    throw error;
  } finally { await lease.close(); }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  runIntel().then((status) => { if (status && !status.ok) process.exitCode = 1; }).catch(() => {
    console.error("Intel pipeline failed; check database connectivity, schema and Actions secrets.");
    process.exitCode = 1;
  });
}

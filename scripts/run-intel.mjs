import { configured, getServiceState, listIntelCandidates, pruneIntelEvidence, setState, upsertIntelEvidence } from "../lib/supabase.js";
import { runIntelPipeline } from "../lib/intel/pipeline.js";

async function main() {
  if (!configured("service")) throw new Error("Supabase service credentials are required");
  const stateRow = await getServiceState("intel_source_state");
  const candidates = await listIntelCandidates(500);
  const result = await runIntelPipeline({ state: stateRow?.value || {}, candidates,
    saveState: (state) => setState("intel_source_state", state), saveEvidence: upsertIntelEvidence });
  await setState("intel_poll_status", result.status);
  await pruneIntelEvidence();
  console.log(JSON.stringify(result.status));
  if (result.status.sources.some((source) => ["degraded", "auth_error", "cooldown"].includes(source.status))) process.exitCode = 1;
}

main().catch(() => {
  console.error("Intel pipeline failed; check database connectivity, schema and Actions secrets.");
  process.exitCode = 1;
});

import { configured, getState, listSourceRuns } from "../lib/supabase.js";
import { fetchDynamicLogList } from "../lib/ct/loglist.js";
import { compileSourceHealth } from "../lib/ct/source-health.js";

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

    response.status(200).json({
      storage_configured: configured(),
      ...healthSummary,
      source_runs: sourceRuns,
      updated_at: pollStatusRow?.updated_at || new Date().toISOString()
    });
  } catch (error) {
    response.status(500).json({ error: "source_status_failed", message: error.message });
  }
}

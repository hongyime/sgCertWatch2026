import { runCertStreamSource } from "./certstream.js";
import { runCrtShSource } from "./crtsh.js";
import { runDirectCtSource } from "./direct-logs.js";
import { fetchDynamicLogList } from "./loglist.js";
import { runStaticCtSource } from "./static/client.js";

async function runStaticCtSourceWrapper({ data, state = {} }) {
  const listResult = await fetchDynamicLogList();
  const staticLogs = listResult.selectedLogs.filter((l) => l.protocol === "static-ct-api");
  return runStaticCtSource({ staticLogs, state });
}

const SOURCE_ORDER = [
  { key: "certstream", label: "Live stream", run: runCertStreamSource },
  { key: "direct_ct", label: "Direct CT logs", run: runDirectCtSource },
  { key: "static_ct", label: "Static CT (Let's Encrypt)", run: runStaticCtSourceWrapper },
  { key: "crtsh", label: "crt.sh backup", run: runCrtShSource }
];

async function runSafely(definition, data, sourceState) {
  const startedAt = Date.now();
  try {
    return await definition.run({ data, state: sourceState[definition.key] || {} });
  } catch (error) {
    return {
      source: definition.key,
      label: definition.label,
      ok: false,
      entries: [],
      scanned_entries: 0,
      errors: [{ message: error.message }],
      duration_ms: Date.now() - startedAt,
      details: {},
      statePatch: null
    };
  }
}

async function runSources({ data, state = {} }) {
  return Promise.all(SOURCE_ORDER.map((definition) => runSafely(definition, data, state)));
}

function mergeSourceState(currentState, runs) {
  return runs.reduce((next, run) => {
    if (!run.statePatch) return next;
    return {
      ...next,
      ...run.statePatch
    };
  }, { ...currentState });
}

export {
  mergeSourceState,
  runSources
};

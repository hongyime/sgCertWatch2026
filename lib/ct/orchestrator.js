import { runCertStreamSource } from "./certstream.js";
import { runCrtShSource } from "./crtsh.js";
import { runDirectCtSource } from "./direct-logs.js";

const SOURCE_ORDER = [
  { key: "certstream", label: "Live stream", run: runCertStreamSource },
  { key: "direct_ct", label: "Direct CT logs", run: runDirectCtSource },
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

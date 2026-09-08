import { createHash } from "node:crypto";
import { attachIntelEvidence, findingHosts } from "./intel/evidence.js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

const PUBLIC_ENTRYPOINTS = ["findings.js", "source-status.js"];
const DB_TIMEOUT_MS = 8000;

function dbFetch(url, options = {}, timeoutMs = DB_TIMEOUT_MS) {
  const timeout = AbortSignal.timeout(timeoutMs);
  return fetch(url, { ...options, signal: options.signal ? AbortSignal.any([options.signal, timeout]) : timeout });
}

function configured(role = "anon") {
  if (role === "service") {
    return Boolean(SUPABASE_URL && SERVICE_KEY);
  }
  return Boolean(SUPABASE_URL && (ANON_KEY || SERVICE_KEY));
}

// Read-only, RLS-enforced. Safe for public endpoints.
function anonHeaders(extra = {}) {
  const key = ANON_KEY || SERVICE_KEY;
  if (!SUPABASE_URL || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_ANON_KEY are required");
  }
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json",
    ...extra
  };
}

// Bypasses RLS. ONLY for cron and triage. Never call from a public read path.
function serviceHeaders(extra = {}, stackOverride = null) {
  const stack = stackOverride ?? (new Error().stack || "");
  for (const entry of PUBLIC_ENTRYPOINTS) {
    if (stack.includes(entry)) {
      throw new Error(`Forbidden: serviceHeaders called from public entrypoint ${entry}`);
    }
  }
  if (!SUPABASE_URL || !SERVICE_KEY) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
  }
  return {
    apikey: SERVICE_KEY,
    Authorization: `Bearer ${SERVICE_KEY}`,
    "Content-Type": "application/json",
    ...extra
  };
}

async function upsertCtRows(table, rows, { assertOwned = () => {} } = {}) {
  if (!configured("service") || !rows.length) return [];
  const saved = [];
  for (let offset = 0; offset < rows.length; offset += 200) {
    assertOwned();
    const response = await dbFetch(`${SUPABASE_URL}/rest/v1/${table}`, {
      method: "POST",
      headers: serviceHeaders({ Prefer: "resolution=merge-duplicates,return=representation" }),
      body: JSON.stringify(rows.slice(offset, offset + 200))
    }, 30000);
    if (!response.ok) {
      throw new Error(`Supabase ${table} upsert failed: ${response.status} ${await response.text()}`);
    }
    const batch = await response.json();
    assertOwned();
    saved.push(...batch);
  }
  return saved;
}

async function upsertFindings(findings, options) {
  return upsertCtRows("findings", findings, options);
}

async function upsertFindingSources(sources, options) {
  return upsertCtRows("finding_sources", sources, options);
}

async function insertSourceRuns(runs) {
  if (!configured("service") || runs.length === 0) return [];

  const response = await dbFetch(`${SUPABASE_URL}/rest/v1/ct_source_runs`, {
    method: "POST",
    headers: serviceHeaders({ Prefer: "return=representation" }),
    body: JSON.stringify(runs)
  });

  if (!response.ok) {
    throw new Error(`Supabase source run insert failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

function boundedLimit(limit, fallback, maximum) {
  return Math.min(Math.max(Math.trunc(Number(limit)) || fallback, 1), maximum);
}

async function findingPage(limit, { watch = false, signal } = {}) {
  const url = new URL(`${SUPABASE_URL}/rest/v1/findings`);
  url.searchParams.set("select", "*");
  url.searchParams.set("suppressed", "eq.false");
  url.searchParams.set("order", watch ? "score.desc,observed_at.desc,id.asc" : "observed_at.desc");
  url.searchParams.set("limit", String(limit));
  if (watch) url.searchParams.set("score", "gte.60");

  const response = await dbFetch(url, { headers: anonHeaders(), signal });
  if (!response.ok) {
    throw new Error(`Supabase query failed: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function activeIntelEvidence(now, signal) {
  const evidence = [];
  const url = new URL(`${SUPABASE_URL}/rest/v1/intel_evidence`);
  url.searchParams.set("select", "*");
  url.searchParams.set("expires_at", `gt.${new Date(now).toISOString()}`);
  url.searchParams.set("order", "id.asc");
  url.searchParams.set("limit", "1000");
  for (let offset = 0; offset < 5000; offset += 1000) {
    url.searchParams.set("offset", String(offset));
    const response = await dbFetch(url, { headers: anonHeaders(), signal });
    if (!response.ok) {
      throw new Error(`Supabase intel query failed: ${response.status} ${await response.text()}`);
    }
    const rows = await response.json();
    evidence.push(...rows);
    if (rows.length < 1000) return evidence;
  }
  throw new Error("Active intel evidence exceeds the public query capacity");
}

function joinIntelEvidence(findings, evidence, now) {
  function inferredSource(finding) {
    if (finding.source?.name) return finding.source.name;
    if (String(finding.source?.cert_link || "").includes("crt.sh")) return "crtsh";
    if (String(finding.source?.cert_link || "").includes("/ct/v1/get-entries")) return "direct_ct";
    return null;
  }

  return findings.map((finding) => {
    const inferred = inferredSource(finding);
    const sourcesForFinding = inferred ? [inferred] : [];
    return attachIntelEvidence({
      ...finding,
      sources: sourcesForFinding,
      source_count: sourcesForFinding.length
    }, evidence, now);
  });
}

function priorityOrder(a, b) {
  return b.priority_score - a.priority_score
    || Date.parse(b.observed_at) - Date.parse(a.observed_at)
    || String(a.id).localeCompare(String(b.id));
}

async function listFindings(limit = 50, { view } = {}) {
  if (!configured("anon")) return [];
  const safeLimit = boundedLimit(limit, 50, 100);
  const now = Date.now();
  const signal = AbortSignal.timeout(8500);
  const [base, evidence] = await Promise.all([
    findingPage(safeLimit, { watch: view === "watch", signal }),
    activeIntelEvidence(now, signal)
  ]);
  if (view !== "watch") {
    return joinIntelEvidence(base, evidence, now);
  }

  const strongHosts = [...new Set(evidence.filter((row) => attachIntelEvidence({
    score: 60, domains: [row.domain]
  }, [row], now).intel_priority_boost > 0).flatMap((row) => findingHosts({ domains: [row.domain] })))];
  let promoted = [];
  if (strongHosts.length) {
    const response = await dbFetch(`${SUPABASE_URL}/rest/v1/rpc/intel_findings_for_hosts`, {
      method: "POST",
      headers: anonHeaders(),
      body: JSON.stringify({ hosts: strongHosts, result_limit: safeLimit }),
      signal
    });
    if (!response.ok) {
      throw new Error(`Supabase promoted findings query failed: ${response.status} ${await response.text()}`);
    }
    promoted = await response.json();
  }
  const candidates = [...new Map([...base, ...promoted].map((row) => [row.id, row])).values()];
  return joinIntelEvidence(candidates, evidence, now)
    .filter((row) => row.score >= 60 && row.priority_score >= 70).sort(priorityOrder).slice(0, safeLimit);
}

async function listIntelCandidates(limit = 500) {
  if (!configured("service")) return [];
  const response = await dbFetch(`${SUPABASE_URL}/rest/v1/rpc/intel_candidate_findings`, {
    method: "POST",
    headers: serviceHeaders(),
    body: JSON.stringify({ candidate_limit: boundedLimit(limit, 500, 1000) })
  });
  if (!response.ok) {
    throw new Error(`Supabase intel candidates query failed: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function upsertIntelEvidence(rows) {
  if (!configured("service") || !rows.length) return [];
  const evidence = rows.map((row) => ({
    ...row,
    id: createHash("sha256").update(`${row.source}|${row.domain}|${row.source_ref}`).digest("hex")
  }));
  const response = await dbFetch(`${SUPABASE_URL}/rest/v1/intel_evidence`, {
    method: "POST",
    headers: serviceHeaders({ Prefer: "resolution=merge-duplicates,return=representation" }),
    body: JSON.stringify(evidence)
  });
  if (!response.ok) {
    throw new Error(`Supabase intel upsert failed: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function pruneIntelEvidence() {
  if (!configured("service")) return [];
  const url = new URL(`${SUPABASE_URL}/rest/v1/intel_evidence`);
  url.searchParams.set("expires_at", `lte.${new Date().toISOString()}`);
  const response = await dbFetch(url, {
    method: "DELETE",
    headers: serviceHeaders({ Prefer: "return=representation" })
  });
  if (!response.ok) {
    throw new Error(`Supabase intel prune failed: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function listSourceRuns(limit = 24, source = null) {
  if (!configured("anon")) return [];

  const safeLimit = Math.min(Math.max(Number(limit) || 24, 1), 100);
  const url = new URL(`${SUPABASE_URL}/rest/v1/ct_source_runs`);
  url.searchParams.set("select", "*");
  url.searchParams.set("order", "checked_at.desc");
  url.searchParams.set("limit", String(safeLimit));
  if (Array.isArray(source) && source.length) {
    url.searchParams.set("source", `in.(${source.join(",")})`);
  } else if (source) {
    url.searchParams.set("source", `eq.${source}`);
  }

  const response = await dbFetch(url, { headers: anonHeaders() });
  if (!response.ok) {
    throw new Error(`Supabase source run query failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function readState(key, headers) {
  const url = new URL(`${SUPABASE_URL}/rest/v1/ingest_state`);
  url.searchParams.set("select", "value,updated_at");
  url.searchParams.set("key", `eq.${key}`);
  url.searchParams.set("limit", "1");

  const response = await dbFetch(url, { headers });
  if (!response.ok) {
    throw new Error(`Supabase state query failed: ${response.status} ${await response.text()}`);
  }

  const rows = await response.json();
  return rows[0] || null;
}

async function getState(key) {
  if (!configured("anon")) return null;
  return readState(key, anonHeaders());
}

async function getServiceState(key) {
  if (!configured("service")) return null;
  return readState(key, serviceHeaders());
}

async function listCtLogs() {
  if (!configured("anon")) return [];
  const url = new URL(`${SUPABASE_URL}/rest/v1/ct_logs`);
  url.searchParams.set("select", "*");
  url.searchParams.set("state", "in.(usable,qualified)");
  const response = await dbFetch(url, { headers: anonHeaders() });
  if (!response.ok) {
    throw new Error(`Supabase CT log query failed: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function setState(key, value) {
  if (!configured("service")) return null;

  const response = await dbFetch(`${SUPABASE_URL}/rest/v1/ingest_state`, {
    method: "POST",
    headers: serviceHeaders({ Prefer: "resolution=merge-duplicates,return=representation" }),
    body: JSON.stringify({
      key,
      value,
      updated_at: new Date().toISOString()
    })
  });

  if (!response.ok) {
    throw new Error(`Supabase state upsert failed: ${response.status} ${await response.text()}`);
  }

  const rows = await response.json();
  return rows[0] || null;
}

async function runLockRpc(name, lockName, ownerId, extra = {}) {
  if (!ownerId) throw new Error("Run lock owner ID is required");
  const response = await dbFetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: "POST", headers: serviceHeaders(),
    body: JSON.stringify({ lock_name: lockName, owner_id: ownerId, ...extra })
  });
  if (!response.ok) throw new Error(`Supabase run lease ${name} failed: HTTP ${response.status}`);
  const result = await response.json();
  if (typeof result !== "boolean") throw new Error("Invalid run lease response");
  return result;
}

async function tryAcquireRunLock(lockName, timeoutSeconds, ownerId) {
  return runLockRpc("acquire_run_lock", lockName, ownerId, { lease_seconds: timeoutSeconds });
}

async function renewRunLock(lockName, timeoutSeconds, ownerId) {
  return runLockRpc("renew_run_lock", lockName, ownerId, { lease_seconds: timeoutSeconds });
}

async function setRunState(lockName, ownerId, key, value) {
  if (!await runLockRpc("set_run_state", lockName, ownerId, { state_key: key, state_value: value })) {
    throw new Error("Run lease ownership lost; state write rejected");
  }
}

async function getRecentAlertRegistrables(hours = 72) {
  if (!configured("service")) return new Set();
  try {
    const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();
    const url = `${SUPABASE_URL}/rest/v1/alert_log?select=registrable&alerted_at=gte.${since}`;
    const resp = await dbFetch(url, { headers: serviceHeaders() });
    if (!resp.ok) return new Set();
    const rows = await resp.json();
    return new Set(rows.map((r) => r.registrable));
  } catch (_e) {
    return new Set();
  }
}

async function recordAlerts(registrables) {
  const list = [...new Set((registrables || []).filter(Boolean))];
  if (!configured("service") || !list.length) return;
  try {
    const url = `${SUPABASE_URL}/rest/v1/alert_log`;
    await dbFetch(url, {
      method: "POST",
      headers: serviceHeaders({ Prefer: "resolution=merge-duplicates" }),
      body: JSON.stringify(list.map((registrable) => ({ registrable, alerted_at: new Date().toISOString() })))
    });
  } catch (_e) {}
}

async function releaseRunLock(lockName, ownerId) {
  return runLockRpc("release_run_lock", lockName, ownerId);
}

export {
  anonHeaders,
  configured,
  getServiceState,
  getState,
  getRecentAlertRegistrables,
  insertSourceRuns,
  listCtLogs,
  listFindings,
  listIntelCandidates,
  listSourceRuns,
  pruneIntelEvidence,
  recordAlerts,
  releaseRunLock,
  renewRunLock,
  serviceHeaders,
  setState,
  setRunState,
  tryAcquireRunLock,
  upsertFindingSources,
  upsertFindings,
  upsertIntelEvidence
};

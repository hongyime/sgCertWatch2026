const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

const PUBLIC_ENTRYPOINTS = ["findings.js", "source-status.js"];

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

async function upsertFindings(findings) {
  if (!configured("service") || findings.length === 0) return [];

  const response = await fetch(`${SUPABASE_URL}/rest/v1/findings`, {
    method: "POST",
    headers: serviceHeaders({ Prefer: "resolution=merge-duplicates,return=representation" }),
    body: JSON.stringify(findings)
  });

  if (!response.ok) {
    throw new Error(`Supabase upsert failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function upsertFindingSources(sources) {
  if (!configured("service") || sources.length === 0) return [];

  const response = await fetch(`${SUPABASE_URL}/rest/v1/finding_sources`, {
    method: "POST",
    headers: serviceHeaders({ Prefer: "resolution=merge-duplicates,return=representation" }),
    body: JSON.stringify(sources)
  });

  if (!response.ok) {
    throw new Error(`Supabase source upsert failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function insertSourceRuns(runs) {
  if (!configured("service") || runs.length === 0) return [];

  const response = await fetch(`${SUPABASE_URL}/rest/v1/ct_source_runs`, {
    method: "POST",
    headers: serviceHeaders({ Prefer: "return=representation" }),
    body: JSON.stringify(runs)
  });

  if (!response.ok) {
    throw new Error(`Supabase source run insert failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function listFindings(limit = 50) {
  if (!configured("anon")) return [];

  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
  const url = new URL(`${SUPABASE_URL}/rest/v1/findings`);
  url.searchParams.set("select", "*");
  url.searchParams.set("suppressed", "eq.false");
  url.searchParams.set("order", "observed_at.desc");
  url.searchParams.set("limit", String(safeLimit));

  const response = await fetch(url, { headers: anonHeaders() });
  if (!response.ok) {
    throw new Error(`Supabase query failed: ${response.status} ${await response.text()}`);
  }

  const findings = await response.json();
  if (!findings.length) return findings;

  function inferredSource(finding) {
    if (finding.source?.name) return finding.source.name;
    if (String(finding.source?.cert_link || "").includes("crt.sh")) return "crtsh";
    if (String(finding.source?.cert_link || "").includes("/ct/v1/get-entries")) return "direct_ct";
    return null;
  }

  return findings.map((finding) => {
    const inferred = inferredSource(finding);
    const sourcesForFinding = inferred ? [inferred] : [];
    return {
      ...finding,
      sources: sourcesForFinding,
      source_count: sourcesForFinding.length
    };
  });
}

async function listSourceRuns(limit = 24) {
  if (!configured("anon")) return [];

  const safeLimit = Math.min(Math.max(Number(limit) || 24, 1), 100);
  const url = new URL(`${SUPABASE_URL}/rest/v1/ct_source_runs`);
  url.searchParams.set("select", "*");
  url.searchParams.set("order", "checked_at.desc");
  url.searchParams.set("limit", String(safeLimit));

  const response = await fetch(url, { headers: anonHeaders() });
  if (!response.ok) {
    throw new Error(`Supabase source run query failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function getState(key) {
  if (!configured("anon")) return null;

  const url = new URL(`${SUPABASE_URL}/rest/v1/ingest_state`);
  url.searchParams.set("select", "value,updated_at");
  url.searchParams.set("key", `eq.${key}`);
  url.searchParams.set("limit", "1");

  const response = await fetch(url, { headers: anonHeaders() });
  if (!response.ok) {
    throw new Error(`Supabase state query failed: ${response.status} ${await response.text()}`);
  }

  const rows = await response.json();
  return rows[0] || null;
}

async function setState(key, value) {
  if (!configured("service")) return null;

  const response = await fetch(`${SUPABASE_URL}/rest/v1/ingest_state`, {
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

async function tryAcquireRunLock(lockName = "ct_poll_run", timeoutSeconds = 300) {
  if (!configured("service")) return true; // Safe in dev / test mode

  // Fallback state-based lock in ingest_state table
  try {
    const existing = await getState(`lock_${lockName}`);
    const now = Date.now();
    if (existing?.value?.locked_until && existing.value.locked_until > now) {
      return false;
    }
    await setState(`lock_${lockName}`, {
      locked_at: now,
      locked_until: now + timeoutSeconds * 1000
    });
    return true;
  } catch (_e) {
    return true;
  }
}

async function getRecentAlertRegistrables(hours = 72) {
  if (!configured("service")) return new Set();
  try {
    const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();
    const url = `${SUPABASE_URL}/rest/v1/alert_log?select=registrable&alerted_at=gte.${since}`;
    const resp = await fetch(url, { headers: serviceHeaders() });
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
    await fetch(url, {
      method: "POST",
      headers: serviceHeaders({ Prefer: "resolution=merge-duplicates" }),
      body: JSON.stringify(list.map((registrable) => ({ registrable, alerted_at: new Date().toISOString() })))
    });
  } catch (_e) {}
}

async function releaseRunLock(lockName = "ct_poll_run") {
  if (!configured("service")) return;
  try {
    await setState(`lock_${lockName}`, { locked_until: 0 });
  } catch (_e) {}
}

export {
  anonHeaders,
  configured,
  getState,
  getRecentAlertRegistrables,
  insertSourceRuns,
  listFindings,
  listSourceRuns,
  recordAlerts,
  releaseRunLock,
  serviceHeaders,
  setState,
  tryAcquireRunLock,
  upsertFindingSources,
  upsertFindings
};

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function configured() {
  return Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
}

function headers(extra = {}) {
  return {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
    ...extra
  };
}

async function upsertFindings(findings) {
  if (!configured() || findings.length === 0) return [];

  const response = await fetch(`${SUPABASE_URL}/rest/v1/findings`, {
    method: "POST",
    headers: headers({ Prefer: "resolution=merge-duplicates,return=representation" }),
    body: JSON.stringify(findings)
  });

  if (!response.ok) {
    throw new Error(`Supabase upsert failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function listFindings(limit = 50) {
  if (!configured()) return [];

  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
  const url = new URL(`${SUPABASE_URL}/rest/v1/findings`);
  url.searchParams.set("select", "*");
  url.searchParams.set("suppressed", "eq.false");
  url.searchParams.set("order", "observed_at.desc");
  url.searchParams.set("limit", String(safeLimit));

  const response = await fetch(url, { headers: headers() });
  if (!response.ok) {
    throw new Error(`Supabase query failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function getState(key) {
  if (!configured()) return null;

  const url = new URL(`${SUPABASE_URL}/rest/v1/ingest_state`);
  url.searchParams.set("select", "value,updated_at");
  url.searchParams.set("key", `eq.${key}`);
  url.searchParams.set("limit", "1");

  const response = await fetch(url, { headers: headers() });
  if (!response.ok) {
    throw new Error(`Supabase state query failed: ${response.status} ${await response.text()}`);
  }

  const rows = await response.json();
  return rows[0] || null;
}

async function setState(key, value) {
  if (!configured()) return null;

  const response = await fetch(`${SUPABASE_URL}/rest/v1/ingest_state`, {
    method: "POST",
    headers: headers({ Prefer: "resolution=merge-duplicates,return=representation" }),
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

export {
  configured,
  getState,
  listFindings,
  setState,
  upsertFindings
};

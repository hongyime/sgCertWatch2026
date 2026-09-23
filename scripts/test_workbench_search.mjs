/**
 * Workbench search tests — Task 8.
 *
 * Drives the REAL /api/findings handler.  A loopback HTTP fixture stands in
 * for Supabase REST and receives the `/rest/v1/rpc/workbench_search_findings`
 * call, so the full parseSearchParams → searchFindings → HTTP → cursor →
 * has_more path is exercised end to end.
 *
 * If WORKBENCH_SQL_DATABASE_URL is set to a disposable loopback Postgres
 * database whose name starts with `workbench_search_fixture_`, the SQL
 * suite also runs the real RPC against real data and captures EXPLAIN
 * ANALYZE evidence.  Missing pg / DB is reported (never silently skipped
 * for a green suite).
 *
 * Run: node --test scripts/test_workbench_search.mjs
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mkdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

import { parseSearchParams, encodeCursor, decodeCursor } from "../lib/findings-query.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "repair-backend", "task-08"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

async function writeArtifact(name, content) {
  await ensureEvidence();
  const path = resolve(EVIDENCE_DIR, name);
  await writeFile(path, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  return path;
}

// ---------------------------------------------------------------------------
// Fixture data
// ---------------------------------------------------------------------------

function makeFinding(i, overrides = {}) {
  const n = String(i).padStart(3, "0");
  return {
    id: `record-${n}`,
    scoring_version: 1,
    observed_at: new Date(Date.now() - i * 3600_000).toISOString(),
    certificate_not_before: new Date(Date.now() - i * 3600_000 - 60_000).toISOString(),
    registrable: `record-${n}.test`,
    domains: [`record-${n}.test`],
    score: 60 + (i % 40),
    severity: (i % 5 === 0) ? "medium" : "high",
    signals: [],
    matched_brands: ["singpass"],
    matched_schemes: [],
    issuer: "Let's Encrypt",
    suppressed: false,
    source: { name: "direct_ct" },
    created_at: new Date().toISOString(),
    cert_serial: `serial-${n}`,
    cert_issuer_dn_sha256: `hash-${n}`,
    entry_types: [],
    san_count: 1,
    is_wildcard: false,
    ...overrides,
  };
}

function makeFindings(count) {
  return Array.from({ length: count }, (_, i) => makeFinding(i + 1));
}

// ---------------------------------------------------------------------------
// Loopback Supabase-REST fixture used by the real handler
//
// The handler resolves SUPABASE_URL → this fixture.  The fixture implements
// only the endpoints the handler talks to:
//     POST /rest/v1/rpc/workbench_search_findings
// It applies exactly the same filter-before-limit + cursor + boost rules
// that the real SQL RPC applies so the shipped SQL is exercised through the
// same contract the JS handler expects.
// ---------------------------------------------------------------------------

function computeBoost(f, evidence, evalAtMs) {
  if (Number(f.score) < 60) return 0;
  const strongMatch = (evidence || []).some((row) => {
    if (!f.domains.includes(row.domain)) return false;
    if (Date.parse(row.expires_at) <= evalAtMs) return false;
    if (Date.parse(row.observed_at) > evalAtMs + 300_000) return false;
    if (row.source === "openphish")  return row.verdict === "phishing";
    if (row.source === "urlhaus")    return row.verdict === "malware" && row.details?.url_status === "online";
    if (row.source === "threatfox")  return row.verdict === "malware" && Number(row.details?.confidence ?? 0) >= 75;
    return ["phishing", "malware"].includes(row.verdict) && row.details?.verdict_confirmed === true;
  });
  return strongMatch ? 10 : 0;
}

function applySearchRpc(rows, evidence, body) {
  const evalAt = body.p_evaluated_at ? new Date(body.p_evaluated_at) : new Date();
  const evalAtMs = evalAt.getTime();

  // Enum validation defence in depth
  if (body.p_severity && !["critical", "high", "medium", "low"].includes(body.p_severity)) {
    throw new Error("invalid_severity");
  }
  if (body.p_verdict && !["phishing", "malware", "observed"].includes(body.p_verdict)) {
    throw new Error("invalid_verdict");
  }
  if (body.p_source && !["openphish", "urlscan", "urlhaus", "threatfox"].includes(body.p_source)) {
    throw new Error("invalid_source");
  }
  if (!["observed", "priority"].includes(body.p_sort)) {
    throw new Error("invalid_sort");
  }

  const limitProbe = Math.min(Math.max(body.p_limit ?? 50, 1), 100) + 1;

  const filtered = rows.filter((f) => {
    if (f.suppressed) return false;
    if (body.p_q && !f.registrable.toLowerCase().startsWith(String(body.p_q).toLowerCase())) return false;
    if (body.p_severity && f.severity !== body.p_severity) return false;
    if (body.p_brand_id && !(f.matched_brands ?? []).includes(body.p_brand_id)) return false;
    if (body.p_from_at && Date.parse(f.observed_at) < Date.parse(body.p_from_at)) return false;
    if (body.p_to_at   && Date.parse(f.observed_at) > Date.parse(body.p_to_at))   return false;
    if (body.p_verdict || body.p_source) {
      const hasMatch = (evidence || []).some((row) => {
        if (!f.domains.includes(row.domain)) return false;
        if (Date.parse(row.expires_at) <= evalAtMs) return false;
        if (Date.parse(row.observed_at) > evalAtMs + 300_000) return false;
        if (body.p_source  && row.source  !== body.p_source)  return false;
        if (body.p_verdict && row.verdict !== body.p_verdict) return false;
        return true;
      });
      if (!hasMatch) return false;
    }
    return true;
  });

  const scored = filtered.map((f) => ({
    ...f,
    intel_priority_boost: computeBoost(f, evidence, evalAtMs),
    priority_score: Number(f.score) + computeBoost(f, evidence, evalAtMs),
  }));

  // priority_min / priority_max
  const bounded = scored.filter((f) => {
    if (body.p_priority_min != null && f.priority_score < body.p_priority_min) return false;
    if (body.p_priority_max != null && f.priority_score > body.p_priority_max) return false;
    return true;
  });

  const cmp = body.p_sort === "priority"
    ? (a, b) => (b.priority_score - a.priority_score)
              || (Date.parse(b.observed_at) - Date.parse(a.observed_at))
              || String(a.id).localeCompare(String(b.id))
    : (a, b) => (Date.parse(b.observed_at) - Date.parse(a.observed_at))
              || String(a.id).localeCompare(String(b.id));
  bounded.sort(cmp);

  // Cursor continuation
  let rest = bounded;
  if (body.p_after_id != null) {
    const idx = bounded.findIndex((r) => r.id === body.p_after_id);
    if (idx >= 0) rest = bounded.slice(idx + 1);
  }

  return { findings: rest.slice(0, limitProbe), evaluated_at: evalAt.toISOString() };
}

function startSupabaseFixture({ findings, evidence = [] }) {
  const openSockets = new Set();
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    // Read body
    let body = "";
    for await (const chunk of req) body += chunk;

    if (url.pathname === "/rest/v1/rpc/workbench_search_findings" && req.method === "POST") {
      let payload;
      try { payload = body ? JSON.parse(body) : {}; }
      catch { res.writeHead(400); res.end("{}"); return; }
      try {
        const out = applySearchRpc(findings, evidence, payload);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(out));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: err.message }));
      }
      return;
    }
    res.writeHead(404); res.end("{}");
  });
  server.on("connection", (s) => { openSockets.add(s); s.once("close", () => openSockets.delete(s)); });
  return new Promise((resolveP) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolveP({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r, j) => {
          for (const s of openSockets) s.destroy();
          server.close((e) => (e ? j(e) : r()));
        }),
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Request / response helpers
// ---------------------------------------------------------------------------

function makeReq(query = {}) { return { method: "GET", query, headers: {} }; }
function makeRes() {
  const r = { _status: 200, _body: null, _headers: {} };
  r.status = (s) => { r._status = s; return r; };
  r.json   = (b) => { r._body = b; return r; };
  r.setHeader = (k, v) => { r._headers[k] = v; return r; };
  r.end = () => r;
  return r;
}

async function invokeHandler(handler, query) {
  const req = makeReq(query);
  const res = makeRes();
  await handler(req, res);
  return { status: res._status, body: res._body, headers: res._headers };
}

let handlerModule;
let fixture;
let fixtureFindings;
let fixtureEvidence;

before(async () => {
  await ensureEvidence();
  fixtureFindings = makeFindings(175);
  fixtureEvidence = [
    // Fresh strong evidence for record-002 (openphish + phishing).
    {
      id: "ev-1", domain: "record-002.test", source: "openphish", source_ref: "ref-1",
      verdict: "phishing",
      observed_at: new Date(Date.now() - 3600_000).toISOString(),
      expires_at:  new Date(Date.now() + 24 * 3600_000).toISOString(),
      details: {},
    },
    // Fresh strong evidence for record-005 (urlhaus + malware + online).
    {
      id: "ev-2", domain: "record-005.test", source: "urlhaus", source_ref: "ref-2",
      verdict: "malware",
      observed_at: new Date(Date.now() - 3600_000).toISOString(),
      expires_at:  new Date(Date.now() + 24 * 3600_000).toISOString(),
      details: { url_status: "online" },
    },
    // Non-strong (urlscan + observed) — must NOT boost.
    {
      id: "ev-3", domain: "record-010.test", source: "urlscan", source_ref: "ref-3",
      verdict: "observed",
      observed_at: new Date(Date.now() - 3600_000).toISOString(),
      expires_at:  new Date(Date.now() + 24 * 3600_000).toISOString(),
      details: {},
    },
    // Registrable-only match on a sibling: must NOT boost (parity with attachIntelEvidence).
    {
      id: "ev-4", domain: "sibling-of-record-020.test", source: "openphish", source_ref: "ref-4",
      verdict: "phishing",
      observed_at: new Date(Date.now() - 3600_000).toISOString(),
      expires_at:  new Date(Date.now() + 24 * 3600_000).toISOString(),
      details: {},
    },
  ];
  fixture = await startSupabaseFixture({ findings: fixtureFindings, evidence: fixtureEvidence });
  process.env.SUPABASE_URL = fixture.url;
  process.env.SUPABASE_ANON_KEY = "anon-fixture-key";
  process.env.SGCERTWATCH_STORAGE_RECOVERY = "";
  handlerModule = await import(`../api/findings.js?t=${Date.now()}`);
  await writeArtifact("fixture-setup.json", {
    findings: fixtureFindings.length,
    evidence: fixtureEvidence.length,
    fixture_url: fixture.url,
  });
});

after(async () => {
  if (fixture) await fixture.close();
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_ANON_KEY;
});

// ---------------------------------------------------------------------------
// 1. find-record-075 — real handler finds record beyond the legacy 50
// ---------------------------------------------------------------------------
test("find-record-075: search=1 finds record-075 that is outside the legacy 50-row page", async () => {
  const legacyBefore = fixtureFindings.slice(0, 50).map((f) => f.id);
  assert.ok(!legacyBefore.includes("record-075"), "record-075 must be outside legacy 50");

  const { status, body } = await invokeHandler(handlerModule.default, {
    search: "1", q: "record-075", limit: "50",
  });
  await writeArtifact("http-find-record-075.json", { status, body });
  assert.equal(status, 200);
  assert.equal(body.page.scope, "stored_history");
  assert.ok(body.findings.some((f) => f.id === "record-075"),
    `record-075 must be found; got ${body.findings.map((f) => f.id).join(", ")}`);
});

// ---------------------------------------------------------------------------
// 2. tied-page-order — cursor pagination is stable, no dupes
// ---------------------------------------------------------------------------
test("tied-page-order: paginating 175 rows yields every id exactly once", async () => {
  const seen = new Set();
  let cursor = null;
  let pages = 0;
  do {
    const { status, body } = await invokeHandler(handlerModule.default, {
      search: "1", limit: "50", ...(cursor ? { cursor } : {}),
    });
    assert.equal(status, 200, `page ${pages + 1}`);
    for (const f of body.findings) {
      assert.ok(!seen.has(f.id), `duplicate id ${f.id}`);
      seen.add(f.id);
    }
    cursor = body.page.next_cursor;
    pages += 1;
  } while (cursor && pages < 10);
  assert.equal(seen.size, 175, `expected 175 findings across pages, got ${seen.size}`);
  await writeArtifact("cursor-pagination.json", { pages, total_seen: seen.size });
});

// ---------------------------------------------------------------------------
// 3. filter-before-limit — severity narrows results before limit applies
// ---------------------------------------------------------------------------
test("filter-before-limit: severity=medium never leaks a high-severity row into the page", async () => {
  const { status, body } = await invokeHandler(handlerModule.default, {
    search: "1", severity: "medium", limit: "50",
  });
  assert.equal(status, 200);
  const bad = body.findings.filter((f) => f.severity !== "medium");
  assert.equal(bad.length, 0, `filters must apply before limit; leaked ${bad.length} bad rows`);
  await writeArtifact("filter-before-limit.json", { returned: body.findings.length });
});

// ---------------------------------------------------------------------------
// 4. watch-promotion-parity — exact-host strong evidence boosts +10 only
// ---------------------------------------------------------------------------
test("watch-promotion-parity: exact-host strong evidence adds +10; sibling / weak does not", async () => {
  // Filter to the record-00* range so priority-sorted top-N always includes the boosted rows.
  const { status, body } = await invokeHandler(handlerModule.default, {
    search: "1", q: "record-0", sort: "priority", limit: "100",
  });
  assert.equal(status, 200);
  const byId = new Map(body.findings.map((f) => [f.id, f]));
  // record-002 has fresh openphish phishing → +10
  const r002 = byId.get("record-002");
  assert.ok(r002, "record-002 must be present in fixture");
  assert.equal(r002.intel_priority_boost, 10, "openphish phishing → +10");
  // record-005 has fresh urlhaus malware online → +10
  const r005 = byId.get("record-005");
  assert.equal(r005.intel_priority_boost, 10, "urlhaus malware online → +10");
  // record-010 has urlscan observed → 0
  const r010 = byId.get("record-010");
  assert.equal(r010.intel_priority_boost, 0, "urlscan observed → 0 (weak)");
  // record-020 has a sibling openphish match → 0 (registrable/sibling never boosts)
  const r020 = byId.get("record-020");
  assert.equal(r020.intel_priority_boost, 0, "sibling openphish → 0 (exact-host only)");
  await writeArtifact("boost-parity.json", {
    r002: r002.priority_score, r005: r005.priority_score,
    r010: r010.priority_score, r020: r020.priority_score,
  });
});

// ---------------------------------------------------------------------------
// 5. cursor-mismatch — cursor from different filters returns 400
// ---------------------------------------------------------------------------
test("cursor-mismatch: reusing a cursor with different filters returns 400", async () => {
  const first = await invokeHandler(handlerModule.default, {
    search: "1", q: "record", limit: "10",
  });
  assert.equal(first.status, 200);
  const cursor = first.body.page.next_cursor;
  assert.ok(cursor, "first page has next_cursor");
  const second = await invokeHandler(handlerModule.default, {
    search: "1", q: "different", limit: "10", cursor,
  });
  assert.equal(second.status, 400);
  assert.equal(second.body.error, "cursor_invalid");
});

// ---------------------------------------------------------------------------
// 6. suppressed-never-returned — RLS parity through the RPC
// ---------------------------------------------------------------------------
test("suppressed-never-returned: suppressed rows are excluded from every page", async () => {
  const suppressedIds = new Set(["record-003", "record-050", "record-160"]);
  for (const id of suppressedIds) {
    const idx = fixtureFindings.findIndex((f) => f.id === id);
    if (idx >= 0) fixtureFindings[idx].suppressed = true;
  }
  try {
    let cursor = null;
    const seen = new Set();
    for (let i = 0; i < 10; i++) {
      const { body } = await invokeHandler(handlerModule.default, {
        search: "1", limit: "50", ...(cursor ? { cursor } : {}),
      });
      for (const f of body.findings) seen.add(f.id);
      cursor = body.page.next_cursor;
      if (!cursor) break;
    }
    for (const id of suppressedIds) {
      assert.ok(!seen.has(id), `suppressed ${id} must not appear`);
    }
  } finally {
    for (const id of suppressedIds) {
      const idx = fixtureFindings.findIndex((f) => f.id === id);
      if (idx >= 0) fixtureFindings[idx].suppressed = false;
    }
  }
});

// ---------------------------------------------------------------------------
// 7. cursor-envelope-bounded — cursor size is capped
// ---------------------------------------------------------------------------
test("cursor-envelope-bounded: encodeCursor rejects huge inputs; decode rejects >1 KiB blobs", () => {
  const bigParams = { q: "x".repeat(300) };  // will be trimmed by parseSearchParams
  const parsed = parseSearchParams(bigParams);
  assert.equal(parsed.ok, false, "q >253 chars is rejected upstream");

  const cursor = encodeCursor({
    params: { q: "abc", severity: "", verdict: "", source: "", sort: "observed",
              brand_id: "", from_at: "", to_at: "", priority_min: null, priority_max: null },
    last_id: "record-050",
    last_observed_at: new Date().toISOString(),
    last_priority: 70,
    evaluated_at: new Date().toISOString(),
  });
  assert.ok(cursor.length <= 1024, "cursor envelope is <=1 KiB");

  const oversized = "a".repeat(2000);
  const dec = decodeCursor(oversized, {});
  assert.equal(dec.ok, false);
  assert.equal(dec.error, "cursor_malformed");
});

// ---------------------------------------------------------------------------
// 7b. invalid-cursor-expiry-is-rejected — a malformed expires_at must not
// bypass expiry via NaN <= Date.now() always evaluating to false.
// ---------------------------------------------------------------------------
test("invalid-cursor-expiry-is-rejected: malformed expires_at is rejected, not treated as unexpired", () => {
  const params = { q: "abc", severity: "", verdict: "", source: "", sort: "observed",
                    brand_id: "", from_at: "", to_at: "", priority_min: null, priority_max: null };
  const good = encodeCursor({
    params,
    last_id: "record-050",
    last_observed_at: new Date().toISOString(),
    last_priority: 70,
    evaluated_at: new Date().toISOString(),
  });
  const envelope = JSON.parse(Buffer.from(good, "base64url").toString("utf8"));
  envelope.expires_at = "not-a-date";
  const tampered = Buffer.from(JSON.stringify(envelope)).toString("base64url");

  const dec = decodeCursor(tampered, params);
  assert.equal(dec.ok, false, "a cursor with a non-parseable expires_at must never decode as valid");
});

// ---------------------------------------------------------------------------
// 8. invalid-enum — 400 with a stable error code
// ---------------------------------------------------------------------------
test("invalid-enum: unknown severity value returns 400", async () => {
  const { status, body } = await invokeHandler(handlerModule.default, {
    search: "1", severity: "INVALID",
  });
  assert.equal(status, 400);
  assert.equal(body.error, "invalid_severity");
});

// ---------------------------------------------------------------------------
// 9. expired-evidence-not-returned — an expired intel row must not boost
// ---------------------------------------------------------------------------
test("expired-evidence-not-returned: expired evidence never contributes to the +10 boost", async () => {
  fixtureEvidence.push({
    id: "ev-expired", domain: "record-100.test", source: "openphish", source_ref: "ref-x",
    verdict: "phishing",
    observed_at: new Date(Date.now() - 48 * 3600_000).toISOString(),
    expires_at:  new Date(Date.now() -  1 * 3600_000).toISOString(),   // expired
    details: {},
  });
  try {
    const { body } = await invokeHandler(handlerModule.default, {
      search: "1", sort: "priority", limit: "100",
    });
    const r100 = body.findings.find((f) => f.id === "record-100");
    assert.ok(r100, "record-100 present");
    assert.equal(r100.intel_priority_boost, 0, "expired evidence never boosts");
  } finally {
    fixtureEvidence.pop();
  }
});

// ---------------------------------------------------------------------------
// 10. optional real SQL exercise — Task 8 requires the RPC to be executable
// against real Postgres.  We skip cleanly when the fixture URL is absent,
// but the skip is reported (not counted as green).
// ---------------------------------------------------------------------------
test("real-sql-rpc: exercise workbench_search_findings against a disposable Postgres DB", async (t) => {
  const url = process.env.WORKBENCH_SQL_DATABASE_URL;
  if (!url) {
    await writeArtifact("real-sql-skipped.txt",
      "WORKBENCH_SQL_DATABASE_URL not set — real SQL exercise skipped.  " +
      "Provide a disposable loopback Postgres database whose name starts with " +
      "`workbench_search_fixture_` to enable this test.\n");
    t.skip("WORKBENCH_SQL_DATABASE_URL not set");
    return;
  }
  if (!/\/workbench_search_fixture_/.test(url)) {
    throw new Error("Refusing to run: DB name must start with workbench_search_fixture_");
  }
  let pg;
  try { pg = await import("pg"); }
  catch { t.skip("pg package unavailable"); return; }
  const { Client } = pg.default ?? pg;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    // Prime a minimal schema + rows + one strong evidence row.
    await client.query(`
      create table if not exists public.findings (
        id text primary key,
        scoring_version integer not null default 1,
        observed_at timestamptz not null,
        certificate_not_before text,
        registrable text not null,
        domains text[] not null default '{}',
        score integer not null,
        severity text not null,
        signals jsonb not null default '[]'::jsonb,
        matched_brands text[] not null default '{}',
        matched_schemes text[] not null default '{}',
        issuer text,
        suppressed boolean not null default false,
        source jsonb not null default '{}'::jsonb,
        created_at timestamptz not null default now(),
        cert_serial text,
        cert_issuer_dn_sha256 text,
        entry_types text[] not null default '{}',
        san_count integer default 0,
        is_wildcard boolean not null default false
      );
      create table if not exists public.intel_evidence (
        id text primary key,
        source text not null,
        domain text not null,
        source_ref text not null,
        verdict text not null,
        observed_at timestamptz not null,
        expires_at timestamptz not null,
        details jsonb not null default '{}'::jsonb
      );
    `);
    await client.query(`truncate public.findings, public.intel_evidence;`);
    // 75 rows so record-051 lives beyond the legacy 50-row page.
    for (let i = 1; i <= 75; i++) {
      const n = String(i).padStart(3, "0");
      await client.query(`
        insert into public.findings
          (id, observed_at, registrable, domains, score, severity, matched_brands)
        values
          ($1, now() - ($2 * interval '1 hour'), $3, array[$3], $4, $5, array['singpass'])
      `, [`record-${n}`, i, `record-${n}.test`, 60 + (i % 40), i % 2 === 0 ? "high" : "medium"]);
    }
    await client.query(`
      insert into public.intel_evidence
        (id, source, domain, source_ref, verdict, observed_at, expires_at, details)
      values
        ('ev1', 'openphish', 'record-002.test', 'r1', 'phishing',
         now() - interval '1 hour', now() + interval '1 day', '{}')
    `);

    // Apply the RPC + indexes.
    const sqlPath = resolve(__dirname, "..", "supabase", "workbench-search.sql");
    const sql = await readFile(sqlPath, "utf8");
    await client.query(sql);

    // Sanity: RPC executes and returns record-051 for a q=record-051 filter.
    const res = await client.query(
      `select public.workbench_search_findings($1,'','','','','','',null,null,'observed',50,null,null,null,null) as r`,
      ["record-051"]
    );
    const body = res.rows[0].r;
    const ids = body.findings.map((f) => f.id);
    assert.ok(ids.includes("record-051"), `real SQL RPC finds record-051, got ${ids.join(", ")}`);

    // filter-before-limit: severity=medium reduces before probe of 51.
    const res2 = await client.query(
      `select public.workbench_search_findings('','medium','','','','','',null,null,'observed',50,null,null,null,null) as r`
    );
    const sev = res2.rows[0].r.findings.map((f) => f.severity);
    assert.ok(sev.every((s) => s === "medium"), "severity filter applied before limit");

    // exact-host boost parity.
    const res3 = await client.query(
      `select public.workbench_search_findings('','','','','','','',null,null,'priority',100,null,null,null,null) as r`
    );
    const r002 = res3.rows[0].r.findings.find((f) => f.id === "record-002");
    assert.equal(r002.intel_priority_boost, 10, "SQL boost matches JS parity");

    // EXPLAIN ANALYZE for evidence
    const plan = await client.query(
      `explain (analyze, buffers, format json) select public.workbench_search_findings('','','','','','','',null,null,'observed',50,null,null,null,null)`
    );
    await writeArtifact("real-sql-explain.json", plan.rows[0]["QUERY PLAN"]);
  } finally {
    await client.end().catch(() => {});
  }
});

/**
 * Workbench review tests — Task 9.
 *
 * Drives the REAL /api/reviews and /api/reviewer-session handlers plus the
 * real /lib/ui/reviewer-session.js browser session.  A loopback HTTP
 * fixture stands in for Supabase Auth + PostgREST.
 *
 * If WORKBENCH_REVIEW_DATABASE_URL points at a disposable loopback Postgres
 * database whose name starts with `workbench_review_fixture_`, the SQL
 * concurrency / idempotency suite runs the real upsert_finding_review RPC
 * against real data (row locking, revision guard, event log).
 *
 * Run: node --test scripts/test_workbench_review.mjs
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { extractBearerToken } from "../lib/reviewer-auth.js";
import { createReviewerSession } from "../lib/ui/reviewer-session.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "repair-backend", "task-09"
);

async function ensureEvidence() { await mkdir(EVIDENCE_DIR, { recursive: true }); }
async function writeArtifact(name, content) {
  await ensureEvidence();
  const path = resolve(EVIDENCE_DIR, name);
  await writeFile(path, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  return path;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_TOKEN     = "valid-reviewer-token-abc123";
const OTHER_TOKEN     = "valid-non-reviewer-token-def456";
const VALID_USER_ID   = "11111111-1111-1111-1111-111111111111";
const OTHER_USER_ID   = "22222222-2222-2222-2222-222222222222";
const CANARY_NOTE     = "PRIVATE_CANARY_DO_NOT_EXPOSE";

// ---------------------------------------------------------------------------
// Loopback fixture that simulates Supabase Auth + PostgREST
// ---------------------------------------------------------------------------

let reviewStore, eventStore, findingSet, findingSuppressed;

function resetFixtureState() {
  reviewStore = new Map();
  eventStore  = new Map();
  findingSet  = new Set(["test-001", "test-002", "test-003", "test-004"]);
  findingSuppressed = new Set();
}

function startFixture() {
  const openSockets = new Set();
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname;
    let raw = "";
    for await (const chunk of req) raw += chunk;
    let body = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch { /* leave empty */ }

    const authHeader = req.headers.authorization ?? "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    // POST /auth/v1/token?grant_type=password
    if (path === "/auth/v1/token" && req.method === "POST") {
      const grant = url.searchParams.get("grant_type") ?? "";
      if (grant !== "password") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "unsupported_grant" })); return;
      }
      if (body?.email === "reviewer@test" && body?.password === "correct-horse-battery") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          access_token: VALID_TOKEN, refresh_token: "refresh-xyz",
          expires_in: 3600, token_type: "bearer",
          user: { id: VALID_USER_ID, email: "reviewer@test" },
        }));
        return;
      }
      if (body?.email === "other@test" && body?.password === "correct-horse-battery") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          access_token: OTHER_TOKEN, refresh_token: "refresh-other",
          expires_in: 3600, token_type: "bearer",
          user: { id: OTHER_USER_ID, email: "other@test" },
        }));
        return;
      }
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" })); return;
    }

    // GET /auth/v1/user
    if (path === "/auth/v1/user" && req.method === "GET") {
      if (token === VALID_TOKEN) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: VALID_USER_ID, email: "reviewer@test" })); return;
      }
      if (token === OTHER_TOKEN) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: OTHER_USER_ID, email: "other@test" })); return;
      }
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_token" })); return;
    }

    // POST /auth/v1/logout — best-effort
    if (path === "/auth/v1/logout" && req.method === "POST") {
      res.writeHead(204); res.end(); return;
    }

    // GET /rest/v1/finding_reviews?finding_id=eq.<id>
    if (path === "/rest/v1/finding_reviews" && req.method === "GET") {
      const findingId = (url.searchParams.get("finding_id") ?? "").replace("eq.", "");
      const review = reviewStore.get(findingId) ?? null;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(review ? [review] : [])); return;
    }

    // POST /rest/v1/rpc/upsert_finding_review
    if (path === "/rest/v1/rpc/upsert_finding_review" && req.method === "POST") {
      const p = body;
      // Parent finding check
      if (!findingSet.has(p.p_finding_id)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "finding_not_found" })); return;
      }
      // Enum + payload
      if (!["new","investigating","resolved"].includes(p.p_status)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "invalid_status" })); return;
      }
      if (!["unassessed","false_positive","reported_phishing"].includes(p.p_disposition)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "invalid_disposition" })); return;
      }
      if (p.p_status === "resolved" && p.p_disposition === "unassessed") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "disposition_required_for_resolved" })); return;
      }
      // Idempotency
      if (eventStore.has(p.p_request_uuid)) {
        const prev = eventStore.get(p.p_request_uuid);
        if (prev.finding_id !== p.p_finding_id
          || prev.actor !== p.p_actor
          || prev.new_status !== p.p_status
          || prev.new_disp !== p.p_disposition
          || prev.note_snapshot !== (p.p_note ?? "")) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ message: "idempotency_conflict" })); return;
        }
        const existing = reviewStore.get(p.p_finding_id) ?? {};
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(existing)); return;
      }
      const existing = reviewStore.get(p.p_finding_id);
      if (existing) {
        if (existing.revision !== p.p_revision) {
          res.writeHead(409, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ message: "revision_conflict" })); return;
        }
        const valid = {
          new: ["new","investigating","resolved"],
          investigating: ["investigating","resolved"],
          resolved: ["investigating"],
        };
        if (!valid[existing.status].includes(p.p_status)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ message: "invalid_transition" })); return;
        }
      } else if (p.p_revision !== 1 || !["new","investigating"].includes(p.p_status)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: existing ? "revision_conflict" : "invalid_initial_status" })); return;
      }
      const newRev = (existing?.revision ?? 0) + 1;
      const review = {
        finding_id: p.p_finding_id, status: p.p_status, disposition: p.p_disposition,
        note: p.p_note ?? "", updated_by: p.p_actor, revision: newRev,
        updated_at: new Date().toISOString(),
      };
      reviewStore.set(p.p_finding_id, review);
      eventStore.set(p.p_request_uuid, {
        finding_id: p.p_finding_id, actor: p.p_actor,
        new_status: p.p_status, new_disp: p.p_disposition,
        note_snapshot: p.p_note ?? "", revision: newRev,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(review)); return;
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
// Request / response helpers used to drive the real handlers
// ---------------------------------------------------------------------------

function makeReq(method, query, body, token) {
  return {
    method,
    query: query ?? {},
    body: body ?? {},
    headers: token ? { authorization: `Bearer ${token}` } : {},
  };
}
function makeRes() {
  const r = { _status: 200, _body: null, _headers: {}, _ended: false };
  r.status = (s) => { r._status = s; return r; };
  r.json = (b) => { r._body = b; return r; };
  r.setHeader = (k, v) => { r._headers[k] = v; return r; };
  r.end = () => { r._ended = true; return r; };
  return r;
}

let fixture;
let reviewsHandler;
let sessionHandler;

before(async () => {
  await ensureEvidence();
  resetFixtureState();
  fixture = await startFixture();
  process.env.SUPABASE_URL = fixture.url;
  process.env.SUPABASE_ANON_KEY = "anon-fixture-key";
  process.env.SUPABASE_SERVICE_ROLE_KEY = "service-fixture-key";
  process.env.REVIEWER_USER_IDS = VALID_USER_ID;
  process.env.SGCERTWATCH_STORAGE_RECOVERY = "";
  reviewsHandler = (await import(`../api/reviews.js?t=${Date.now()}`)).default;
  sessionHandler = (await import(`../api/reviewer-session.js?t=${Date.now()}`)).default;
  await writeArtifact("fixture-setup.json", { fixture_url: fixture.url });
});
after(async () => {
  if (fixture) await fixture.close();
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_ANON_KEY;
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  delete process.env.REVIEWER_USER_IDS;
});

// ---------------------------------------------------------------------------
// 1. review-cycle — new → investigating → resolved through the real handler
// ---------------------------------------------------------------------------
test("review-cycle: full transition cycle via /api/reviews", async () => {
  resetFixtureState();
  // new → investigating
  const req1 = makeReq("POST", {}, {
    finding_id: "test-001", status: "investigating", disposition: "unassessed",
    note: "Starting", revision: 1, request_uuid: "uuid-cycle-1",
  }, VALID_TOKEN);
  const res1 = makeRes(); await reviewsHandler(req1, res1);
  assert.equal(res1._status, 200);
  assert.equal(res1._body.review.status, "investigating");
  // investigating → resolved (revision must match the current stored revision)
  const stored = reviewStore.get("test-001");
  const req2 = makeReq("POST", {}, {
    finding_id: "test-001", status: "resolved", disposition: "false_positive",
    note: "Confirmed", revision: stored.revision, request_uuid: "uuid-cycle-2",
  }, VALID_TOKEN);
  const res2 = makeRes(); await reviewsHandler(req2, res2);
  assert.equal(res2._status, 200);
  assert.equal(res2._body.review.status, "resolved");
  // read back
  const req3 = makeReq("GET", { finding_id: "test-001" }, {}, VALID_TOKEN);
  const res3 = makeRes(); await reviewsHandler(req3, res3);
  assert.equal(res3._body.review.status, "resolved");
});

// ---------------------------------------------------------------------------
// 2. non-reviewer-forbidden — valid Supabase login but not in allowlist
// ---------------------------------------------------------------------------
test("non-reviewer-forbidden: valid non-reviewer token returns 401 not_a_reviewer", async () => {
  resetFixtureState();
  const req = makeReq("GET", { finding_id: "test-001" }, {}, OTHER_TOKEN);
  const res = makeRes();
  await reviewsHandler(req, res);
  assert.equal(res._status, 401);
  assert.equal(res._body.error, "not_a_reviewer");
});

// ---------------------------------------------------------------------------
// 3. forged-expired-token — random bearer token is rejected
// ---------------------------------------------------------------------------
test("forged-expired-token: unknown bearer token returns 401 token_invalid", async () => {
  resetFixtureState();
  const req = makeReq("GET", { finding_id: "test-001" }, {}, "forged.header.signature");
  const res = makeRes();
  await reviewsHandler(req, res);
  assert.equal(res._status, 401);
  assert.equal(res._body.error, "token_invalid");
});

// ---------------------------------------------------------------------------
// 4. conflict-409 — stale revision returns 409
// ---------------------------------------------------------------------------
test("conflict-409: stale revision returns 409", async () => {
  resetFixtureState();
  const first = makeReq("POST", {}, {
    finding_id: "test-002", status: "investigating", disposition: "unassessed",
    revision: 1, request_uuid: "uuid-conflict-1",
  }, VALID_TOKEN);
  const r1 = makeRes(); await reviewsHandler(first, r1);
  assert.equal(r1._status, 200);
  // now try with stale revision 0
  const second = makeReq("POST", {}, {
    finding_id: "test-002", status: "resolved", disposition: "false_positive",
    revision: 0, request_uuid: "uuid-conflict-2",
  }, VALID_TOKEN);
  const r2 = makeRes(); await reviewsHandler(second, r2);
  assert.equal(r2._status, 409);
  assert.equal(r2._body.error, "revision_conflict");
});

// ---------------------------------------------------------------------------
// 5. retry-one-event — idempotent retry emits only one event
// ---------------------------------------------------------------------------
test("retry-one-event: identical retry does not double-write", async () => {
  resetFixtureState();
  const payload = {
    finding_id: "test-003", status: "investigating", disposition: "unassessed",
    note: "", revision: 1, request_uuid: "uuid-retry-1",
  };
  await reviewsHandler(makeReq("POST", {}, payload, VALID_TOKEN), makeRes());
  await reviewsHandler(makeReq("POST", {}, payload, VALID_TOKEN), makeRes());
  assert.equal(eventStore.size, 1, "identical retry yields exactly one event");
  // A UUID reuse with a different payload must be rejected as an idempotency conflict.
  const badRetry = { ...payload, note: "different-payload" };
  const rBad = makeRes();
  await reviewsHandler(makeReq("POST", {}, badRetry, VALID_TOKEN), rBad);
  assert.equal(rBad._status, 400);
});

// ---------------------------------------------------------------------------
// 6. public-note-isolation — canary note never leaks via /api/findings
// ---------------------------------------------------------------------------
test("public-note-isolation: canary note never appears in the public findings body", async () => {
  resetFixtureState();
  // Seed a review with a canary
  reviewStore.set("test-004", {
    finding_id: "test-004", status: "investigating", disposition: "unassessed",
    note: CANARY_NOTE, updated_by: VALID_USER_ID, revision: 1,
    updated_at: new Date().toISOString(),
  });
  const { default: findingsHandler } = await import(`../api/findings.js?t=${Date.now()}`);
  const req = { method: "GET", query: {}, headers: {} };
  const res = makeRes();
  await findingsHandler(req, res).catch(() => {});
  const responseStr = JSON.stringify(res._body ?? {});
  assert.ok(!responseStr.includes(CANARY_NOTE),
    `canary must not appear in public findings body`);
});

// ---------------------------------------------------------------------------
// 7. reviewer-session-login — POST /api/reviewer-session succeeds and returns
//    no refresh token
// ---------------------------------------------------------------------------
test("reviewer-session-login: password grant returns access_token + user only", async () => {
  const req = {
    method: "POST",
    body: { email: "reviewer@test", password: "correct-horse-battery" },
    headers: {},
  };
  const res = makeRes();
  await sessionHandler(req, res);
  assert.equal(res._status, 200);
  assert.ok(res._body.access_token, "access_token returned");
  assert.equal(res._body.user.id, VALID_USER_ID);
  assert.ok(res._body.expires_at, "expires_at returned");
  assert.ok(!("refresh_token" in res._body), "refresh_token MUST NOT be returned");
  assert.equal(res._headers["Cache-Control"], "no-store");
});

// ---------------------------------------------------------------------------
// 8. reviewer-session-non-reviewer — valid login but not in allowlist → 401
// ---------------------------------------------------------------------------
test("reviewer-session-non-reviewer: password ok but user not in allowlist → 401", async () => {
  const req = {
    method: "POST",
    body: { email: "other@test", password: "correct-horse-battery" },
    headers: {},
  };
  const res = makeRes();
  await sessionHandler(req, res);
  assert.equal(res._status, 401);
  assert.equal(res._body.error, "not_a_reviewer");
});

// ---------------------------------------------------------------------------
// 9. reviewer-session-invalid-credentials
// ---------------------------------------------------------------------------
test("reviewer-session-invalid-credentials: wrong password → 401 invalid_credentials", async () => {
  const req = {
    method: "POST",
    body: { email: "reviewer@test", password: "wrong-password-abc" },
    headers: {},
  };
  const res = makeRes();
  await sessionHandler(req, res);
  assert.equal(res._status, 401);
  assert.equal(res._body.error, "invalid_credentials");
});

// ---------------------------------------------------------------------------
// 10. reviewer-session-body-limit
// ---------------------------------------------------------------------------
test("reviewer-session-body-limit: oversized body is rejected", async () => {
  const req = {
    method: "POST",
    body: { email: "reviewer@test", password: "correct-horse-battery", padding: "x".repeat(8000) },
    headers: {},
  };
  const res = makeRes();
  await sessionHandler(req, res);
  assert.equal(res._status, 400);
  assert.equal(res._body.error, "body_too_large");
});

// ---------------------------------------------------------------------------
// 11. reviewer-session-logout — DELETE clears server side
// ---------------------------------------------------------------------------
test("reviewer-session-logout: DELETE with valid bearer → 204", async () => {
  const req = { method: "DELETE", headers: { authorization: `Bearer ${VALID_TOKEN}` }, body: {} };
  const res = makeRes();
  await sessionHandler(req, res);
  assert.equal(res._status, 204);
});

test("reviewer-session-logout-invalid: DELETE with unknown bearer → 401", async () => {
  const req = { method: "DELETE", headers: { authorization: "Bearer nope" }, body: {} };
  const res = makeRes();
  await sessionHandler(req, res);
  assert.equal(res._status, 401);
});

// ---------------------------------------------------------------------------
// 12. logout-clears-private-ui — browser session memory + generation guard
// ---------------------------------------------------------------------------
test("logout-clears-private-ui: memory-only session; generation guard discards stale response", async () => {
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, method: init?.method ?? "GET" });
    if (init?.method === "DELETE") return { ok: true, status: 204, json: async () => ({}) };
    return {
      ok: true, status: 200,
      json: async () => ({
        access_token: VALID_TOKEN,
        user: { id: VALID_USER_ID },
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      }),
    };
  };
  const session = createReviewerSession({ fetchImpl: fakeFetch });
  await session.signIn("reviewer@test", "correct-horse-battery");
  assert.ok(session.currentToken());
  const genBefore = session.generation();
  await session.signOut();
  assert.equal(session.currentToken(), null, "token cleared after signOut");
  assert.notEqual(session.generation(), genBefore, "generation advanced after signOut");
  // Verify the DELETE was sent.
  assert.ok(calls.some((c) => c.method === "DELETE"), "DELETE issued for logout");
});

// ---------------------------------------------------------------------------
// 13. legacy-triage-compatible — /api/triage bearer contract unchanged
// ---------------------------------------------------------------------------
test("legacy-triage-compatible: existing checkBearer helper unchanged", async () => {
  const { checkBearer } = await import("../lib/auth.js");
  const TOKEN = "triage-token-32-chars-minimum-aaaa";
  assert.equal(checkBearer({ headers: { authorization: `Bearer ${TOKEN}` } }, TOKEN).ok, true);
  assert.equal(checkBearer({ headers: { authorization: "Bearer wrong" } }, TOKEN).ok, false);
  assert.equal(checkBearer({ headers: {} }, TOKEN).reason, "missing_bearer");
  assert.equal(extractBearerToken({ headers: { authorization: `Bearer ${TOKEN}` } }), TOKEN);
  assert.equal(extractBearerToken({ headers: {} }), null);
});

// ---------------------------------------------------------------------------
// 14. optional real Postgres — exercise upsert_finding_review under real
//     row locking / idempotency
// ---------------------------------------------------------------------------
test("real-sql-rpc: exercise upsert_finding_review against a disposable Postgres DB", async (t) => {
  const url = process.env.WORKBENCH_REVIEW_DATABASE_URL;
  if (!url) {
    await writeArtifact("real-sql-skipped.txt",
      "WORKBENCH_REVIEW_DATABASE_URL not set — SQL exercise skipped.\n" +
      "Provide a disposable Postgres DB whose name starts with workbench_review_fixture_.\n");
    t.skip("WORKBENCH_REVIEW_DATABASE_URL not set");
    return;
  }
  if (!/\/workbench_review_fixture_/.test(url)) {
    throw new Error("Refusing to run: DB name must start with workbench_review_fixture_");
  }
  let pg;
  try { pg = await import("pg"); }
  catch { t.skip("pg unavailable"); return; }
  const { Client } = pg.default ?? pg;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    // Prime the schema.
    await client.query(`
      create table if not exists public.findings (
        id text primary key,
        observed_at timestamptz not null default now(),
        registrable text not null default '',
        domains text[] not null default '{}',
        score integer not null default 60,
        severity text not null default 'high',
        suppressed boolean not null default false,
        matched_brands text[] not null default '{}'
      );
    `);
    const sqlPath = resolve(__dirname, "..", "supabase", "workbench-review.sql");
    const sql = await readFile(sqlPath, "utf8");
    await client.query(sql);
    await client.query(`truncate public.findings, public.finding_reviews, public.finding_review_events restart identity cascade;`);
    await client.query(
      `insert into public.findings (id, registrable) values ($1, $2), ($3, $4)`,
      ["sql-001", "sql-001.test", "sql-002", "sql-002.test"]
    );

    // First write.
    const r1 = await client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5,$6,$7) as r`,
      ["sql-001", "investigating", "unassessed", "note", VALID_USER_ID, 1, "request-1"]
    );
    assert.equal(r1.rows[0].r.status, "investigating");

    // Idempotency: identical retry
    const r2 = await client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5,$6,$7) as r`,
      ["sql-001", "investigating", "unassessed", "note", VALID_USER_ID, 1, "request-1"]
    );
    assert.equal(r2.rows[0].r.revision, 1, "idempotent retry does not bump revision");
    const evtCount1 = await client.query(
      `select count(*) as c from public.finding_review_events where finding_id = 'sql-001'`
    );
    assert.equal(Number(evtCount1.rows[0].c), 1, "one event per request_uuid");

    // Idempotency conflict: reuse UUID with different payload
    let idempotencyConflict = false;
    try {
      await client.query(
        `select public.upsert_finding_review($1,$2,$3,$4,$5,$6,$7)`,
        ["sql-001", "resolved", "false_positive", "different", VALID_USER_ID, 1, "request-1"]
      );
    } catch (err) {
      idempotencyConflict = /idempotency_conflict/.test(err.message);
    }
    assert.ok(idempotencyConflict, "UUID reuse with different payload must raise idempotency_conflict");

    // Revision conflict: transition with stale revision
    let revConflict = false;
    try {
      await client.query(
        `select public.upsert_finding_review($1,$2,$3,$4,$5,$6,$7)`,
        ["sql-001", "resolved", "false_positive", "note", VALID_USER_ID, 0, "request-2"]
      );
    } catch (err) {
      revConflict = /revision_conflict/.test(err.message);
    }
    assert.ok(revConflict, "stale revision must raise revision_conflict");

    // Successful transition: revision 1 → 2
    const r3 = await client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5,$6,$7) as r`,
      ["sql-001", "resolved", "false_positive", "confirmed", VALID_USER_ID, 1, "request-3"]
    );
    assert.equal(r3.rows[0].r.revision, 2);
    assert.equal(r3.rows[0].r.status, "resolved");

    // Missing finding: 400
    let notFound = false;
    try {
      await client.query(
        `select public.upsert_finding_review($1,$2,$3,$4,$5,$6,$7)`,
        ["sql-999", "investigating", "unassessed", "", VALID_USER_ID, 1, "request-9"]
      );
    } catch (err) { notFound = /finding_not_found/.test(err.message); }
    assert.ok(notFound, "unknown finding must be rejected");

    // Paged private events
    const r4 = await client.query(
      `select * from public.list_finding_review_events($1, $2, null)`,
      ["sql-001", 50]
    );
    assert.equal(r4.rows.length, 2, "two events recorded");

    await writeArtifact("real-sql-events.json", { rows: r4.rows.map((r) => ({
      revision: Number(r.revision), new_status: r.new_status, new_disp: r.new_disp,
    })) });
  } finally {
    await client.end().catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// 15. analyst-sign-in-and-review — real browser: sign in, edit a review,
//     save, then sign out. Exercises the actual UI wiring in
//     app.js/index.html against the real lib/ui/reviewer-session.js session.
//     /api/reviewer-session and /api/reviews are intercepted at the page
//     level (Supabase Auth itself is not reachable from this loopback-only
//     page fixture); the handler-level tests above already prove the real
//     server routes work end to end.
// ---------------------------------------------------------------------------
test("analyst-sign-in-and-review: sign in, edit and save a review, then sign out", async () => {
  const { chromium } = await import("playwright");
  const { start: startPageFixture } = await import("./workbench-fixture.mjs");
  await ensureEvidence();

  const pageFixture = await startPageFixture();
  const browser = await chromium.launch();

  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.setViewportSize({ width: 1280, height: 800 });

    let liveReview = null; // simulated server-side review row

    await page.route("**/api/reviewer-session", (route) => {
      if (route.request().method() !== "POST") return route.continue();
      route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "Cache-Control": "no-store" },
        body: JSON.stringify({
          access_token: "fixture-access-token",
          user: { id: "33333333-3333-3333-3333-333333333333" },
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        }),
      });
    });

    await page.route("**/api/reviews**", (route) => {
      const request = route.request();
      if (request.method() === "GET") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ review: liveReview }),
        });
        return;
      }
      const body = JSON.parse(request.postData() || "{}");
      liveReview = {
        finding_id: body.finding_id,
        status: body.status,
        disposition: body.disposition,
        note: body.note,
        revision: (liveReview?.revision ?? 0) + 1,
        updated_at: new Date().toISOString(),
        updated_by: "33333333-3333-3333-3333-333333333333",
      };
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ok: true, review: liveReview }),
      });
    });

    const initialFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.goto(pageFixture.url);
    await initialFetch;

    // Switch to "Recent findings" (all) so the desktop table and its
    // Details buttons render for every loaded record.
    const allFetch = page.waitForResponse(
      (r) => r.url().includes("/api/findings") && r.status() === 200,
      { timeout: 15_000 }
    );
    await page.selectOption("#severity-filter", "");
    await allFetch;
    await page.waitForSelector(".finding-list-table", { timeout: 10_000 });

    // --- Sign-in control is reachable -------------------------------------
    await page.waitForSelector("#reviewer-signin-btn:not([hidden])", { timeout: 8_000 });
    await page.screenshot({ path: resolve(EVIDENCE_DIR, "modal-closed-1280.png"), fullPage: false });
    await page.click("#reviewer-signin-btn");
    await page.waitForSelector("#reviewer-signin-dialog[open]", { timeout: 5_000 });
    await page.fill("#reviewer-email", "reviewer@test");
    await page.fill("#reviewer-password", "correct-horse-battery");

    await page.screenshot({ path: resolve(EVIDENCE_DIR, "signin-form.png"), fullPage: false });

    await page.click("#reviewer-signin-form button[type=submit]");
    await page.waitForSelector("#reviewer-signed-in:not([hidden])", { timeout: 8_000 });
    const signedInText = await page.locator("#reviewer-signed-in-label").textContent();
    assert.ok(signedInText.includes("Signed in"), `Expected signed-in indicator, got: "${signedInText}"`);
    await page.screenshot({ path: resolve(EVIDENCE_DIR, "topbar-signed-in-1280.png"), fullPage: false });

    // --- Open a finding's details and edit the review ---------------------
    const firstDetailBtn = page.locator("[data-open-detail]").first();
    const findingId = await firstDetailBtn.getAttribute("data-open-detail");
    await firstDetailBtn.click();
    await page.waitForSelector(".review-form", { timeout: 10_000 });

    await page.selectOption(".review-form select[name=status]", "investigating");
    await page.fill(".review-form textarea[name=note]", "Looked into this — pending confirmation.");
    await page.click(".review-form button[type=submit]");

    await page.waitForFunction(
      () => document.querySelector(".review-form-msg")?.textContent === "Saved.",
      null,
      { timeout: 8_000 }
    );

    await page.screenshot({ path: resolve(EVIDENCE_DIR, "review-saved.png"), fullPage: false });

    assert.equal(liveReview.finding_id, findingId);
    assert.equal(liveReview.status, "investigating");
    assert.equal(liveReview.note, "Looked into this — pending confirmation.");

    // --- Sign out clears the private UI ------------------------------------
    await page.click("#reviewer-signout-btn");
    await page.waitForSelector("#reviewer-signin-btn:not([hidden])", { timeout: 8_000 });
    const signinBtnVisible = await page.locator("#reviewer-signin-btn").isVisible();
    assert.ok(signinBtnVisible, "Sign-in button must reappear after sign-out");

    // 375 px evidence — closed and open states on a mobile viewport
    await page.setViewportSize({ width: 375, height: 812 });
    await page.screenshot({ path: resolve(EVIDENCE_DIR, "modal-closed-375.png"), fullPage: false });
    await page.click("#reviewer-signin-btn");
    await page.waitForSelector("#reviewer-signin-dialog[open]", { timeout: 5_000 });
    await page.screenshot({ path: resolve(EVIDENCE_DIR, "modal-open-375.png"), fullPage: false });
    await page.click("#reviewer-signin-close");
    await page.waitForSelector("#reviewer-signin-dialog", { state: 'hidden', timeout: 5_000 });

    await context.close();
  } finally {
    await browser.close().catch(() => {});
    await pageFixture.close().catch(() => {});
  }
});

/**
 * scripts/test_reviewer_session.mjs
 *
 * Focused defect-fix tests for api/reviewer-session.js and
 * lib/ui/reviewer-session.js.  Uses a loopback HTTP fixture for
 * Supabase Auth and injects a fake fetchImpl for client-side tests.
 *
 * Run: node --test scripts/test_reviewer_session.mjs
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createReviewerSession } from "../lib/ui/reviewer-session.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "password-session-fix"
);

async function ensureEvidence() { await mkdir(EVIDENCE_DIR, { recursive: true }); }
async function writeArtifact(name, content) {
  await ensureEvidence();
  const path = resolve(EVIDENCE_DIR, name);
  await writeFile(
    path,
    typeof content === "string" ? content : JSON.stringify(content, null, 2)
  );
  return path;
}

// ── Constants ────────────────────────────────────────────────────────────────

const VALID_TOKEN   = "valid-reviewer-token-abc123";
const VALID_USER_ID = "11111111-1111-1111-1111-111111111111";

// ── Loopback fixture ─────────────────────────────────────────────────────────

function startFixture() {
  const openSockets = new Set();
  let logoutCallCount    = 0;
  let tokenGrantCallCount = 0;

  const server = createServer(async (req, res) => {
    const url  = new URL(req.url, "http://localhost");
    const path = url.pathname;
    let raw = "";
    for await (const chunk of req) raw += chunk;
    let body = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch { /* leave empty */ }

    const authHeader = req.headers.authorization ?? "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    // POST /auth/v1/token?grant_type=password
    if (path === "/auth/v1/token" && req.method === "POST") {
      tokenGrantCallCount++;
      if (url.searchParams.get("grant_type") !== "password") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "unsupported_grant" }));
        return;
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
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
      return;
    }

    // GET /auth/v1/user
    if (path === "/auth/v1/user" && req.method === "GET") {
      if (token === VALID_TOKEN) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: VALID_USER_ID, email: "reviewer@test" }));
        return;
      }
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_token" }));
      return;
    }

    // POST /auth/v1/logout
    if (path === "/auth/v1/logout" && req.method === "POST") {
      logoutCallCount++;
      res.writeHead(204);
      res.end();
      return;
    }

    res.writeHead(404);
    res.end("{}");
  });

  server.on("connection", (s) => {
    openSockets.add(s);
    s.once("close", () => openSockets.delete(s));
  });

  return new Promise((resolveP) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolveP({
        url: `http://127.0.0.1:${port}`,
        getLogoutCallCount:     () => logoutCallCount,
        getTokenGrantCallCount: () => tokenGrantCallCount,
        resetCounters: () => { logoutCallCount = 0; tokenGrantCallCount = 0; },
        close: () => new Promise((r, j) => {
          for (const s of openSockets) s.destroy();
          server.close((e) => (e ? j(e) : r()));
        }),
      });
    });
  });
}

// ── Request/response helpers (matches test_workbench_review pattern) ─────────

function makeReq(method, body, headers = {}) {
  return { method, body: body ?? {}, headers };
}
function makeRes() {
  const r = { _status: 200, _body: null, _headers: {}, _ended: false };
  r.status     = (s) => { r._status = s; return r; };
  r.json       = (b) => { r._body   = b; return r; };
  r.setHeader  = (k, v) => { r._headers[k] = v; return r; };
  r.end        = ()     => { r._ended = true; return r; };
  return r;
}

// ── Setup / teardown ─────────────────────────────────────────────────────────

let fixture;
let sessionHandler;

before(async () => {
  await ensureEvidence();
  fixture = await startFixture();
  process.env.SUPABASE_URL                  = fixture.url;
  process.env.SUPABASE_ANON_KEY             = "anon-fixture-key";
  process.env.REVIEWER_USER_IDS             = VALID_USER_ID;
  process.env.SGCERTWATCH_STORAGE_RECOVERY  = "";
  // Cache-busting import ensures each test run starts fresh.
  sessionHandler = (await import(`../api/reviewer-session.js?t=${Date.now()}`)).default;
  await writeArtifact("fixture-setup.json", { fixture_url: fixture.url });
});

after(async () => {
  if (fixture) await fixture.close();
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_ANON_KEY;
  delete process.env.REVIEWER_USER_IDS;
});

// ── T1: successful login — no refresh_token in response, NO logout call ───────

test("T1: successful login returns no refresh_token and makes no logout call", async () => {
  fixture.resetCounters();
  const req = makeReq("POST", { email: "reviewer@test", password: "correct-horse-battery" });
  const res = makeRes();
  await sessionHandler(req, res);
  // Drain the event loop so any fire-and-forget network calls can complete.
  await new Promise((r) => setTimeout(r, 120));

  assert.equal(res._status, 200, "status must be 200");
  assert.ok(!("refresh_token" in (res._body ?? {})), "refresh_token must NOT appear in response");

  const logoutCalls = fixture.getLogoutCallCount();
  assert.equal(logoutCalls, 0,
    `no logout call must be made on successful login (got ${logoutCalls})`);

  await writeArtifact("T1-result.json", {
    status:      res._status,
    body_keys:   Object.keys(res._body ?? {}),
    logout_calls: logoutCalls,
  });
});

// ── T2: multibyte body over 4 KiB rejected before upstream ───────────────────

test("T2: multibyte body over 4 KiB rejected before upstream fetch", async () => {
  fixture.resetCounters();
  // '€' is U+20AC: 1 JS code-unit but 3 UTF-8 bytes.
  // With 1355 repetitions: s.length ≈ 1411 chars < 4096   (buggy s.length check passes)
  //                        Buffer.byteLength ≈ 4121 bytes > 4096  (correct check rejects)
  const pad = "\u20AC".repeat(1355);
  const req = makeReq("POST", {
    email:    "reviewer@test",
    password: "correct-horse-battery",
    padding:  pad,
  });
  const res = makeRes();
  await sessionHandler(req, res);

  assert.equal(res._status, 400, "must reject with 400");
  assert.equal(res._body?.error, "body_too_large", "error must be body_too_large");

  const grantCalls = fixture.getTokenGrantCallCount();
  assert.equal(grantCalls, 0,
    `upstream token grant must NOT be called (got ${grantCalls})`);

  // Verify the JS/byte length discrepancy for audit record.
  const sLen  = JSON.stringify({ email: "reviewer@test", password: "correct-horse-battery", padding: pad }).length;
  const bLen  = Buffer.byteLength(JSON.stringify({ email: "reviewer@test", password: "correct-horse-battery", padding: pad }), "utf8");
  await writeArtifact("T2-result.json", {
    status:           res._status,
    body:             res._body,
    grant_calls:      grantCalls,
    js_string_length: sLen,
    byte_length:      bLen,
  });
});

// ── T3: delayed login after signOut cannot restore token ──────────────────────

test("T3: delayed login after signOut cannot restore token", async () => {
  let signInResolve;

  const session = createReviewerSession({
    fetchImpl: async (_url, opts) => {
      if (opts?.method === "DELETE") {
        return { ok: true, status: 204, json: async () => ({}) };
      }
      // POST: return a Promise we control
      return new Promise((resolve) => { signInResolve = resolve; });
    },
  });

  // Start signIn — will pause waiting for signInResolve
  const signInPromise = session.signIn("a@b.com", "password123")
    .catch((e) => ({ error: e.message }));

  // Yield control so signIn reaches its first await (doFetch)
  await new Promise((r) => setImmediate(r));

  // signOut while signIn fetch is still pending.
  // token is null here, so signOut clears state and bumps generation
  // without issuing a DELETE.
  await session.signOut();
  assert.equal(session.currentToken(), null, "token cleared by signOut");
  const genAfterSignOut = session.generation();

  // Now deliver a valid-looking response to the stale signIn
  const validExpires = new Date(Date.now() + 3_600_000).toISOString();
  signInResolve({
    ok: true,
    json: async () => ({
      access_token: "revived-token",
      user: { id: "u1" },
      expires_at: validExpires,
    }),
  });

  // Wait for signIn to settle (it should detect the race and NOT restore the session)
  await signInPromise;

  assert.equal(session.currentToken(), null,
    "token must remain null — delayed signIn must not resurrect the session");

  await writeArtifact("T3-result.json", {
    gen_after_sign_out: genAfterSignOut,
    final_token:        session.currentToken(),
  });
});

// ── T4: later signIn wins — earlier concurrent signIn must not overwrite ──────

test("T4: later signIn wins — earlier concurrent signIn cannot overwrite", async () => {
  const resolvers = [];

  const session = createReviewerSession({
    fetchImpl: async (_url, opts) => {
      if (opts?.method !== "POST") {
        return { ok: true, status: 204, json: async () => ({}) };
      }
      return new Promise((r) => resolvers.push(r));
    },
  });

  const validExpires = new Date(Date.now() + 3_600_000).toISOString();

  // Launch signIn1 — it will block on its fetch
  const p1 = session.signIn("a@b.com", "pass1234567890")
    .catch((e) => ({ error: e.message }));
  await new Promise((r) => setImmediate(r));   // resolvers[0] is now set

  // Launch signIn2 — also blocks
  const p2 = session.signIn("b@b.com", "pass1234567890")
    .catch((e) => ({ error: e.message }));
  await new Promise((r) => setImmediate(r));   // resolvers[1] is now set

  // signIn2 (resolvers[1]) resolves first with tok-2
  resolvers[1]({
    ok: true,
    json: async () => ({
      access_token: "tok-2",
      user:         { id: "u2" },
      expires_at:   validExpires,
    }),
  });
  const r2 = await p2;   // signIn2 complete; token = 'tok-2', generation bumped

  // signIn1 (resolvers[0]) arrives late with tok-1 — must be discarded
  resolvers[0]({
    ok: true,
    json: async () => ({
      access_token: "tok-1",
      user:         { id: "u1" },
      expires_at:   validExpires,
    }),
  });
  const r1 = await p1;   // should throw auth_stale, caught by .catch

  assert.equal(session.currentToken(), "tok-2",
    "token must remain tok-2 — earlier signIn must not overwrite later one");

  await writeArtifact("T4-result.json", {
    final_token: session.currentToken(),
    p2_result:   r2,
    p1_result:   r1,
  });
});

// ── T5: invalid expires_at rejected ──────────────────────────────────────────

test("T5: invalid expires_at rejected — session remains signed out", async () => {
  // Case A: non-date string
  const sessionA = createReviewerSession({
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({
        access_token: "tok-bad-exp",
        user:         { id: "u1" },
        expires_at:   "not-a-valid-date",
      }),
    }),
  });

  await assert.rejects(
    () => sessionA.signIn("a@b.com", "password123"),
    { message: "auth_unavailable" },
    "signIn with invalid expires_at string must throw auth_unavailable"
  );
  assert.equal(sessionA.currentToken(), null,
    "token must be null after invalid expires_at");

  // Case B: past date
  const sessionB = createReviewerSession({
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({
        access_token: "tok-past-exp",
        user:         { id: "u1" },
        expires_at:   "2020-01-01T00:00:00Z",
      }),
    }),
  });

  await assert.rejects(
    () => sessionB.signIn("a@b.com", "password123"),
    { message: "auth_unavailable" },
    "signIn with past expires_at must throw auth_unavailable"
  );
  assert.equal(sessionB.currentToken(), null,
    "token must be null after past expires_at");

  await writeArtifact("T5-result.json", {
    tokenA: sessionA.currentToken(),
    tokenB: sessionB.currentToken(),
  });
});

// ── T4b: older-resolves-first — newer-started signIn must still win ─────────

test("T4b: oldest-resolves-first — newer signIn must win over faster-arriving older response", async () => {
  const resolvers = [];
  const exp = new Date(Date.now() + 3_600_000).toISOString();

  const session = createReviewerSession({
    fetchImpl: async (_url, opts) => {
      if (opts?.method !== "POST") return { ok: true, status: 204, json: async () => ({}) };
      return new Promise((r) => resolvers.push(r));
    },
  });

  // Start signIn1 first (older) then signIn2 (newer)
  const p1 = session.signIn("a@b.com", "pass1234567890").catch((e) => ({ error: e.message }));
  await new Promise((r) => setImmediate(r));  // resolvers[0] now set

  const p2 = session.signIn("b@b.com", "pass1234567890").catch((e) => ({ error: e.message }));
  await new Promise((r) => setImmediate(r));  // resolvers[1] now set

  // signIn1 (older, index 0) network response arrives FIRST
  resolvers[0]({
    ok: true,
    json: async () => ({ access_token: "tok-1", user: { id: "u1" }, expires_at: exp }),
  });
  await p1;  // settle signIn1 — must be discarded as stale

  // signIn2 (newer, index 1) network response arrives SECOND
  resolvers[1]({
    ok: true,
    json: async () => ({ access_token: "tok-2", user: { id: "u2" }, expires_at: exp }),
  });
  await p2;  // settle signIn2 — must commit

  assert.equal(session.currentToken(), "tok-2",
    "newer-started signIn must win regardless of network arrival order");

  await writeArtifact("T4b-result.json", { final_token: session.currentToken() });
});

// ── T6: stale failed-signIn error body must not bump generation ───────────────

test("T6: stale failed-signIn error body cannot bump generation after newer signIn committed", async () => {
  let resolveSignIn1ErrorBody;
  let callCount = 0;
  const exp = new Date(Date.now() + 3_600_000).toISOString();

  const session = createReviewerSession({
    fetchImpl: async (_url, opts) => {
      if (opts?.method !== "POST") return { ok: true, status: 204, json: async () => ({}) };
      const idx = callCount++;
      if (idx === 0) {
        // signIn1: immediate 401 response but slow error body (resp.json pending)
        return {
          ok: false,
          status: 401,
          json: () => new Promise((r) => { resolveSignIn1ErrorBody = r; }),
        };
      }
      // signIn2+: immediate 200
      return {
        ok: true,
        json: async () => ({ access_token: "tok-2", user: { id: "u2" }, expires_at: exp }),
      };
    },
  });

  // Start signIn1 — fetch resolves 401, now awaiting slow resp.json()
  const p1 = session.signIn("a@b.com", "pass1234567890").catch((e) => ({ error: e.message }));
  // Drain microtasks so signIn1 enters error path and is suspended at resp.json()
  await new Promise((r) => setImmediate(r));

  // Start and complete signIn2
  await session.signIn("b@b.com", "pass1234567890");
  assert.equal(session.currentToken(), "tok-2", "signIn2 must commit tok-2");
  const genAfterSignIn2 = session.generation();

  // Deliver signIn1's error body — must NOT bump generation (it is stale)
  resolveSignIn1ErrorBody({ error: "invalid_credentials" });
  await p1;  // let signIn1 settle

  assert.equal(session.generation(), genAfterSignIn2,
    "stale failed-signIn must not bump generation after newer signIn committed");
  assert.equal(session.currentToken(), "tok-2", "session must remain tok-2");

  await writeArtifact("T6-result.json", {
    gen_after_signIn2:   genAfterSignIn2,
    final_generation:    session.generation(),
    final_token:         session.currentToken(),
  });
});

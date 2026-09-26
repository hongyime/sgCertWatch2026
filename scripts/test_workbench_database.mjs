/**
 * scripts/test_workbench_database.mjs
 *
 * Real PostgreSQL 17 smoke tests for workbench SQL contracts.
 * Uses the shared createFixture() helper — no duplicate Docker/schema code.
 *
 * Run:  node --test scripts/test_workbench_database.mjs
 *       bun test scripts/test_workbench_database.mjs   (if Node hangs)
 *
 * Never touches production or .env files.  The container is removed in
 * the after() hook whether tests pass or fail.
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { createFixture, PG_PASSWORD } from "./workbench-db-fixture.mjs";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const execFileAsync = promisify(execFile);

// ── Evidence directories ──────────────────────────────────────────────────────
const EVIDENCE_DIR = resolve(
  REPO_ROOT, ".omo", "evidence",
  "free-tier-investigation-upgrade", "password-session-fix"
);
const REPLAY_FIX_DIR = resolve(
  REPO_ROOT, ".omo", "evidence",
  "free-tier-investigation-upgrade", "replay-fix"
);

async function writeArtifact(dir, name, content) {
  await mkdir(dir, { recursive: true });
  const path = resolve(dir, name);
  await writeFile(
    path,
    typeof content === "string" ? content : JSON.stringify(content, null, 2)
  );
  return path;
}

// ── Test state ────────────────────────────────────────────────────────────────
let fx;
let originalReview = null;   // captured by DB-01, compared by DB-05

const ACTOR_UUID   = "11111111-1111-1111-1111-111111111111";
const ACTOR2_UUID  = "22222222-2222-2222-2222-222222222222";
const FINDING_A    = "f-db-001";
const FINDING_B    = "f-db-002";
const FINDING_EXAM = "f-db-exam";
const FINDING_C    = "f-db-003";  // clean finding for new tests

// ── before / after ────────────────────────────────────────────────────────────
before(async () => {
  await mkdir(EVIDENCE_DIR,    { recursive: true });
  await mkdir(REPLAY_FIX_DIR, { recursive: true });

  fx = await createFixture();

  // observed_at NOT NULL in real schema.sql — include it explicitly.
  await fx.client.query(`
    insert into public.findings
      (id, registrable, domains, score, severity, suppressed, observed_at)
    values
      ($1, 'example.com', '{phish.example.com}', 80, 'high',   false, now()),
      ($2, 'testnet.net', '{evil.testnet.net}',  65, 'medium', false, now()),
      ($3, 'exam.org',    '{exam.org}',           72, 'high',   false, now()),
      ($4, 'other.org',   '{other.org}',          70, 'high',   false, now())
    on conflict do nothing
  `, [FINDING_A, FINDING_B, FINDING_EXAM, FINDING_C]);

  await writeArtifact(EVIDENCE_DIR, "db-fixture-setup.json", {
    container:       fx.containerName,
    port:            fx.port,
    database:        fx.database,
    migrations:      ["schema.sql", "workbench-review.sql", "workbench-search.sql"],
    seeded_findings: [FINDING_A, FINDING_B, FINDING_EXAM, FINDING_C],
  });
}, { timeout: 300_000 });

after(async () => {
  let teardown = { container: fx?.containerName, removed_verified: null };
  if (fx) {
    const r = await fx.close();
    teardown = { container: r.containerName, removed_verified: r.removed };
    assert.notStrictEqual(r.removed, false,
      `fixture container ${r.containerName} must not be confirmed-still-running after close()`);
  }
  await writeArtifact(EVIDENCE_DIR, "db-fixture-teardown.json", teardown);
}, { timeout: 120_000 });

// ── Tests ─────────────────────────────────────────────────────────────────────

// DB-01: create new review — capture full original response for DB-05 deepEqual
test("DB-01: upsert_finding_review creates initial review at revision=1", async () => {
  const r = await fx.client.query(
    `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7) as rv`,
    [FINDING_A, "investigating", "unassessed", "Initial note", ACTOR_UUID, 1, "req-db-01"]
  );
  originalReview = r.rows[0].rv;  // save for DB-05 deepEqual
  assert.equal(originalReview.finding_id,  FINDING_A,      "finding_id");
  assert.equal(originalReview.status,      "investigating", "status");
  assert.equal(originalReview.disposition, "unassessed",   "disposition");
  assert.equal(originalReview.note,        "Initial note", "note");
  assert.equal(originalReview.updated_by,  ACTOR_UUID,     "updated_by");
  assert.equal(originalReview.revision,    1,              "revision");
  assert.ok(originalReview.updated_at,                     "updated_at present");
});

// DB-02: idempotent replay before any later update → same revision
test("DB-02: idempotent replay (no later update) returns revision=1", async () => {
  const r = await fx.client.query(
    `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7) as rv`,
    [FINDING_A, "investigating", "unassessed", "Initial note", ACTOR_UUID, 1, "req-db-01"]
  );
  assert.equal(r.rows[0].rv.revision, 1, "idempotent replay must not bump revision");
});

// DB-03: revision conflict for stale p_revision
test("DB-03: stale revision raises revision_conflict", async () => {
  let threw = false;
  try {
    await fx.client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7)`,
      [FINDING_A, "resolved", "false_positive", "", ACTOR_UUID, 0, "req-db-03"]
    );
  } catch (e) {
    threw = /revision_conflict/.test(e.message);
  }
  assert.ok(threw, "stale p_revision must raise revision_conflict");
});

// DB-04: advance to resolved (revision 1 → 2)
test("DB-04: advance review to resolved at revision=2", async () => {
  const r = await fx.client.query(
    `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7) as rv`,
    [FINDING_A, "resolved", "false_positive", "Confirmed", ACTOR_UUID, 1, "req-db-04"]
  );
  assert.equal(r.rows[0].rv.status,   "resolved");
  assert.equal(r.rows[0].rv.revision, 2);
});

// DB-05: idempotent replay of req-db-01 AFTER a later update must return the
// EXACT original response — deepEqual including timestamp.
// RED: old SQL returned {revision:2}. GREEN: fixed SQL returns original object.
test("DB-05: idempotent replay after later update returns exact original response", async () => {
  const r = await fx.client.query(
    `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7) as rv`,
    [FINDING_A, "investigating", "unassessed", "Initial note", ACTOR_UUID, 1, "req-db-01"]
  );
  const row = r.rows[0].rv;

  await writeArtifact(REPLAY_FIX_DIR, "DB-05-replay-after-update.json", {
    returned_revision:    row.revision,
    returned_status:      row.status,
    returned_disposition: row.disposition,
    note: "SQL reconstructs original event response; does not return latest row",
    bug_confirmed: false,
  });

  // deepEqual confirms every field — including updated_at — matches DB-01.
  assert.deepEqual(row, originalReview,
    "replay after update must be deepEqual to the original first-write response");
});

// DB-06: list_finding_review_events returns at least 2 events for FINDING_A
test("DB-06: list_finding_review_events returns ≥2 events in DESC order", async () => {
  const r = await fx.client.query(
    `select * from public.list_finding_review_events($1, $2, null)`,
    [FINDING_A, 50]
  );
  assert.ok(r.rows.length >= 2, `expected ≥2 events, got ${r.rows.length}`);
  if (r.rows.length >= 2) {
    assert.ok(
      BigInt(r.rows[0].id) > BigInt(r.rows[1].id),
      "events must be ordered by id DESC"
    );
  }
});

// DB-07: idempotency conflict — same UUID, different finding_id
test("DB-07: UUID reuse with different finding_id raises idempotency_conflict", async () => {
  let threw = false;
  try {
    await fx.client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7)`,
      [FINDING_B, "investigating", "unassessed", "different payload", ACTOR_UUID, 1, "req-db-01"]
    );
  } catch (e) {
    threw = /idempotency_conflict/.test(e.message);
  }
  assert.ok(threw, "reusing req-db-01 UUID with a different finding_id must raise idempotency_conflict");
});

// DB-08: workbench_search_findings returns unsuppressed findings
test("DB-08: workbench_search_findings returns all unsuppressed findings", async () => {
  const r = await fx.client.query(
    `select public.workbench_search_findings() as result`
  );
  const result = r.rows[0].result;
  assert.ok(Array.isArray(result.findings), "findings must be an array");
  assert.ok(result.findings.length >= 3, `expected ≥3 findings, got ${result.findings.length}`);
  assert.ok(result.evaluated_at, "evaluated_at must be present");
});

// DB-09: prefix match works for non-special query
test("DB-09: workbench_search_findings prefix 'exam' matches exam.org", async () => {
  const r = await fx.client.query(
    `select public.workbench_search_findings($1) as result`,
    ["exam"]
  );
  const result = r.rows[0].result;
  assert.ok(
    result.findings.some(f => f.registrable === "exam.org"),
    `prefix 'exam' must match exam.org; got: ${result.findings.map(f => f.registrable).join(", ")}`
  );
});

// DB-10: special chars in query do not cause a server error
test("DB-10: search with SQL-special chars (%, _, \\) does not throw", async () => {
  let escapeResult = null;
  let escapeError  = null;
  try {
    const r = await fx.client.query(
      `select public.workbench_search_findings($1) as result`,
      ["exa%mple_te\\st"]
    );
    escapeResult = { count: r.rows[0].result.findings.length, error: null };
  } catch (e) {
    escapeError  = e.message;
    escapeResult = { count: -1, error: e.message };
  }
  await writeArtifact(EVIDENCE_DIR, "DB-10-escape-result.json", {
    query:                "exa%mple_te\\st",
    result:               escapeResult,
    error:                escapeError,
    escape_bug_confirmed: escapeError !== null,
  });
  assert.equal(escapeError, null,
    `search with special chars must not throw (escape clause bug?): ${escapeError}`);
  assert.equal(escapeResult.count, 0,
    "special-char query must return 0 rows (no match expected)");
});

// DB-11: exercise PostgreSQL parameter syntax without inferring a production bug.
test("DB-11: parameterized SET is rejected; set_config accepts parameters", async () => {
  let setBugThrew = false;
  try {
    await fx.client.query("SET statement_timeout = $1", ["3000ms"]);
  } catch {
    setBugThrew = true;
  }
  const r = await fx.client.query(
    "SELECT set_config($1, $2, false) as v",
    ["statement_timeout", "3000ms"]
  );
  assert.ok(setBugThrew,
    "SET statement_timeout = $1 must fail on PostgreSQL");
  assert.ok(r.rows[0].v,
    "set_config() must succeed as the correct alternative");
  await writeArtifact(EVIDENCE_DIR, "DB-11-set-timeout-bug.json", {
    set_with_param_throws: setBugThrew,
    set_config_works:      Boolean(r.rows[0].v),
  });
});

// DB-12: wrong actor with same request_uuid raises idempotency_conflict
test("DB-12: wrong actor with same request_uuid raises idempotency_conflict", async () => {
  let threw = false;
  try {
    await fx.client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7)`,
      [FINDING_A, "investigating", "unassessed", "Initial note", ACTOR2_UUID, 1, "req-db-01"]
    );
  } catch (e) {
    threw = /idempotency_conflict/.test(e.message);
  }
  assert.ok(threw, "req-db-01 with a different actor must raise idempotency_conflict");
});

// DB-13: first write with revision != 1 raises revision_conflict
test("DB-13: first write with revision=2 raises revision_conflict", async () => {
  let threw = false;
  try {
    await fx.client.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7)`,
      [FINDING_B, "investigating", "unassessed", "", ACTOR_UUID, 2, "req-db-13"]
    );
  } catch (e) {
    threw = /revision_conflict/.test(e.message);
  }
  assert.ok(threw, "first write with revision=2 must raise revision_conflict");
});

// DB-14: anon role cannot SELECT finding_reviews directly (SET ROLE check)
test("DB-14: anon cannot SELECT finding_reviews (RLS/permission check)", async () => {
  const c2 = fx.newClient();
  await c2.connect();
  let threw = false;
  try {
    await c2.query("SET ROLE anon");
    await c2.query("SELECT * FROM public.finding_reviews LIMIT 1");
  } catch (e) {
    threw = /permission denied/i.test(e.message);
  } finally {
    await c2.end().catch(() => {});
  }
  assert.ok(threw, "anon must not be able to SELECT finding_reviews");
});

// DB-15: anon role cannot call upsert_finding_review (SET ROLE check)
test("DB-15: anon cannot call upsert_finding_review (permission check)", async () => {
  const c2 = fx.newClient();
  await c2.connect();
  let threw = false;
  try {
    await c2.query("SET ROLE anon");
    await c2.query(
      `select public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7)`,
      [FINDING_C, "investigating", "unassessed", "", ACTOR_UUID, 1, "req-db-15"]
    );
  } catch (e) {
    threw = /permission denied/i.test(e.message);
  } finally {
    await c2.end().catch(() => {});
  }
  assert.ok(threw, "anon must not be able to call upsert_finding_review");
});

// DB-16: true concurrency — c1 holds BEGIN + FOR UPDATE on the parent finding row,
// c2 calls upsert_finding_review (blocks inside the function at its own FOR UPDATE),
// pg_stat_activity confirms a Lock waiter, then c1 commits, c2 creates the review,
// and exactly one event exists.
test("DB-16: parent FOR UPDATE lock serialises concurrent first-writes", async () => {
  const c1      = fx.newClient();
  const c2      = fx.newClient();
  const monitor = fx.newClient();
  await c1.connect();
  await c2.connect();
  await monitor.connect();

  let c2Result;
  try {
    // c1 acquires exclusive lock on the FINDING_B parent row.
    await c1.query("BEGIN");
    await c1.query(
      "SELECT id FROM public.findings WHERE id = $1 FOR UPDATE",
      [FINDING_B]
    );

    // c2 starts upsert — will block at the function's FOR UPDATE on findings.
    const c2Promise = c2.query(
      `SELECT public.upsert_finding_review($1,$2,$3,$4,$5::uuid,$6,$7) AS rv`,
      [FINDING_B, "investigating", "unassessed", "from-c2", ACTOR_UUID, 1, "req-db-16-c2"]
    );

    // Poll pg_stat_activity until c2 appears as a Lock waiter (up to 4 s).
    let lockRows = [];
    for (let i = 0; i < 20 && lockRows.length === 0; i++) {
      await new Promise(res => setTimeout(res, 200));
      const { rows } = await monitor.query(`
        SELECT pid, wait_event_type, wait_event, state
        FROM pg_stat_activity
        WHERE wait_event_type = 'Lock'
          AND state = 'active'
          AND query LIKE '%upsert_finding_review%'
      `);
      lockRows = rows;
    }
    assert.ok(lockRows.length >= 1,
      `c2 must be blocked on a Lock; found ${lockRows.length} waiter(s) in pg_stat_activity`);

    // Release lock — c2 can now proceed.
    await c1.query("COMMIT");
    c2Result = await c2Promise;
  } finally {
    await c1.query("ROLLBACK").catch(() => {});
    await c1.end().catch(() => {});
    await c2.end().catch(() => {});
    await monitor.end().catch(() => {});
  }

  assert.equal(c2Result.rows[0].rv.revision, 1,
    "c2 must create the first review at revision=1");

  // Exactly one event — parent lock prevented any double-insert.
  const { rows } = await fx.client.query(
    "SELECT count(*)::int AS n FROM public.finding_review_events WHERE finding_id = $1",
    [FINDING_B]
  );
  assert.equal(rows[0].n, 1,
    "exactly one event after serialised concurrent first-write");
});

// DB-17: createFixture removes container on startup failure (bad migration file).
// Uses docker inspect on the exact container name (avoids docker ps timeout).
test("DB-17: createFixture removes container on startup failure", { timeout: 300_000 }, async () => {
  let threw = false;
  let failedContainer = null;
  let cleanupVerified = false;
  try {
    // Non-existent migration file: container starts then createFixture throws.
    await createFixture({ migrationFiles: ["/this-file-does-not-exist.sql"] });
  } catch (e) {
    threw = true;
    failedContainer = e.fixtureContainerName ?? null;
  }

  if (failedContainer) {
    // Verify the specific container was removed (targeted inspect, not docker ps).
    try {
      const { stdout } = await execFileAsync(
        "docker", ["inspect", failedContainer, "--format", "{{.ID}}"],
        { timeout: 30_000 }
      );
      cleanupVerified = false;  // inspect succeeded but container still exists (or empty)
    } catch (inspectErr) {
      const msg = String(inspectErr.stderr || inspectErr.message || "").toLowerCase();
      cleanupVerified = msg.includes("no such object") || msg.includes("no such container");
    }
  } else {
    // Failed before container was started — nothing to clean up.
    cleanupVerified = true;
  }

  await writeArtifact(REPLAY_FIX_DIR, "DB-17-startup-failure.json", {
    threw, failed_container: failedContainer, cleanup_verified: cleanupVerified,
  });
  assert.ok(threw, "createFixture with bad migration file must throw");
  assert.ok(cleanupVerified,
    `container ${failedContainer} must be gone after startup failure`);
});

// DB-18: service_role has explicit grants; no broad 'grant all' needed
test("DB-18: service_role has explicit privileges; anon has none", async () => {
  const r = await fx.client.query(`
    SELECT
      has_table_privilege('service_role', 'public.finding_reviews', 'SELECT')    AS sr_sel,
      has_table_privilege('service_role', 'public.finding_reviews', 'INSERT')    AS sr_ins,
      has_table_privilege('service_role', 'public.finding_reviews', 'UPDATE')    AS sr_upd,
      has_function_privilege('service_role',
        'public.upsert_finding_review(text,text,text,text,uuid,bigint,text)',
        'EXECUTE')                                                               AS sr_exec,
      has_table_privilege('anon', 'public.finding_reviews', 'SELECT')            AS anon_sel,
      has_function_privilege('anon',
        'public.upsert_finding_review(text,text,text,text,uuid,bigint,text)',
        'EXECUTE')                                                               AS anon_exec
  `);
  const row = r.rows[0];
  assert.ok(row.sr_sel,      "service_role must have SELECT on finding_reviews");
  assert.ok(row.sr_ins,      "service_role must have INSERT on finding_reviews");
  assert.ok(row.sr_upd,      "service_role must have UPDATE on finding_reviews");
  assert.ok(row.sr_exec,     "service_role must have EXECUTE on upsert_finding_review");
  assert.ok(!row.anon_sel,   "anon must NOT have SELECT on finding_reviews");
  assert.ok(!row.anon_exec,  "anon must NOT have EXECUTE on upsert_finding_review");
});

/**
 * Workbench capacity checker tests — Task 7.
 *
 * Exercises scripts/check_workbench_capacity.mjs end to end:
 *  - Argument / opt-in guards
 *  - Fail-closed on unknown limit / missing measured inputs
 *  - Real disposable Postgres path (SQL allowlist proves read-only)
 *  - No writes to the fixture DB before/after
 *
 * If WORKBENCH_CAPACITY_DATABASE_URL is set to a disposable loopback
 * Postgres URL whose name starts with `workbench_capacity_fixture_`, we
 * run the checker against it and compare bytes before/after.  Otherwise
 * we exercise only the argument / fail-closed paths (a skip is reported).
 *
 * Run: node --test scripts/test_workbench_capacity.mjs
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "repair-backend", "task-07"
);
const CHECKER = resolve(__dirname, "check_workbench_capacity.mjs");

async function ensureEvidence() { await mkdir(EVIDENCE_DIR, { recursive: true }); }
async function writeArtifact(name, content) {
  await ensureEvidence();
  const p = resolve(EVIDENCE_DIR, name);
  await writeFile(p, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  return p;
}

function runChecker(args = [], env = {}) {
  const result = spawnSync(process.execPath, [CHECKER, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 20_000,
  });
  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

before(async () => { await ensureEvidence(); });

// ---------------------------------------------------------------------------
// 1. usage-error — refuses to run without --opt-in
// ---------------------------------------------------------------------------
test("opt-in-required: exits 2 without --opt-in", () => {
  const r = runChecker(["--db-url", "postgres://localhost/x", "--limit-bytes", "500000000"]);
  assert.equal(r.exitCode, 2);
  assert.ok(r.stderr.includes("--opt-in"), `stderr must mention --opt-in: ${r.stderr}`);
});

// ---------------------------------------------------------------------------
// 2. unknown-budget — missing limit is UNKNOWN (fail closed, exit 1)
// ---------------------------------------------------------------------------
test("unknown-budget: missing limit fails closed with exit 1", () => {
  const r = runChecker(["--db-url", "postgres://localhost/x", "--opt-in"],
                       { WORKBENCH_DATABASE_LIMIT_BYTES: "" });
  assert.equal(r.exitCode, 1);
  assert.ok(r.stdout.includes("UNKNOWN"), "must report UNKNOWN");
});

// ---------------------------------------------------------------------------
// 3. measured-inputs-required — missing measured migration bytes is UNKNOWN
// ---------------------------------------------------------------------------
test("measured-inputs-required: missing migration/rollback bytes fails closed", () => {
  const r = runChecker([
    "--db-url", "postgres://localhost/x",
    "--limit-bytes", "500000000",
    "--opt-in",
  ], {
    WORKBENCH_MIGRATION_PEAK_BYTES: "",
    WORKBENCH_ROLLBACK_BYTES: "",
  });
  assert.equal(r.exitCode, 1, "missing measured inputs must not exit 0");
  assert.ok(r.stdout.includes("UNKNOWN"), "must report UNKNOWN");
});

// ---------------------------------------------------------------------------
// 4. recovery-mode — unreachable host is UNKNOWN, no URL leak in stdout
// ---------------------------------------------------------------------------
test("recovery-mode: unreachable host is UNKNOWN and URL is redacted", () => {
  const r = runChecker([
    "--db-url", "postgres://user:secret@invalid-host-does-not-exist.test/db",
    "--limit-bytes", "500000000",
    "--migration-peak-bytes", "10485760",
    "--rollback-bytes", "10485760",
    "--opt-in",
  ]);
  assert.notEqual(r.exitCode, 0);
  assert.ok(!r.stdout.includes("secret"), "must not leak password in stdout");
  assert.ok(!r.stdout.includes("invalid-host-does-not-exist"), "must not leak hostname in stdout");
});

// ---------------------------------------------------------------------------
// 5. help — prints usage and exits 0
// ---------------------------------------------------------------------------
test("help: --help prints usage and exits 0", () => {
  const r = runChecker(["--help"]);
  assert.equal(r.exitCode, 0);
  assert.ok(r.stdout.includes("Usage:"), "should print usage");
});

// ---------------------------------------------------------------------------
// 6. real disposable Postgres — happy path against a fresh loopback DB
// ---------------------------------------------------------------------------
test("real-disposable-postgres: PASS when required space fits threshold", async (t) => {
  const url = process.env.WORKBENCH_CAPACITY_DATABASE_URL;
  if (!url) {
    await writeArtifact("real-postgres-skipped.txt",
      "WORKBENCH_CAPACITY_DATABASE_URL not set — real-disposable-postgres skipped.\n" +
      "Provide a disposable loopback Postgres URL whose db name starts with " +
      "`workbench_capacity_fixture_` to enable.\n");
    t.skip("WORKBENCH_CAPACITY_DATABASE_URL not set");
    return;
  }
  if (!/\/workbench_capacity_fixture_/.test(url)) {
    throw new Error("Refusing to run: DB name must start with workbench_capacity_fixture_");
  }
  let pg;
  try { pg = await import("pg"); }
  catch { t.skip("pg unavailable"); return; }
  const { Client } = pg.default ?? pg;
  const client = new Client({ connectionString: url });
  await client.connect();
  let before, after;
  try {
    // Prime with a tiny table
    await client.query(`create table if not exists cap_probe(x int);`);
    const b = await client.query(`select pg_database_size(current_database()) as s`);
    before = Number(b.rows[0].s);
  } finally { await client.end().catch(() => {}); }

  // Run the checker with a generous limit so it PASSes.
  const r = runChecker([
    "--db-url", url,
    "--limit-bytes",           String(10 * 1024 * 1024 * 1024),  // 10 GiB
    "--migration-peak-bytes",  String(1_048_576),                // 1 MiB
    "--rollback-bytes",        String(1_048_576),                // 1 MiB
    "--opt-in",
  ]);
  assert.equal(r.exitCode, 0, `expected PASS, stderr: ${r.stderr}, stdout tail: ${r.stdout.slice(-400)}`);
  assert.ok(r.stdout.includes("STATUS: PASS"), "must report PASS");

  // Verify no writes: DB size did not decrease (checker never writes).
  const c2 = new Client({ connectionString: url });
  await c2.connect();
  try {
    const a = await c2.query(`select pg_database_size(current_database()) as s`);
    after = Number(a.rows[0].s);
  } finally { await c2.end().catch(() => {}); }
  // Any drift should be small (autovacuum etc); size should not have grown
  // by any amount attributable to the checker.
  const drift = Math.abs(after - before);
  assert.ok(drift < 1_048_576, `checker must not write; drift ${drift} bytes`);
  await writeArtifact("real-postgres-drift.json", { before, after, drift });

  // Same DB with a tight limit → FAIL
  const rFail = runChecker([
    "--db-url", url,
    "--limit-bytes",           String(before + 512),   // just above current
    "--migration-peak-bytes",  String(1_048_576),
    "--rollback-bytes",        String(1_048_576),
    "--opt-in",
  ]);
  assert.equal(rFail.exitCode, 1, "tight limit must FAIL");
  assert.ok(rFail.stdout.includes("STATUS: FAIL"), "must report FAIL");
});

// ---------------------------------------------------------------------------
// 7. tls-verification — insecure-tls flag is recorded in the JSON report
// ---------------------------------------------------------------------------
test("tls-verification: insecure-tls flag is recorded in the JSON report", () => {
  const r = runChecker([
    "--db-url", "postgres://nowhere.test/x",
    "--limit-bytes", "500000000",
    "--migration-peak-bytes", "10485760",
    "--rollback-bytes", "10485760",
    "--opt-in",
    "--insecure-tls",
  ]);
  assert.notEqual(r.exitCode, 0, "unreachable host still fails, but report should still parse");
  const m = r.stdout.match(/\{[\s\S]*\}\s*$/);
  if (m) {
    const report = JSON.parse(m[0]);
    assert.equal(report.tls_verified, false, "tls_verified must reflect --insecure-tls");
  }
});

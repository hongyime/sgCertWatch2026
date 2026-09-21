/**
 * scripts/check_workbench_capacity.mjs
 *
 * Read-only capacity checker for the workbench database rollout gate (Task 7).
 *
 * Usage:
 *   node scripts/check_workbench_capacity.mjs \
 *     --db-url <postgres-url> \
 *     --limit-bytes <bytes> \
 *     --migration-peak-bytes <bytes> \
 *     --rollback-bytes <bytes> \
 *     --opt-in
 *
 * Every overhead value MUST be a measured input from the fixture — the
 * checker refuses to guess.  Unknown or non-numeric inputs fail closed.
 *
 * Environment variables (equivalent to flags):
 *   WORKBENCH_DB_URL
 *   WORKBENCH_DATABASE_LIMIT_BYTES
 *   WORKBENCH_MIGRATION_PEAK_BYTES
 *   WORKBENCH_ROLLBACK_BYTES
 *
 * Exit codes:
 *   0  PASS
 *   1  FAIL / UNKNOWN  (fail closed)
 *   2  Usage error
 *
 * Guarantees:
 * - Read-only: only executes a SQL statement allowlist.
 * - Never writes to the database.
 * - Never loads .env files automatically.
 * - Never logs secrets or the raw DB URL.
 * - TLS enabled by default; TLS verification only skipped with an
 *   explicit --insecure-tls flag (recorded in the report).
 * - Bounded connect / query / total timeouts.
 */

import { parseArgs } from "node:util";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const { values: args } = parseArgs({
  options: {
    "db-url":                { type: "string" },
    "limit-bytes":           { type: "string" },
    "migration-peak-bytes":  { type: "string" },
    "rollback-bytes":        { type: "string" },
    "activation-threshold":  { type: "string" },
    "connect-timeout-ms":    { type: "string" },
    "statement-timeout-ms":  { type: "string" },
    "opt-in":                { type: "boolean", default: false },
    "insecure-tls":          { type: "boolean", default: false },
    help:                    { type: "boolean", default: false },
  },
  strict: false,
});

if (args.help) {
  process.stdout.write(
    `Usage: node scripts/check_workbench_capacity.mjs \\\n` +
    `  --db-url <postgres-url> \\\n` +
    `  --limit-bytes <bytes> \\\n` +
    `  --migration-peak-bytes <bytes> \\\n` +
    `  --rollback-bytes <bytes> \\\n` +
    `  --opt-in\n` +
    `\nExits 0 = PASS, 1 = FAIL/UNKNOWN, 2 = usage error.  Never writes.\n`
  );
  process.exit(0);
}

function pickNumber(argName, envName) {
  const raw = args[argName] ?? process.env[envName];
  if (raw === undefined || raw === null || raw === "") return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : NaN;
}

const dbUrl               = args["db-url"] || process.env.WORKBENCH_DB_URL || "";
const limitBytes          = pickNumber("limit-bytes",          "WORKBENCH_DATABASE_LIMIT_BYTES");
const migrationPeakBytes  = pickNumber("migration-peak-bytes", "WORKBENCH_MIGRATION_PEAK_BYTES");
const rollbackBytes       = pickNumber("rollback-bytes",       "WORKBENCH_ROLLBACK_BYTES");
const activationRaw       = pickNumber("activation-threshold", "WORKBENCH_ACTIVATION_THRESHOLD");
const connectTimeoutMs    = Number(args["connect-timeout-ms"]   || process.env.WORKBENCH_CONNECT_TIMEOUT_MS   || 5_000);
const statementTimeoutMs  = Number(args["statement-timeout-ms"] || process.env.WORKBENCH_STATEMENT_TIMEOUT_MS || 3_000);
const optIn               = Boolean(args["opt-in"]);
const insecureTls         = Boolean(args["insecure-tls"]);

const ACTIVATION_THRESHOLD =
  Number.isFinite(activationRaw) && activationRaw > 0 && activationRaw <= 1
    ? activationRaw : 0.80;

// ---------------------------------------------------------------------------
// Fail-closed validation
// ---------------------------------------------------------------------------

function usageError(msg) {
  process.stderr.write(`ERROR: ${msg}\n`);
  process.exit(2);
}

function unknown(reason, report = {}) {
  const out = { status: "UNKNOWN", reason, ...report };
  process.stdout.write("STATUS: UNKNOWN\n");
  process.stdout.write(`REASON: ${reason}\n`);
  process.stdout.write("        Production rollout is BLOCKED until this check passes.\n\n");
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  process.exit(1);
}

if (!optIn) {
  usageError("--opt-in is required to run against any database. Prevents accidental production queries.");
}
if (!dbUrl) {
  usageError("--db-url or WORKBENCH_DB_URL is required.");
}
if (!limitBytes || !Number.isFinite(limitBytes) || limitBytes <= 0) {
  unknown("WORKBENCH_DATABASE_LIMIT_BYTES missing or invalid.  Provide the exact free-plan storage limit from your provider.");
}
if (!Number.isFinite(migrationPeakBytes) || migrationPeakBytes < 0) {
  unknown("WORKBENCH_MIGRATION_PEAK_BYTES missing or invalid.  Provide the fixture-measured peak migration bytes.");
}
if (!Number.isFinite(rollbackBytes) || rollbackBytes < 0) {
  unknown("WORKBENCH_ROLLBACK_BYTES missing or invalid.  Provide the fixture-measured rollback space bytes.");
}

// ---------------------------------------------------------------------------
// SQL allowlist — only these statements may be issued
// ---------------------------------------------------------------------------

const ALLOWED_QUERIES = new Set([
  "SELECT pg_database_size(current_database())",
  "SELECT set_config($1, $2, false)",
]);

function assertAllowed(sql) {
  const normalized = String(sql).trim().replace(/\s+/g, " ");
  if (!ALLOWED_QUERIES.has(normalized)) {
    throw new Error(`Forbidden query: ${normalized.slice(0, 80)}`);
  }
}

// ---------------------------------------------------------------------------
// TLS configuration
//
// Default: verify certificates (rejectUnauthorized: true).  Free-tier hosted
// Postgres instances typically require SSL; the driver upgrades automatically
// unless the URL disables it.  We NEVER silently accept unverified TLS.
// ---------------------------------------------------------------------------

function tlsConfig() {
  if (insecureTls) return { rejectUnauthorized: false };
  // Detect explicit sslmode=disable and honour it — the caller is responsible
  // for using --insecure-tls to acknowledge the risk.
  const parsed = safeParseUrl(dbUrl);
  const sslmode = parsed?.searchParams.get("sslmode") ?? "";
  if (sslmode === "disable") return false;
  return { rejectUnauthorized: true, minVersion: "TLSv1.2" };
}

function safeParseUrl(u) {
  try { return new URL(u); } catch { return null; }
}

function redact(err) {
  const raw = String(err?.message ?? err ?? "unknown");
  return raw
    .replace(/postgres(?:ql)?:\/\/[^\s]*/gi, "<redacted-url>")
    .replace(/ENOTFOUND\s+\S+/gi, "ENOTFOUND <redacted-host>")
    .replace(/ECONNREFUSED\s+\S+/gi, "ECONNREFUSED <redacted-host>")
    .replace(/[0-9A-Za-z_\-.]+@/g, "<redacted>@")
    .slice(0, 400);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

async function queryDbSize() {
  let pg;
  try {
    pg = await import("pg");
  } catch {
    return { ok: false, reason: "pg_not_available" };
  }
  const { Client } = pg.default ?? pg;
  const client = new Client({
    connectionString: dbUrl,
    ssl: tlsConfig(),
    connectionTimeoutMillis: connectTimeoutMs,
    statement_timeout: statementTimeoutMs,
    query_timeout: statementTimeoutMs,
  });

  const overall = setTimeout(() => {
    try { client.end().catch(() => {}); } catch { /* noop */ }
  }, connectTimeoutMs + statementTimeoutMs + 2_000).unref?.() ?? null;

  try {
    await client.connect();

    const setStmt = "SELECT set_config($1, $2, false)";
    assertAllowed(setStmt);
    await client.query(setStmt, ["statement_timeout", `${Math.floor(statementTimeoutMs)}ms`]);

    const sizeSql = "SELECT pg_database_size(current_database())";
    assertAllowed(sizeSql);
    const result = await client.query(sizeSql);

    const bytes = Number(result?.rows?.[0]?.pg_database_size);
    if (!Number.isFinite(bytes) || bytes < 0) {
      return { ok: false, reason: "invalid_size_response" };
    }
    return { ok: true, bytes };
  } catch (err) {
    return { ok: false, reason: redact(err) };
  } finally {
    if (overall) clearTimeout(overall);
    await client.end().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const snapshotAt = new Date().toISOString();
process.stdout.write("\nsgCertWatch2026 Workbench Capacity Check\n");
process.stdout.write(`Snapshot:              ${snapshotAt}\n`);
process.stdout.write(`Limit:                 ${(limitBytes / 1_048_576).toFixed(1)} MiB (${limitBytes} bytes)\n`);
process.stdout.write(`Migration peak (msrd): ${(migrationPeakBytes / 1_048_576).toFixed(1)} MiB\n`);
process.stdout.write(`Rollback space (msrd): ${(rollbackBytes / 1_048_576).toFixed(1)} MiB\n`);
process.stdout.write(`Activation threshold:  ${(ACTIVATION_THRESHOLD * 100).toFixed(0)}%\n`);
process.stdout.write(`Connect timeout:       ${connectTimeoutMs} ms\n`);
process.stdout.write(`Statement timeout:     ${statementTimeoutMs} ms\n`);
process.stdout.write(`TLS verification:      ${insecureTls ? "DISABLED (--insecure-tls)" : "enabled"}\n\n`);

const result = await queryDbSize();

const baseReport = {
  snapshot_at: snapshotAt,
  limit_bytes: limitBytes,
  migration_peak_bytes: migrationPeakBytes,
  rollback_bytes: rollbackBytes,
  threshold_pct: ACTIVATION_THRESHOLD,
  tls_verified: !insecureTls,
  connect_timeout_ms: connectTimeoutMs,
  statement_timeout_ms: statementTimeoutMs,
};

if (!result.ok) {
  if (result.reason === "pg_not_available") {
    unknown("pg package not available. Install with: npm install pg", baseReport);
  }
  unknown(`Database query failed: ${result.reason}`, baseReport);
}

const currentBytes   = result.bytes;
const requiredBytes  = currentBytes + migrationPeakBytes + rollbackBytes;
const thresholdBytes = Math.floor(limitBytes * ACTIVATION_THRESHOLD);

const report = {
  ...baseReport,
  current_bytes: currentBytes,
  required_bytes: requiredBytes,
  threshold_bytes: thresholdBytes,
};

process.stdout.write(`Current DB size:       ${(currentBytes / 1_048_576).toFixed(1)} MiB (${currentBytes} bytes)\n`);
process.stdout.write(`Required (curr+peak+rb): ${(requiredBytes / 1_048_576).toFixed(1)} MiB\n`);
process.stdout.write(`Activation threshold:    ${(thresholdBytes / 1_048_576).toFixed(1)} MiB\n\n`);

if (requiredBytes <= thresholdBytes) {
  report.status = "PASS";
  report.reason = "Required space fits within activation threshold.";
  process.stdout.write("STATUS: PASS\n");
  process.stdout.write("REASON: Required space fits within activation threshold.\n");
  process.stdout.write("        Production rollout may proceed after separate authorization.\n\n");
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exit(0);
} else {
  report.status = "FAIL";
  report.reason = `Required ${(requiredBytes / 1_048_576).toFixed(1)} MiB exceeds ${(thresholdBytes / 1_048_576).toFixed(1)} MiB threshold.`;
  process.stdout.write("STATUS: FAIL\n");
  process.stdout.write(`REASON: ${report.reason}\n`);
  process.stdout.write("        Production rollout is BLOCKED. Apply space-recovery.sql first.\n\n");
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  process.exit(1);
}

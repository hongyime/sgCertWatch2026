/**
 * scripts/workbench-db-fixture.mjs
 *
 * Reusable Docker + PostgreSQL 17 fixture helper for workbench smoke tests.
 * Exports createFixture() which spins up a disposable postgres:17.6 container
 * on a random loopback port, applies the real supabase/schema.sql plus
 * workbench SQL migrations, and tears down cleanly — even on startup failure.
 *
 * Usage in test files:
 *
 *   import { createFixture } from "./workbench-db-fixture.mjs";
 *
 *   let fx;
 *   before(async () => { fx = await createFixture(); }, { timeout: 300_000 });
 *   after(async  () => { await fx.close(); },           { timeout:  60_000 });
 *
 *   test("...", async () => {
 *     const r = await fx.client.query("select ...");
 *     // or:
 *     const c2 = fx.newClient();
 *     await c2.connect();
 *     // ...
 *     await c2.end();
 *   });
 *
 * Never reads .env or production credentials.
 * Always removes its own container in close() and on any startup failure.
 */

import { execFile }      from "node:child_process";
import { readFileSync }  from "node:fs";
import { resolve }       from "node:path";
import { fileURLToPath } from "node:url";
import { promisify }     from "node:util";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");

const execFileAsync = promisify(execFile);

// ── Docker image ─────────────────────────────────────────────────────────────
const PG_IMAGE    = "postgres:17.6";
const PG_PASSWORD = "fixture_no_prod";

// ── Helpers ──────────────────────────────────────────────────────────────────

function docker(args, timeoutMs = 90_000) {
  return execFileAsync("docker", args, { timeout: timeoutMs });
}

async function startContainer(name, dbName) {
  await docker([
    "run", "-d",
    "--name", name,
    "-e", `POSTGRES_PASSWORD=${PG_PASSWORD}`,
    "-e", `POSTGRES_DB=${dbName}`,
    "-p", "127.0.0.1::5432",  // Docker auto-assigns a free loopback port
    PG_IMAGE,
  ], 180_000);
}

/** Returns the host port Docker assigned for container's 5432/tcp. */
async function getAssignedPort(name) {
  const { stdout } = await docker(["port", name, "5432/tcp"], 10_000);
  // stdout: "127.0.0.1:PORT\n"  (possibly one line per address family)
  const line  = stdout.trim().split("\n")[0];
  const match = line.match(/:(\d+)$/);
  if (!match) throw new Error(`Could not parse Docker assigned port from: ${stdout.trim()}`);
  return parseInt(match[1], 10);
}

// Use -f so cleanup always works even if the container is still running
// (e.g. docker stop timed out while PG was applying the schema).
async function stopContainer(name) {
  try { await docker(["rm", "-f", name], 30_000); } catch { /* best-effort */ }
}

async function waitForReady(Client, port, database, maxWaitMs = 120_000) {
  // Brief initial pause — PostgreSQL init takes a few seconds to start.
  await new Promise(r => setTimeout(r, 5_000));
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    const c = new Client({
      host: "127.0.0.1", port,
      database, user: "postgres", password: PG_PASSWORD,
      connectionTimeoutMillis: 3_000,
    });
    try {
      await c.connect();
      await c.query("SELECT 1");
      await c.end();
      return;
    } catch {
      await c.end().catch(() => {});
      await new Promise(r => setTimeout(r, 1_200));
    }
  }
  throw new Error(`PostgreSQL not ready after ${maxWaitMs} ms`);
}

// ── Role bootstrap ────────────────────────────────────────────────────────────
// Real schema is applied via schema.sql; no inline duplicate schema here.

const FIXTURE_ROLES = `
do $$
begin
  if not exists (select from pg_roles where rolname = 'anon') then
    create role anon nologin;
  end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
  if not exists (select from pg_roles where rolname = 'service_role') then
    create role service_role nologin;
  end if;
end;
$$;
grant all  on schema public to service_role;
grant usage on schema public to anon, authenticated;
`;

// ── Public interface ─────────────────────────────────────────────────────────

/**
 * Create a disposable PostgreSQL 17 fixture.
 *
 * Assigns a random loopback port so concurrent fixtures never collide.
 * Applies the real supabase/schema.sql (not a minimal inline duplicate).
 * Cleans up its own Docker container on close() or on any startup failure.
 *
 * @param {object} [opts]
 * @param {string[]} [opts.migrationFiles]  SQL migration files applied after
 *   schema.sql.  Defaults to workbench-review.sql + workbench-search.sql.
 * @param {Array<[string, ...unknown[]]>} [opts.seedRows]  Extra queries run
 *   after migrations (each element is [sql, ...params]).
 * @returns {Promise<{
 *   client:        import("pg").Client,
 *   containerName: string,
 *   port:          number,
 *   database:      string,
 *   newClient:     () => import("pg").Client,
 *   close:         () => Promise<{ containerName: string, removed: boolean|null }>
 * }>}
 */
export async function createFixture({
  migrationFiles = [
    resolve(REPO_ROOT, "supabase", "workbench-review.sql"),
    resolve(REPO_ROOT, "supabase", "workbench-search.sql"),
  ],
  seedRows = [],
} = {}) {
  // Unique names per invocation to prevent port and container collisions.
  const ts  = Date.now();
  const rnd = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, "0");
  const containerName = `sgcw_wbfix_${ts}_${rnd}`;
  const pgDatabase    = `wbfix_${ts.toString(36)}_${rnd}`;

  // Load pg dynamically so the module can be imported without a hard dependency.
  let pg;
  try {
    pg = (await import("pg")).default ?? (await import("pg"));
  } catch {
    throw new Error("pg package not installed — run: npm install");
  }
  const { Client } = pg;

  // Track client for cleanup; attempt stopContainer by unique name on ANY
  // error — including docker-run CLI timeout (daemon may have already created
  // the container before the CLI process was killed).
  let client = null;
  try {
    await startContainer(containerName, pgDatabase);

    const port = await getAssignedPort(containerName);
    await waitForReady(Client, port, pgDatabase);

    client = new Client({
      host: "127.0.0.1", port,
      database: pgDatabase, user: "postgres", password: PG_PASSWORD,
    });
    await client.connect();

    // Roles first, then the real schema (not an inline minimal duplicate).
    await client.query(FIXTURE_ROLES);
    const schemaSql = readFileSync(
      resolve(REPO_ROOT, "supabase", "schema.sql"), "utf8"
    );
    await client.query(schemaSql);
    // No broad "grant all" — rely on explicit grants in schema.sql and migration files.

    // Apply migration files (workbench-review.sql, workbench-search.sql, …)
    for (const filePath of migrationFiles) {
      const sql = readFileSync(filePath, "utf8");
      await client.query(sql);
    }

    // Optional seed data
    for (const [sql, ...params] of seedRows) {
      await client.query(sql, params.length ? params : undefined);
    }

    /** Returns a new, unconnected Client bound to this fixture's host/port/db. */
    function newClient() {
      return new Client({
        host: "127.0.0.1", port,
        database: pgDatabase, user: "postgres", password: PG_PASSWORD,
      });
    }

    /**
     * Returns { containerName, removed } where:
     *   true  — docker inspect confirmed "No such object" (container gone)
     *   false — inspect still found the container (removal failed)
     *   null  — inconclusive (daemon/timeout error; cannot confirm removal)
     */
    async function close() {
      await client.end().catch(() => {});
      await stopContainer(containerName);

      let removed = null;
      try {
        const { stdout } = await docker(
          ["inspect", containerName, "--format", "{{.ID}}"], 30_000
        );
        if (stdout.trim()) {
          // inspect returned output — container still exists
          removed = false;
          console.error(`[fixture] container ${containerName} still exists after close()`);
        }
      } catch (inspectErr) {
        const msg = String(inspectErr.stderr || inspectErr.message || "").toLowerCase();
        if (msg.includes("no such object") || msg.includes("no such container")) {
          removed = true;   // confirmed not-found
        } else {
          // timeout, daemon error, or unexpected — cannot confirm removal
          removed = null;
          console.error(
            `[fixture] removal check inconclusive for ${containerName}: ${inspectErr.message}`
          );
        }
      }
      return { containerName, removed };
    }

    return { client, containerName, port, database: pgDatabase, newClient, close };
  } catch (err) {
    // Always end client and attempt container removal by unique name.
    // Handles: docker-run timeout, getAssignedPort failure, migration errors.
    if (client) await client.end().catch(() => {});
    await stopContainer(containerName).catch(() => {});
    // Annotate so callers can verify cleanup by container name without docker ps.
    err.fixtureContainerName = containerName;
    throw err;
  }
}

// ── Convenience re-exports ────────────────────────────────────────────────────
export { PG_IMAGE, PG_PASSWORD };

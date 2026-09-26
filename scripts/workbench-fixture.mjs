/**
 * Loopback HTTP fixture server for UI workbench tests.
 *
 * Serves an explicit allowlist of public app files and two synthetic API
 * routes.  Binds to 127.0.0.1 only.  Never contacts Supabase or any other
 * external service.
 *
 * Exports
 *   start()            → Promise<{ url: string, close: () => Promise<void> }>
 *   generateFindings(count) → Array of finding objects (count + 1 items;
 *                             the extra entry is record-075.test which the
 *                             /api/findings route does NOT serve)
 */

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const PROJECT_ROOT = resolve(__dirname, "..");

/** Files the fixture is permitted to serve; all others return 404. */
const ALLOWLIST = new Set([
  "index.html",
  "app.js",
  "styles.css",
  "refresh.js",
  "favicon.svg",
  "watchlist.json",
  "keywords.json",
  "allowlist.json",
  "schemes.json",
  // lib/ui modules dynamically imported by app.js
  "lib/ui/findings-list.js",
  "lib/ui/finding-details.js",
  "lib/ui/report.js",
  "lib/ui/saved-views.js",
  "lib/ui/evidence-timeline.js",
  "lib/ui/related-findings.js",
  "lib/ui/impersonation.js",
  "lib/ui/reviewer-session.js",
]);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

const SG_BRANDS = ["singpass", "cpf", "iras", "hdb", "mom", "psa", "moh", "sla"];
const SG_TERMS  = ["login", "claim", "portal", "account", "verify", "auth", "secure", "gov"];
const ISSUERS   = ["Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign"];

/**
 * Generate synthetic findings.
 *
 * Produces `count` sequentially-numbered findings (record-001 … record-NNN)
 * followed by one extra entry whose registrable is "record-075.test".  That
 * extra entry exists in the generator but is NOT returned by the
 * /api/findings route, which always slices the array to the first `count`
 * items.  Searching for "record-075.test" in the UI therefore proves the
 * scope label is honest about the loaded window.
 *
 * All .test TLD hostnames — no real domains used.
 *
 * @param {number} count
 * @returns {Array}
 */
export function generateFindings(count) {
  const now = Date.now();
  const findings = [];

  for (let i = 1; i <= count; i++) {
    const paddedId  = String(i).padStart(3, "0");
    const brandIdx  = Math.floor((i - 1) / SG_TERMS.length) % SG_BRANDS.length;
    const termIdx   = (i - 1) % SG_TERMS.length;
    const brand     = SG_BRANDS[brandIdx];
    const term      = SG_TERMS[termIdx];
    const registrable = `${brand}-${term}.test`;
    const score     = 70 + ((i - 1) % 30);   // 70–99 → all visible in watch view
    const severity  = score >= 90 ? "critical" : "high";

    findings.push({
      id:                  `record-${paddedId}`,
      registrable,
      score,
      severity,
      priority_score:      score,
      signals:             ["keyword_match", "brand_match"],
      matched_brands:      [brand],
      domains:             [registrable, `www.${registrable}`],
      observed_at:         new Date(now - i * 3_600_000).toISOString(),
      issuer:              ISSUERS[(i - 1) % ISSUERS.length],
      sources:             ["direct_ct"],
      intel_evidence:      [],
      intel_hit_count:     0,
      intel_priority_boost: 0,
    });
  }

  // The 51st entry — exists in the generator, NOT served by /api/findings.
  findings.push({
    id:                  "record-075.test",
    registrable:         "record-075.test",
    score:               75,
    severity:            "high",
    priority_score:      75,
    signals:             ["keyword_match"],
    matched_brands:      ["singpass"],
    domains:             ["record-075.test"],
    observed_at:         new Date(now - 75 * 3_600_000).toISOString(),
    issuer:              "Let's Encrypt",
    sources:             ["direct_ct"],
    intel_evidence:      [],
    intel_hit_count:     0,
    intel_priority_boost: 0,
  });

  return findings;
}

// Build once at module init so all start() calls share the same findings.
const ALL_FINDINGS    = generateFindings(50); // 51 items: 001–050 + record-075.test
const SERVED_FINDINGS = ALL_FINDINGS.slice(0, 50); // /api/findings returns only these

const SOURCE_STATUS_FIXTURE = {
  storage_configured: true,
  health: "pending",
  sources: [],
  display_sources: [],
  intel_sources: [
    "openphish", "urlscan", "urlhaus", "threatfox",
  ].map((source) => ({
    source,
    label: source,
    status: "pending",
    ok: false,
    checked_at: null,
    last_checked_at: null,
    scanned_entries: 0,
    matched: 0,
    persisted: 0,
    errors: [],
    details: {},
    next_poll_at: null,
  })),
  operations: {
    state: "pending",
    last_started_at: null,
    last_success_at: null,
    checked_at: null,
    next_due_at: null,
    target_interval_minutes: 15,
    duration_ms: null,
    runtime_ms: null,
    success_age_ms: null,
    freshness: "unknown",
    run_id: null,
    trigger: null,
    scheduler_trigger: null,
  },
  cursor_lag: { measured_logs: 0, lag_entries: null, max_lag_entries: null },
  intel_schedule: {
    runner: "github-actions",
    workflow: "intel.yml",
    cron: "7 * * * *",
    script: "scripts/run-intel.mjs",
  },
  schedule: {
    runner: "github-actions",
    workflow: "ingest.yml",
    cron: "7,22,37,52 * * * *",
    script: "scripts/run-ingest.mjs",
    target_interval_minutes: 15,
    last_external_trigger_at: null,
  },
  source_runs: [],
  updated_at: new Date().toISOString(),
};

/** Write a JSON response. */
function writeJson(res, statusCode, body) {
  const data = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type":  "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(data),
    "Cache-Control": "no-store",
  });
  res.end(data);
}

/**
 * Start the fixture server on an ephemeral loopback port.
 *
 * @returns {Promise<{ url: string, close: () => Promise<void> }>}
 */
export function start() {
  const server = createServer(async (req, res) => {
    // --- Parse URL -----------------------------------------------------------
    let parsed;
    try {
      parsed = new URL(req.url ?? "/", "http://localhost");
    } catch {
      writeJson(res, 400, { error: "bad_request" });
      return;
    }
    const pathname = parsed.pathname;

    // --- Security: block anything outside the allowlist ----------------------
    // Reject path traversal, hidden files/dirs, and node_modules.
    // The ALLOWLIST check below catches everything else.
    if (
      pathname.includes("..") ||
      /(?:^|\/)\./.test(pathname) ||    // /.git, /.env, /.agents, etc.
      pathname.startsWith("/node_modules")
    ) {
      writeJson(res, 403, { error: "forbidden" });
      return;
    }

    // --- API routes ----------------------------------------------------------
    if (pathname === "/api/findings") {
      // Accept (and ignore) malformed query params — never crash on bad input.
      // limit=abc, view=injected  → still returns valid JSON with 50 findings.
      writeJson(res, 200, { storage_configured: true, findings: SERVED_FINDINGS });
      return;
    }

    if (pathname === "/api/source-status") {
      writeJson(res, 200, SOURCE_STATUS_FIXTURE);
      return;
    }

    if (pathname === "/api/reviewer-session") {
      // Read body for POST
      let raw = "";
      for await (const chunk of req) raw += chunk;
      let body = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch { /* ignore */ }

      if (req.method === "POST") {
        // Synthetic auth for UI tests only; production handlers have their own
        // tests. Accept only this fixture's explicit credential pair.
        const isBadCreds =
          body.email !== "reviewer@test.local" ||
          body.password !== "correct-horse-battery";
        if (!isBadCreds) {
          const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
          writeJson(res, 200, {
            access_token: "fixture-reviewer-token-" + Date.now(),
            user: { id: "11111111-1111-1111-1111-111111111111" },
            expires_at: expiresAt,
          });
        } else {
          writeJson(res, 401, { error: "invalid_credentials" });
        }
        return;
      }

      if (req.method === "DELETE") {
        res.writeHead(204, { "Cache-Control": "no-store" });
        res.end();
        return;
      }

      writeJson(res, 405, { error: "method_not_allowed" });
      return;
    }


    // --- Static files (allowlist only) ---------------------------------------
    const name = pathname === "/" ? "index.html" : pathname.slice(1);

    if (!ALLOWLIST.has(name)) {
      writeJson(res, 404, { error: "not_found" });
      return;
    }

    const filePath = join(PROJECT_ROOT, name);
    try {
      const data = await readFile(filePath);
      const mime = MIME[extname(name)] ?? "application/octet-stream";
      res.writeHead(200, {
        "Content-Type":   mime,
        "Content-Length": data.length,
        "Cache-Control":  "no-store",
      });
      res.end(data);
    } catch {
      writeJson(res, 404, { error: "not_found" });
    }
  });

  return new Promise((resolve, reject) => {
    const openSockets = new Set();
    server.on("connection", (socket) => {
      openSockets.add(socket);
      socket.once("close", () => openSockets.delete(socket));
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url:   `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((res, rej) => {
            for (const s of openSockets) s.destroy();
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

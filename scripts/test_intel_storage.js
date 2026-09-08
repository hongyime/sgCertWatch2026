import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

process.env.SUPABASE_URL = "https://intel-storage.example";
process.env.SUPABASE_ANON_KEY = "test-anon";
process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service";

const storage = await import("../lib/supabase.js");
const { default: findingsHandler } = await import("../api/findings.js");
const { default: statusHandler } = await import("../api/source-status.js");
const now = Date.now();
const at = (hours = 0) => new Date(now + hours * 3600000).toISOString();

function finding(id, score = 65, extra = {}) {
  return { id, score, domains: [`${id}.example.com`], registrable: "example.com",
    suppressed: false, observed_at: at(), source: { name: "direct_ct" }, ...extra };
}

function evidence(domain, extra = {}) {
  return { id: `evidence-${domain}`, domain, source: "openphish", verdict: "phishing",
    source_ref: "https://openphish.com/phishing_feeds.html", observed_at: at(-1), expires_at: at(12),
    details: {}, ...extra };
}

function mockDatabase(t, { findings = [], evidence: evidenceRows = [], states = {}, runs = [], logs = [], publicCursorState = false, fail = null } = {}) {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (input, options = {}) => {
    const url = new URL(input);
    assert.equal(url.origin, process.env.SUPABASE_URL, "API must only call storage, never external feeds");
    assert.ok(options.signal instanceof AbortSignal, "Every DB request must have a timeout signal");
    calls.push({ url, ...options });
    const table = url.pathname.split("/").at(-1);
    const failure = fail?.(table, url, options);
    if (failure) return new Response(failure, { status: 503 });
    let rows = [];
    if (table === "intel_candidate_findings" || table === "intel_findings_for_hosts") {
      const args = JSON.parse(options.body);
      rows = findings.filter((row) => !row.suppressed && row.score >= 60).toSorted((a, b) => b.score - a.score
        || Date.parse(b.observed_at) - Date.parse(a.observed_at) || a.id.localeCompare(b.id));
      if (table === "intel_candidate_findings") {
        const seen = new Set();
        rows = rows.filter((row) => {
          if (seen.has(row.registrable)) return false;
          seen.add(row.registrable);
          return true;
        }).slice(0, args.candidate_limit);
      } else {
        rows = rows.filter((row) => row.domains.length
          ? row.domains.some((host) => args.hosts.includes(host)) : args.hosts.includes(row.registrable))
          .slice(0, args.result_limit);
      }
    } else if (options.method === "POST") rows = [].concat(JSON.parse(options.body));
    else if (table === "findings") {
      rows = findings.filter((row) => !row.suppressed);
      if (url.searchParams.get("score") === "gte.60") rows = rows.filter((row) => row.score >= 60);
      const scoreFirst = url.searchParams.get("order").startsWith("score.desc");
      rows = rows.toSorted((a, b) => (scoreFirst ? b.score - a.score : 0)
        || Date.parse(b.observed_at) - Date.parse(a.observed_at) || a.id.localeCompare(b.id));
    } else if (table === "intel_evidence") {
      const deleting = options.method === "DELETE";
      const cutoff = Date.parse(url.searchParams.get("expires_at").replace(/^(?:gt|lte)\./, ""));
      if (deleting) rows = evidenceRows.filter((row) => Date.parse(row.expires_at) <= cutoff);
      else {
        rows = evidenceRows.filter((row) => Date.parse(row.expires_at) > cutoff)
          .toSorted((a, b) => a.id.localeCompare(b.id));
      }
    } else if (table === "ingest_state") {
      const key = url.searchParams.get("key").slice(3);
      if ((key === "intel_source_state" || (key === "ct_source_state" && !publicCursorState))
        && options.headers.apikey !== "test-service") rows = [];
      else if (states[key]) rows = [states[key]];
    } else if (table === "ct_logs") {
      rows = logs;
    } else if (table === "ct_source_runs") {
      const source = url.searchParams.get("source");
      rows = runs.filter((run) => !source || (source.startsWith("eq.")
        ? source.slice(3) === run.source : source.slice(4, -1).split(",").includes(run.source)));
      rows = rows.toSorted((a, b) => Date.parse(b.checked_at) - Date.parse(a.checked_at));
    }
    const offset = Number(url.searchParams.get("offset") || 0);
    const limit = Number(url.searchParams.get("limit") || rows.length);
    return Response.json(rows.slice(offset, offset + limit));
  });
  return calls;
}

async function invoke(handler, query = {}, method = "GET") {
  const response = {
    headers: {},
    setHeader(key, value) { this.headers[key] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; }
  };
  await handler({ method, query }, response);
  return response;
}

test("private runner state uses service credentials even when anon is configured", async (t) => {
  const state = { value: { sources: { urlhaus: { cursor: "private" } }, abuse_cooldown_until: at(72) } };
  const calls = mockDatabase(t, { states: { intel_source_state: state } });
  assert.equal(await storage.getState("intel_source_state"), null);
  assert.deepEqual(await storage.getServiceState("intel_source_state"), state);
  assert.deepEqual(calls.map((call) => call.headers.apikey), ["test-anon", "test-service"]);
});

test("candidate selection is service-only and duplicate registrables cannot starve other domains", async (t) => {
  const calls = mockDatabase(t, { findings: [finding("low", 10), finding("older", 95, { observed_at: at(-20) }),
    ...Array.from({ length: 600 }, (_, i) => finding(`repeat-${i}`, 90)),
    finding("eligible", 68, { registrable: "other.test" }), finding("suppressed", 100, { suppressed: true })] });
  assert.deepEqual((await storage.listIntelCandidates()).map((row) => row.id), ["older", "eligible"]);
  assert.equal(calls[0].headers.apikey, "test-service");
  assert.deepEqual(JSON.parse(calls[0].body), { candidate_limit: 500 });
  assert.equal(calls[0].url.pathname, "/rest/v1/rpc/intel_candidate_findings");
  assert.equal(calls.length, 1);
});

test("evidence upsert hashes provider identity and prune deletes only expired rows", async (t) => {
  const fresh = evidence("login.example.com");
  const expired = evidence("old.example.com", { expires_at: at(-1) });
  const original = structuredClone(fresh);
  const calls = mockDatabase(t, { evidence: [fresh, expired] });
  const [saved] = await storage.upsertIntelEvidence([fresh]);
  assert.equal(saved.id, createHash("sha256").update(`${fresh.source}|${fresh.domain}|${fresh.source_ref}`).digest("hex"));
  assert.deepEqual(fresh, original);
  assert.match(calls[0].headers.Prefer, /resolution=merge-duplicates/);
  assert.deepEqual(await storage.pruneIntelEvidence(), [expired]);
  assert.equal(calls[1].method, "DELETE");
  assert.ok(calls.every((call) => call.headers.apikey === "test-service"));
  assert.deepEqual(await storage.upsertIntelEvidence([]), []);
  assert.equal(calls.length, 2);
});

test("default findings preserve recency, base scores and exact-host evidence boundaries", async (t) => {
  const rows = [finding("exact", 65, { domains: ["LOGIN.Example.com."] }),
    finding("sibling", 65, { domains: ["other.example.com"] }),
    finding("fallback", 65, { domains: [] }), finding("low", 59),
    finding("observed", 65), finding("expired", 65), finding("wildcard", 65, { domains: ["*.example.com"] })];
  const original = structuredClone(rows);
  const calls = mockDatabase(t, { findings: rows, evidence: [evidence("login.example.com"),
    evidence("example.com"), evidence("low.example.com"),
    evidence("observed.example.com", { verdict: "observed" }),
    evidence("expired.example.com", { expires_at: at(-1) })] });
  const result = new Map((await storage.listFindings()).map((row) => [row.id, row]));
  assert.equal(result.get("exact").priority_score, 75);
  assert.equal(result.get("exact").score, 65);
  assert.equal(result.get("exact").intel_hit_count, 1);
  assert.deepEqual(result.get("exact").sources, ["direct_ct"]);
  assert.equal(result.get("sibling").intel_hit_count, 0);
  assert.equal(result.get("fallback").priority_score, 75);
  assert.equal(result.get("low").priority_score, 59);
  assert.equal(result.get("low").intel_priority_boost, 0);
  assert.equal(result.get("observed").priority_score, 65);
  assert.equal(result.get("expired").intel_hit_count, 0);
  assert.equal(result.get("wildcard").intel_hit_count, 0);
  assert.deepEqual(rows, original);
  assert.equal(calls[0].url.searchParams.get("order"), "observed_at.desc");
  assert.equal(calls[0].url.searchParams.get("score"), null);
  assert.ok(calls.every((call) => call.headers.apikey === "test-anon"));
});

test("watch view finds older high scores and boosted candidates beyond the first page", async (t) => {
  const rows = [...Array.from({ length: 60 }, (_, i) => finding(`low-${i}`, 8)),
    finding("base-high", 75, { observed_at: at(-20) }),
    ...Array.from({ length: 100 }, (_, i) => finding(`near-${i}`, 69, { observed_at: at(-1) })),
    finding("boosted", 68, { observed_at: at(-30) })];
  const calls = mockDatabase(t, { findings: rows, evidence: [evidence("boosted.example.com")] });
  const ordinary = await invoke(findingsHandler);
  assert.equal(ordinary.statusCode, 200);
  assert.ok(ordinary.body.findings.every((row) => row.score === 8));
  const response = await invoke(findingsHandler, { view: "watch", limit: "1" });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.findings.length, 1);
  assert.equal(response.body.findings[0].id, "boosted");
  assert.equal(response.body.findings[0].priority_score, 78);
  assert.ok(calls.some((call) => call.url.pathname.endsWith("/rpc/intel_findings_for_hosts")));
  assert.equal(calls.length, 5, "Default uses two requests; watch uses three regardless of candidate count");
});

test("thousands of high-score ties use one base query and retain promoted recency ties", async (t) => {
  const calls = mockDatabase(t, { findings: [
    ...Array.from({ length: 3000 }, (_, i) => finding(`base-${i}`, 70, { observed_at: at(-4) })),
    finding("tie", 60, { observed_at: at(-1) })], evidence: [evidence("tie.example.com")] });
  const rows = await storage.listFindings(1, { view: "watch" });
  assert.equal(rows[0].id, "tie");
  assert.equal(rows[0].priority_score, 70);
  assert.equal(calls.length, 3);
  assert.equal(calls.filter((call) => call.url.pathname.endsWith("/findings")).length, 1);
  assert.ok(calls.every((call) => !call.url.searchParams.has("offset") || call.url.searchParams.get("offset") === "0"));
});

test("evidence history is paged so a strong verdict after 1000 rows is included", async (t) => {
  const domain = "history.example.com";
  const calls = mockDatabase(t, { findings: [finding("history")], evidence: [
    ...Array.from({ length: 1000 }, (_, i) => evidence(domain, { id: `a-${String(i).padStart(4, "0")}`, verdict: "observed" })),
    evidence(domain, { id: "z-confirmed" })] });
  const [row] = await storage.listFindings();
  assert.equal(row.priority_score, 75);
  assert.equal(row.intel_evidence.length, 1001);
  assert.ok(calls.some((call) => call.url.searchParams.get("offset") === "1000"));
  assert.equal(calls.length, 3);
});

test("evidence capacity stops at five pages instead of silently returning incomplete rankings", async (t) => {
  const calls = mockDatabase(t, { evidence: Array.from({ length: 5000 }, (_, i) =>
    evidence("bounded.example.com", { id: String(i) })) });
  await assert.rejects(storage.listFindings(1, { view: "watch" }), /exceeds the public query capacity/);
  assert.equal(calls.length, 6);
});

function ctState(checkedAt = at()) {
  return { ct_poll_status: { value: { checked_at: checkedAt, health: "healthy" }, updated_at: checkedAt },
    ct_source_state: { value: {} } };
}

test("an absent CT heartbeat is pending, never healthy by default", async (t) => {
  mockDatabase(t, { states: {} });
  const { body } = await invoke(statusHandler);
  assert.equal(body.health, "pending");
  assert.equal(body.operations.last_success_at, null);
  assert.equal(body.operations.next_due_at, null);
  assert.equal(body.cursor_lag.lag_entries, null);
});

test("CT freshness uses last success with strict warning/critical thresholds even while running", async (t) => {
  t.mock.method(Date, "now", () => now);
  const states = ctState();
  const poll = states.ct_poll_status.value;
  Object.assign(poll, { state: "running", last_started_at: at(-1 / 60), duration_ms: 123,
    run_id: "test-run-123", trigger: "workflow_dispatch", scheduler_trigger: "cloudflare" });
  mockDatabase(t, { states, runs: [{ source: "direct_ct", ok: true, checked_at: at() }] });
  for (const [minutes, freshness, health] of [[15, "fresh", "healthy"], [30, "fresh", "healthy"],
    [30.01, "warning", "stale"], [60, "warning", "stale"], [60.01, "critical", "stale"]]) {
    poll.last_success_at = at(-minutes / 60);
    const { statusCode, body } = await invoke(statusHandler);
    assert.equal(statusCode, 200);
    assert.equal(body.health, health);
    assert.equal(body.operations.freshness, freshness);
    assert.equal(body.operations.state, "running");
    assert.equal(body.operations.runtime_ms, 60000, "Running runtime never reuses the previous duration");
    assert.equal(body.operations.checked_at, poll.checked_at);
    assert.equal(body.operations.last_success_at, poll.last_success_at);
    assert.equal(body.operations.next_due_at, at(14 / 60));
    assert.equal(body.operations.run_id, poll.run_id);
    assert.equal(body.operations.trigger, "workflow_dispatch");
    assert.equal(body.operations.target_interval_minutes, 15);
  }
});

test("legacy fallback requires a successful health and never uses row updates or explicit missing successes", async (t) => {
  t.mock.method(Date, "now", () => now);
  const states = ctState();
  mockDatabase(t, { states });
  for (const health of ["healthy", "partial", "down", "pending", "degraded"]) {
    states.ct_poll_status.value = { checked_at: at(-0.1), health };
    const { body } = await invoke(statusHandler);
    assert.equal(body.operations.last_success_at, ["healthy", "partial"].includes(health) ? at(-0.1) : null);
  }
  for (const value of [null, "invalid"]) {
    states.ct_poll_status.value = { checked_at: at(), health: "healthy", last_success_at: value };
    const { body } = await invoke(statusHandler);
    assert.equal(body.health, "pending");
    assert.equal(body.operations.last_success_at, null);
  }
  states.ct_poll_status.value = { health: "healthy", state: "running", last_started_at: at() };
  const { body } = await invoke(statusHandler);
  assert.equal(body.health, "pending");
  assert.equal(body.operations.freshness, "unknown");
  assert.equal(body.operations.last_success_at, null);
});

test("a failed CT run stays down after freshness expires and completed runtime stays fixed", async (t) => {
  t.mock.method(Date, "now", () => now);
  const states = ctState(at(-2));
  Object.assign(states.ct_poll_status.value, { state: "failed", health: "down", last_success_at: at(-3),
    last_started_at: at(-2.1), duration_ms: 120000 });
  mockDatabase(t, { states, runs: [{ source: "direct_ct", ok: true, checked_at: at() }] });
  const { body } = await invoke(statusHandler);
  assert.equal(body.health, "down");
  assert.equal(body.operations.freshness, "critical");
  assert.equal(body.operations.runtime_ms, 120000);
  Object.assign(states.ct_poll_status.value, { state: "completed", health: "partial", last_success_at: at() });
  const completed = (await invoke(statusHandler)).body;
  assert.equal(completed.health, "partial");
  assert.equal(completed.operations.runtime_ms, 120000);
});

test("scheduler observation requires its actual persisted timestamp and preserves fallback history", async (t) => {
  const states = ctState();
  const poll = states.ct_poll_status.value;
  Object.assign(poll, { scheduler_trigger: "cloudflare", last_started_at: at() });
  mockDatabase(t, { states });
  let body = (await invoke(statusHandler)).body;
  assert.equal(body.schedule.last_external_trigger_at, null);
  assert.equal(body.schedule.cron, "7,22,37,52 * * * *");
  assert.equal(body.intel_schedule.cron, "7 * * * *");
  Object.assign(poll, { scheduler_trigger: "github", last_external_trigger_at: at(-24) });
  body = (await invoke(statusHandler)).body;
  assert.equal(body.schedule.last_external_trigger_at, at(-24));
  poll.last_external_trigger_at = "invalid";
  assert.equal((await invoke(statusHandler)).body.schedule.last_external_trigger_at, null);
});

const cursorLogs = Array.from({ length: 5 }, (_, i) => ({ log_id: `test-log-${i}`, state: "usable", protocol: "rfc6962" }));
function cursorStates() {
  return { ...ctState(), ct_source_state: { value: { direct_ct: { cursors: {
    "test-log-0": { tree_size: 1000, next_index: 750, checked_at: at() },
    "test-log-1": { treeSize: 500, next: 500, checked_at: at() },
    "test-log-2": { tree_size: 100 },
    "test-log-3": { tree_size: null, next_index: null },
    "test-log-4": { tree_size: 10, next_index: 11 }
  } } } } };
}

test("RLS-hidden cursors never become measured zero-lag sources", async (t) => {
  const calls = mockDatabase(t, { states: cursorStates(), logs: cursorLogs });
  const { body } = await invoke(statusHandler);
  assert.equal(body.health, "healthy");
  assert.deepEqual(body.cursor_lag, { measured_logs: 0, lag_entries: null, max_lag_entries: null });
  assert.ok(body.sources.every((row) => row.lag_entries === null));
  assert.ok(calls.every((call) => call.headers.apikey === "test-anon"));
});

test("cursor lag includes only valid measured tree sizes and positions, including actual zero", async (t) => {
  mockDatabase(t, { states: cursorStates(), logs: cursorLogs, publicCursorState: true });
  const { body } = await invoke(statusHandler);
  assert.deepEqual(body.cursor_lag, { measured_logs: 2, lag_entries: 250, max_lag_entries: 250 });
  assert.deepEqual(body.sources.filter((row) => row.protocol === "rfc6962").map((row) => row.lag_entries), [250, 0]);
});

test("notification status exposes only safe aggregates, with missing counts distinct from zero", async (t) => {
  const states = { ...ctState(), notifications_poll_status: { value: { state: "partial", checked_at: at(),
    pending: 80, dead: 3, oldest_pending_at: at(-4), payload: { token: "fake-secret-must-not-leak" },
    errors: [{ id: "private-job", message: "fake-secret-must-not-leak" }] } } };
  const calls = mockDatabase(t, { states });
  const { body } = await invoke(statusHandler);
  assert.equal(body.health, "healthy");
  assert.deepEqual(body.notifications, { state: "partial", checked_at: at(), pending: 80, dead: 3, oldest_pending_at: at(-4) });
  assert.doesNotMatch(JSON.stringify(body), /fake-secret|private-job/);
  assert.ok(calls.some((call) => call.url.searchParams.get("key") === "eq.notifications_poll_status"));
  assert.ok(calls.every((call) => call.headers.apikey === "test-anon"));
  states.notifications_poll_status.value = { state: "unconfigured", checked_at: at(), pending: 0, dead: 0 };
  const unconfigured = (await invoke(statusHandler)).body;
  assert.equal(unconfigured.health, "healthy");
  assert.equal(unconfigured.notifications.state, "unconfigured");
  assert.equal(unconfigured.notifications.pending, 0);
  assert.equal(unconfigured.notifications.dead, 0);
  states.notifications_poll_status.value = { state: "idle", pending: -1, dead: "0", checked_at: "invalid" };
  const invalid = (await invoke(statusHandler)).body;
  assert.equal(invalid.notifications.pending, null);
  assert.equal(invalid.notifications.dead, null);
  assert.equal(invalid.notifications.checked_at, null);
});

test("missing, failed or inaccessible notification/cursor state does not break CT health", async (t) => {
  let failing = false;
  mockDatabase(t, { states: ctState(), fail: (table, url) => failing && table === "ingest_state"
    && ["eq.notifications_poll_status", "eq.ct_source_state"].includes(url.searchParams.get("key"))
    ? "fake-private-error" : null });
  for (const fail of [false, true]) {
    failing = fail;
    const { statusCode, body } = await invoke(statusHandler);
    assert.equal(statusCode, 200);
    assert.equal(body.health, "healthy");
    assert.deepEqual(body.notifications, { state: "unavailable", checked_at: null, pending: null, dead: null, oldest_pending_at: null });
    assert.doesNotMatch(JSON.stringify(body), /fake-private-error/);
  }
});

test("crt.sh cooldown exposes real attempt/retry times without refreshing the last check", async (t) => {
  const run = { source: "crtsh", checked_at: at(), ok: false, errors: [{ message: "crt.sh HTTP 502" }],
    details: { state: "cooldown", last_attempt_at: at(-3), last_success_at: at(-4), next_poll_at: at(1) } };
  mockDatabase(t, { states: ctState(), runs: [run] });
  const { body } = await invoke(statusHandler);
  const row = body.display_sources[0];
  assert.equal(row.status, "cooldown");
  assert.equal(row.ok, false);
  assert.equal(row.last_checked_at, run.details.last_attempt_at);
  assert.equal(row.next_poll_at, run.details.next_poll_at);
  run.checked_at = at(-2);
  const stale = await invoke(statusHandler);
  assert.equal(stale.body.display_sources[0].status, "stale");
});

test("intel status has four explicit rows, provider freshness and independent CT health", async (t) => {
  const states = { ...ctState(), intel_poll_status: { value: { checked_at: at(), sources: [
    { source: "openphish", status: "ok", ok: true, checked_at: at(-8), scanned_entries: 25, matched: 2, persisted: 2 },
    { source: "urlscan", status: "ok", ok: true, checked_at: at(-8) },
    { source: "urlhaus", status: "not_configured", ok: false, checked_at: at(-80) }
  ] } } };
  const calls = mockDatabase(t, { states, runs: [
    { source: "direct_ct", checked_at: at(), ok: true },
    { source: "urlscan", checked_at: at(), ok: false }
  ] });
  const response = await invoke(statusHandler);
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.health, "healthy");
  assert.equal(response.body.intel_schedule.cron, "7 * * * *");
  assert.equal(response.body.display_sources.length, 1);
  assert.equal(response.body.display_sources[0].ok, true);
  const intel = response.body.intel_sources;
  assert.deepEqual(intel.map((row) => row.source), ["openphish", "urlscan", "urlhaus", "threatfox"]);
  assert.deepEqual(intel.map((row) => row.status), ["ok", "stale", "not_configured", "pending"]);
  assert.equal(intel[0].persisted, 2);
  assert.equal(intel[1].ok, false);
  for (const row of intel) for (const key of ["source", "label", "status", "ok", "checked_at",
    "scanned_entries", "matched", "persisted", "errors", "details", "next_poll_at"]) assert.ok(key in row);
  assert.ok(calls.every((call) => call.headers.apikey === "test-anon"));
  assert.ok(calls.every((call) => call.url.searchParams.get("key") !== "eq.intel_source_state"));
});

test("source freshness respects next poll times and marks old CT successes stale", async (t) => {
  const states = { ...ctState(at(-2)), intel_poll_status: { value: { sources: [
    { source: "urlhaus", status: "ok", ok: true, checked_at: at(-8), next_poll_at: at(1) },
    { source: "threatfox", status: "cooldown", ok: false, checked_at: null, next_poll_at: at(52) }
  ] } } };
  mockDatabase(t, { states, runs: [{ source: "direct_ct", checked_at: at(-2), ok: true }] });
  const { body } = await invoke(statusHandler);
  assert.equal(body.health, "stale");
  assert.equal(body.display_sources[0].status, "stale");
  assert.equal(body.display_sources[0].ok, false);
  assert.equal(body.intel_sources[2].status, "ok");
  assert.equal(body.intel_sources[3].status, "cooldown");
});

test("unpolled cooldown and auth errors remain explicit until their retry deadline", async (t) => {
  const sources = [
    { source: "urlhaus", status: "auth_error", ok: false, checked_at: null, next_poll_at: at(24) },
    { source: "threatfox", status: "cooldown", ok: false, checked_at: null, next_poll_at: at(72) }
  ];
  mockDatabase(t, { states: { ...ctState(), intel_poll_status: { value: { sources } } } });
  const active = await invoke(statusHandler);
  assert.equal(active.statusCode, 200);
  assert.equal(active.body.health, "healthy");
  assert.deepEqual(active.body.intel_sources.slice(2).map((row) => row.status), ["auth_error", "cooldown"]);
  assert.ok(active.body.intel_sources.slice(2).every((row) => row.checked_at === null && !row.ok));

  for (const source of sources) source.next_poll_at = at(-0.01);
  const expired = await invoke(statusHandler);
  assert.equal(expired.statusCode, 200);
  assert.equal(expired.body.health, "healthy");
  assert.ok(expired.body.intel_sources.slice(2).every((row) => row.status === "stale" && !row.ok));
});

test("missing or failed intel status never makes CT health fail", async (t) => {
  const calls = mockDatabase(t, { states: ctState(), fail: (table, url) =>
    table === "ingest_state" && url.searchParams.get("key") === "eq.intel_poll_status" ? "unavailable" : null });
  const response = await invoke(statusHandler);
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.health, "healthy");
  assert.ok(response.body.intel_sources.every((row) => row.status === "unavailable" && !row.ok));
  assert.ok(calls.length > 0);
});

test("query and write failures surface instead of returning successful empty results", async (t) => {
  mockDatabase(t, { findings: [finding("failure")], fail: (table) => table === "intel_evidence" ? "storage failed" : null });
  assert.equal((await invoke(findingsHandler)).statusCode, 500);
  await assert.rejects(storage.upsertIntelEvidence([evidence("failure.example.com")]), /intel upsert failed: 503/);
  await assert.rejects(storage.pruneIntelEvidence(), /intel prune failed: 503/);
});

test("source filtering and method rejection preserve API compatibility", async (t) => {
  const calls = mockDatabase(t, { runs: [{ source: "direct_ct", checked_at: at() }, { source: "urlscan", checked_at: at() }] });
  assert.equal((await storage.listSourceRuns(24, "direct_ct")).length, 1);
  assert.equal((await storage.listSourceRuns()).length, 2);
  for (const handler of [findingsHandler, statusHandler]) {
    const response = await invoke(handler, {}, "POST");
    assert.equal(response.statusCode, 405);
    assert.equal(response.headers.Allow, "GET");
  }
  assert.equal(calls.length, 2);
});

test("hung database requests abort within the configured timeout", async (t) => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  t.mock.method(AbortSignal, "timeout", (ms) => {
    assert.ok(ms > 0 && ms <= 10000);
    return timeout(1);
  });
  t.mock.method(globalThis, "fetch", async (_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  }));
  const keepAlive = setTimeout(() => {}, 1000);
  try {
    await assert.rejects(storage.getServiceState("intel_source_state"), { name: "TimeoutError" });
  } finally { clearTimeout(keepAlive); }
});

test("migration and schema share evidence definitions and expose only public intel status", async () => {
  const migration = await readFile(new URL("../supabase/intel.sql", import.meta.url), "utf8");
  const schema = await readFile(new URL("../supabase/schema.sql", import.meta.url), "utf8");
  const definition = migration.slice(migration.indexOf("create table"), migration.indexOf("drop policy if exists ingest_state"));
  assert.ok(schema.includes(definition.trim()));
  for (const sql of [migration, schema]) {
    assert.match(sql, /expires_at > now\(\)/);
    assert.match(sql, /f\.suppressed = false/);
    assert.match(sql, /cardinality\(f\.domains\) = 0/);
    assert.match(sql, /f\.domains @> array\[intel_evidence\.domain\]/);
    assert.doesNotMatch(sql, /regexp_replace|unnest\(f\.domains\)/);
    assert.match(sql, /using gin \(domains\) where suppressed = false/);
    assert.match(sql, /f\.domains && hosts/);
    assert.match(sql, /distinct on \(finding\.registrable\)/);
    assert.match(sql, /revoke all on function public\.intel_candidate_findings\(integer\) from public, anon, authenticated/);
    assert.match(sql, /using \(key in \('ct_poll_status', 'ct_source_state', 'intel_poll_status'\)\)/);
    assert.doesNotMatch(sql, /intel_source_state/);
    assert.match(sql, /grant select, insert, update, delete on table public\.intel_evidence to service_role/);
    assert.doesNotMatch(sql, /grant [^;]*(?:insert|update|delete)[^;]*intel_evidence to anon/);
  }
  assert.match(migration, /drop policy if exists intel_evidence_public_read/);
});

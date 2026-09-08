import test from "node:test";
import assert from "node:assert/strict";
import { MINUTE, STATE_KEY, WORKFLOWS, configuration } from "../core.mjs";
import worker, { SchedulerCoordinator } from "../worker.mjs";
import { BASE_TIME, harness, run, TEST_ENV } from "./helpers.mjs";

test("concurrent duplicate ticks atomically reserve one dispatch per workflow", async () => {
  const h = harness();
  await Promise.all(Array.from({ length: 12 }, () => h.tick()));
  assert.equal(h.dispatches().length, 3);
  for (const w of WORKFLOWS) assert.equal(h.dispatches(w.file).length, 1);
  const state = await h.state();
  assert.equal(state.metrics.ticksProcessed, 1);
  assert.equal(state.metrics.ticksReceived, 12);
  assert.equal(state.workflows.ingest.lastSuccessAt, null);
  assert.equal(state.workflows.ingest.reservation.state, "accepted");
});

test("reservation is committed before GitHub receives the dispatch", async () => {
  const h = harness();
  h.override = async (url, init) => {
    if (init.method === "POST") {
      const state = await h.state();
      const name = WORKFLOWS.find(w => url.pathname.includes(w.file)).name;
      assert.equal(state.workflows[name].reservation.state, "reserved");
    }
  };
  await h.tick();
});

test("ingest and notification cadence is 15 minutes, intel is hourly", async () => {
  const h = harness();
  for (let minute = 0; minute <= 60; minute += 5) {
    h.time = BASE_TIME + minute * MINUTE;
    for (const rows of Object.values(h.rows)) for (const r of rows) { r.status = "completed"; r.conclusion = "success"; }
    await h.tick();
  }
  assert.equal(h.dispatches("ingest.yml").length, 5);
  assert.equal(h.dispatches("notifications.yml").length, 5);
  assert.equal(h.dispatches("intel.yml").length, 2);
  assert.deepEqual(JSON.parse(h.dispatches()[0].init.body), { ref: "main", inputs: { scheduler: "cloudflare" }, return_run_details: true });
});

for (const status of ["queued", "in_progress", "waiting", "pending", "requested"]) {
  test(`old ${status} run outside the recent page, including another branch, blocks dispatch`, async () => {
    const h = harness();
    h.rows["ingest.yml"] = Array.from({ length: 6 }, (_, i) => run(h.time, { id: 10 + i,
      created_at: new Date(h.time - (30 + i) * MINUTE).toISOString() }));
    h.rows["ingest.yml"].push(run(h.time, { id: 1, status, conclusion: null, head_branch: "release",
      created_at: new Date(h.time - 180 * MINUTE).toISOString() }));
    await h.tick();
    assert.equal(h.dispatches("ingest.yml").length, 0);
    assert.equal((await h.state()).workflows.ingest.decision, "active_run");
    assert.equal((await h.state()).workflows.ingest.activeRun.id, 1);
  });
}

test("recent manual, scheduled, failed or rerun starts all suppress a new dispatch", async () => {
  for (const event of ["schedule", "workflow_dispatch", "push"]) {
    const h = harness();
    h.rows["ingest.yml"] = [run(h.time, { event, conclusion: "failure", run_attempt: 2,
      run_started_at: new Date(h.time - MINUTE).toISOString() })];
    await h.tick();
    assert.equal(h.dispatches("ingest.yml").length, 0);
    assert.equal((await h.state()).workflows.ingest.decision, "recent_run");
  }
});

test("restart retains accepted reservation even when GitHub list has not caught up", async () => {
  const h = harness();
  h.visibleDispatch = false;
  await h.tick();
  h.advance(15);
  await h.tick();
  assert.equal(h.dispatches().length, 3);
  h.advance(15);
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 2);
  assert.equal(h.dispatches("intel.yml").length, 1);
});

test("current GitHub return_run_details response is accepted and reconciled", async () => {
  const h = harness();
  h.dispatchStatus = 200;
  await h.tick();
  assert.equal((await h.state()).workflows.ingest.reservation.runId, 100);
  h.advance(5);
  await h.tick();
  assert.equal((await h.state()).workflows.ingest.reservation.state, "observed");
});

test("definitive failed dispatch persists failure and retries after cooldown", async () => {
  const h = harness();
  let failed = false;
  h.override = (url, init) => {
    if (!failed && init.method === "POST" && url.pathname.includes("ingest.yml")) {
      failed = true;
      return new Response("never log this token", { status: 422 });
    }
  };
  const result = await h.tick();
  assert.equal(result.ok, false);
  let state = await h.state();
  assert.equal(state.workflows.ingest.reservation.state, "rejected");
  assert.equal(state.workflows.ingest.lastDispatchAcceptedAt, undefined);
  assert.equal(state.workflows.ingest.dispatchError, "github_http_422");
  h.advance(5);
  await h.tick();
  state = await h.state();
  assert.equal(h.dispatches("ingest.yml").length, 2);
  assert.equal(state.workflows.ingest.reservation.state, "accepted");
});

test("ambiguous dispatch timeout or 5xx keeps reservation and never immediately reposts", async () => {
  for (const failure of ["network", "http"]) {
    const h = harness();
    h.override = (url, init) => {
      if (init.method === "POST" && url.pathname.includes("ingest.yml")) {
        if (failure === "network") throw new Error(`private ${h.env.GITHUB_TOKEN}`);
        return new Response(null, { status: 502 });
      }
    };
    await h.tick();
    assert.equal((await h.state()).workflows.ingest.reservation.state, "unknown");
    h.override = undefined;
    h.advance(15);
    await h.tick();
    assert.equal(h.dispatches("ingest.yml").length, 1);
    h.advance(15);
    await h.tick();
    assert.equal(h.dispatches("ingest.yml").length, 2);
  }
});

test("crash after remote acceptance cannot erase the durable reservation", async () => {
  const h = harness();
  h.storage.failPut = state => ["accepted", "unknown"].includes(state.workflows.ingest.reservation?.state)
    || state.workflows.ingest.decision === "error";
  await assert.rejects(h.tick());
  assert.equal((await h.state()).workflows.ingest.reservation.state, "reserved");
  h.storage.failPut = undefined;
  h.advance(5);
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 1);
  assert.equal((await h.state()).metrics.abandonedTicks, 1);
  assert.equal((await h.state()).workflows.ingest.reservation.state, "observed");
});

test("expired lease fences a delayed old invocation from mutations and dispatches", async () => {
  const h = harness({ timeoutMs: 5000 });
  let release;
  let entered;
  const blocked = new Promise(resolve => { entered = resolve; });
  let first = true;
  h.override = async () => {
    if (first) {
      first = false;
      entered();
      await new Promise(resolve => { release = resolve; });
    }
  };
  const old = h.tick();
  await blocked;
  h.advance(5);
  await h.tick();
  release();
  await assert.rejects(old, /lease_lost/);
  assert.equal(h.dispatches().length, 3);
});

test("delayed ticks dispatch current work once without replaying missed intervals", async () => {
  const h = harness();
  await h.tick();
  h.advance(180);
  h.rows = Object.fromEntries(WORKFLOWS.map(w => [w.file, []]));
  await h.tick(BASE_TIME + 5 * MINUTE);
  assert.equal(h.dispatches().length, 6);
  let state = await h.state();
  assert.equal(state.metrics.lastScheduleDelayMs, 175 * MINUTE);
  assert.equal(state.metrics.missedTickWindows, 35);
  assert.equal(state.workflows.intel.reservation.slot, Math.floor(h.time / (60 * MINUTE)));
  h.advance(5);
  await h.tick(BASE_TIME + MINUTE);
  state = await h.state();
  assert.equal(h.dispatches().length, 6);
  assert.equal(state.metrics.ticksDuplicate, 1);
});

test("atomic reservation also enforces elapsed time across calendar slot boundaries", async () => {
  const h = harness();
  h.advance(14);
  await h.tick();
  h.advance(1);
  await h.tick();
  assert.equal(h.dispatches().length, 3);
});

test("GitHub 429 persists Retry-After and suppresses all GitHub requests on restart", async () => {
  const h = harness();
  h.override = url => url.hostname === "api.github.com" ? new Response(null, { status: 429, headers: { "Retry-After": "7200" } }) : undefined;
  await h.tick();
  assert.equal(h.calls.length, 1);
  assert.equal((await h.state()).github.retryAt, BASE_TIME + 120 * MINUTE);
  h.override = undefined;
  h.advance(60);
  await h.tick();
  assert.equal(h.calls.length, 1);
  h.advance(60);
  await h.tick();
  assert.equal(h.dispatches().length, 3);
});

test("secondary 403 and primary exhausted response respect the larger reset time", async () => {
  const h = harness();
  h.override = () => new Response(null, { status: 403, headers: {
    "Retry-After": "60", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": String((h.time + 90 * MINUTE) / 1000)
  } });
  await h.tick();
  assert.equal((await h.state()).github.retryAt, h.time + 90 * MINUTE);
  assert.equal(h.calls.length, 1);
});

test("local exponential backoff is capped, with one request per eligible failing tick", async () => {
  const h = harness();
  h.override = () => new Response(null, { status: 429 });
  const delays = [];
  for (let i = 0; i < 9; i++) {
    await h.tick();
    const retryAt = (await h.state()).github.retryAt;
    delays.push(retryAt - h.time);
    h.time = Math.max(retryAt, h.time + 5 * MINUTE);
  }
  assert.deepEqual(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60].map(v => v * MINUTE));
  assert.equal(h.calls.length, 9);
});

test("invalid GitHub responses fail closed and are visible instead of dispatching", async () => {
  const h = harness();
  h.override = url => url.hostname === "api.github.com" ? Response.json({ workflow_runs: [], total_count: 1 }) : undefined;
  const result = await h.tick();
  assert.equal(result.ok, false);
  assert.equal(h.dispatches().length, 0);
  assert.equal((await h.status()).workflows.ingest.error, "invalid_runs_response");
});

test("future success timestamps cannot make the watchdog healthy indefinitely", async () => {
  const h = harness();
  h.rows["ingest.yml"] = [run(h.time, { updated_at: new Date(h.time + 60 * MINUTE).toISOString() })];
  await h.tick();
  assert.equal((await h.status()).workflows.ingest.error, "invalid_run_timestamp");
  assert.equal(h.dispatches("ingest.yml").length, 0);
});

const telegramEnv = { TELEGRAM_BOT_TOKEN: "123456:fake-secret", TELEGRAM_CHAT_ID: "-12345" };

test("warning at 30m, critical at 60m and recovery are delivered once across restarts", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(29);
  await h.tick();
  assert.equal(h.alerts().length, 0);
  h.advance(1);
  await h.tick();
  assert.equal(h.alerts().length, 2);
  assert.match(JSON.parse(h.alerts()[0].init.body).text, /WARNING/);
  h.advance(5);
  await h.tick();
  assert.equal(h.alerts().length, 2);
  h.advance(25);
  await h.tick();
  assert.equal(h.alerts().length, 4);
  assert.match(JSON.parse(h.alerts()[2].init.body).text, /CRITICAL/);
  h.advance(5);
  h.healthy(0);
  await h.tick();
  assert.equal(h.alerts().length, 6);
  assert.match(JSON.parse(h.alerts()[4].init.body).text, /RECOVERY/);
  h.advance(5);
  h.healthy(0);
  await h.tick();
  assert.equal(h.alerts().length, 6);
  assert.equal((await h.status()).ok, true);
});

test("hourly intel warns at 90m and becomes critical at 120m", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(60);
  await h.tick();
  assert.equal((await h.status()).assessments.intel.level, 0);
  h.advance(30);
  await h.tick();
  assert.equal((await h.state()).incidents.intel.level, 1);
  h.advance(30);
  await h.tick();
  assert.equal((await h.state()).incidents.intel.level, 2);
});

test("queued work and failed runs never advance workflow success freshness", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(60);
  h.rows["ingest.yml"].unshift(run(h.time, { id: 3, conclusion: "failure", created_at: new Date(h.time - MINUTE).toISOString() }));
  await h.tick();
  const state = await h.state();
  assert.equal(state.workflows.ingest.lastSuccessAt, BASE_TIME);
  assert.equal(state.incidents.ingest.level, 2);
  assert.equal(state.workflows.ingest.latestRun.conclusion, "failure");
});

test("observation errors cannot emit a false recovery from cached success", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(30);
  await h.tick();
  h.advance(5);
  h.override = url => url.hostname === "api.github.com" ? new Response(null, { status: 401 }) : undefined;
  await h.tick();
  assert.equal((await h.state()).incidents.ingest.active, true);
  assert.equal(h.alerts().filter(c => JSON.parse(c.init.body).text.includes("RECOVERY")).length, 0);
});

test("disabled alert channel is reported truthfully and never marked delivered", async () => {
  const h = harness();
  await h.tick();
  h.advance(60);
  await h.tick();
  const status = await h.status();
  assert.equal(status.config.alertChannel, "none");
  assert.equal(status.config.proactiveAlerts, false);
  assert.equal(status.incidents.ingest.notice.state, "channel_unconfigured");
  assert.equal(status.metrics.alertsDelivered || 0, 0);
  assert.equal(h.alerts().length, 0);
  h.advance(5);
  h.env = { ...h.env, ...telegramEnv };
  await h.tick();
  assert.equal(h.alerts().length, 2);
});

test("no recovery message is sent for an incident that was never announced", async () => {
  const h = harness();
  await h.tick();
  h.advance(30);
  await h.tick();
  h.env = { ...h.env, ...telegramEnv };
  h.advance(5);
  h.healthy(0);
  await h.tick();
  assert.equal(h.alerts().length, 0);
  assert.equal((await h.state()).incidents.ingest.notice, null);
});

test("Telegram explicit rejection retries with a stable incident key and bounded cooldown", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.override = url => url.hostname === "api.telegram.org"
    ? Response.json({ ok: false, error_code: 429, parameters: { retry_after: 900 } }) : undefined;
  h.advance(30);
  assert.equal((await h.tick()).ok, false);
  const key = (await h.state()).incidents.ingest.notice.key;
  assert.equal(h.alerts().length, 1);
  h.advance(5);
  await h.tick();
  assert.equal(h.alerts().length, 1);
  h.override = undefined;
  h.advance(10);
  await h.tick();
  const notice = (await h.state()).incidents.ingest.notice;
  assert.equal(notice.key, key);
  assert.equal(notice.state, "sent");
  assert.equal(notice.attempts, 2);
});

test("ambiguous Telegram failure retries after delay with the same event key", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.override = url => { if (url.hostname === "api.telegram.org") throw new Error("token/secret in URL"); };
  h.advance(30);
  await h.tick();
  let state = await h.state();
  assert.equal(state.incidents.ingest.notice.state, "unknown");
  const key = state.incidents.ingest.notice.key;
  await h.tick();
  assert.equal(h.alerts().length, 1);
  h.override = undefined;
  h.advance(5);
  await h.tick();
  assert.equal(h.alerts().filter(c => JSON.parse(c.init.body).text.includes("ingest:")).length, 2);
  assert.equal((await h.state()).incidents.ingest.notice.key, key);
  h.advance(5);
  h.healthy(0);
  await h.tick();
  state = await h.state();
  assert.equal(state.incidents.ingest.notice.kind, "recovery");
  assert.equal(state.incidents.ingest.notice.state, "sent");
});

test("expired alert sending lease retries after restart and records recovery", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(30);
  h.storage.failPut = state => ["sent", "unknown"].includes(state.incidents.ingest?.notice?.state);
  assert.equal((await h.tick()).ok, false);
  assert.equal((await h.state()).incidents.ingest.notice.state, "sending");
  h.storage.failPut = undefined;
  h.advance(5);
  await h.tick();
  assert.equal((await h.state()).incidents.ingest.notice.state, "sent");
  assert.equal((await h.state()).metrics.alertLeasesRecovered, 1);
  assert.equal(h.alerts().filter(c => JSON.parse(c.init.body).text.includes("ingest:")).length, 2);
});

test("private HTTPS webhook accepts text success and uses a stable event ID", async () => {
  const h = harness({ env: { ALERT_WEBHOOK_URL: "https://alerts.example.test/private-secret-path?key=secret", ALERT_WEBHOOK_SECRET: "private-auth-token" } });
  h.healthy(0);
  await h.tick();
  h.advance(30);
  await h.tick();
  const call = h.alerts()[0];
  const body = JSON.parse(call.init.body);
  assert.equal(body.kind, "warning");
  assert.equal(body.subject, "ingest");
  assert.equal(body.event_id, (await h.state()).incidents.ingest.notice.key);
  assert.equal(call.init.headers.Authorization, "Bearer private-auth-token");
  assert.equal(call.init.redirect, "manual");
  const output = JSON.stringify(await h.status());
  assert.equal(output.includes("private-secret-path"), false);
  assert.equal(output.includes("private-auth-token"), false);
  h.advance(5);
  await h.tick();
  assert.equal(h.alerts().length, 2);
});

test("webhook is HTTPS only, cannot come from public request input, and never follows redirects", async () => {
  const h = harness({ env: { ALERT_WEBHOOK_URL: "http://alerts.example.test/" } });
  await h.tick();
  assert.equal(h.calls.length, 0);
  assert.ok((await h.status()).config.errors.includes("invalid_alert_webhook_url"));
  h.env.ALERT_WEBHOOK_URL = "https://alerts.example.test/";
  h.advance(5);
  h.healthy(0);
  await h.tick();
  h.advance(30);
  h.override = url => url.hostname === "alerts.example.test" ? new Response(null, { status: 302, headers: { Location: "https://elsewhere.test/" } }) : undefined;
  await h.tick();
  assert.equal((await h.state()).incidents.ingest.notice.state, "failed");
  assert.ok(h.calls.every(c => c.url.hostname !== "elsewhere.test"));
  const response = await worker.fetch(new Request("https://scheduler.test/notify?url=https://elsewhere.test"), h.env);
  assert.equal(response.status, 404);
});

test("notification dispatch continues in the same tick when CT dispatch is rejected", async () => {
  const h = harness();
  h.override = (url, init) => {
    if (init.method === "POST" && url.pathname.includes("ingest.yml")) {
      return new Response(null, { status: 422 });
    }
  };
  await h.tick();
  assert.equal(h.dispatches("notifications.yml").length, 1);
});

const heartbeatEnv = { SUPABASE_URL: "https://project.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test" };
function heartbeat(h, successAt = h.time) {
  h.heartbeatRows = [{ key: "ct_poll_status", checked_at: new Date(h.time).toISOString(),
    last_started_at: new Date(successAt).toISOString(), last_success_at: new Date(successAt).toISOString(),
    last_external_trigger_at: new Date(h.time).toISOString(), ok: "true", health: "ok" },
  { key: "intel_poll_status", checked_at: new Date(h.time).toISOString(), last_started_at: new Date(h.time).toISOString(),
    last_success_at: new Date(h.time).toISOString(), ok: "true", health: null },
  { key: "notifications_poll_status", checked_at: new Date(h.time).toISOString(),
    started_at: new Date(h.time).toISOString(), finished_at: new Date(h.time).toISOString(), state: "idle",
    pending: "0", processing: "0", dead: "0", oldest_pending_at: null }];
}

test("direct safe heartbeat uses last_success_at despite recent successful skipped workflows", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  h.advance(60);
  h.healthy(0);
  heartbeat(h, BASE_TIME);
  await h.tick();
  const status = await h.status();
  assert.equal(status.assessments.ingest.level, 2);
  assert.equal(status.assessments.ingest.successAgeMs, 60 * MINUTE);
  assert.equal(status.workflows.ingest.heartbeat.source, "last_success_at");
  assert.equal(status.workflows.ingest.heartbeat.lastExternalTriggerAt, h.time);
  assert.equal(status.assessments.notifications.healthy, true);
  const call = h.calls.find(c => c.url.hostname === "project.supabase.co");
  assert.equal(call.url.pathname, "/rest/v1/ingest_state");
  assert.match(call.url.searchParams.get("select"), /last_success_at/);
  assert.equal(call.url.searchParams.get("limit"), "3");
  assert.equal(call.init.headers.Authorization, undefined);
  assert.equal(call.init.headers.apikey, heartbeatEnv.SUPABASE_PUBLISHABLE_KEY);
  h.advance(5);
  heartbeat(h);
  h.healthy(0);
  await h.tick();
  assert.equal((await h.state()).incidents.ingest.notice.kind, "recovery");
});

test("failed or absent heartbeat never fabricates successful scan progress", async () => {
  const h = harness({ env: heartbeatEnv });
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  h.advance(60);
  h.healthy(0);
  heartbeat(h, BASE_TIME);
  h.heartbeatRows[0].ok = "false";
  h.heartbeatRows[0].health = "down";
  await h.tick();
  assert.equal((await h.status()).workflows.ingest.lastHeartbeatSuccessAt, BASE_TIME);
  assert.equal((await h.status()).assessments.ingest.healthy, false);
  h.advance(5);
  h.heartbeatRows = [];
  await h.tick();
  assert.equal((await h.status()).workflows.ingest.heartbeatError, "missing_heartbeat_row");
  assert.equal((await h.status()).assessments.ingest.observation, "unknown");
});

test("legacy public anon heartbeat is supported without granting service privileges", async () => {
  const key = `e30.${btoa(JSON.stringify({ role: "anon" }))}.signature`;
  const h = harness({ env: { ...heartbeatEnv, SUPABASE_PUBLISHABLE_KEY: key } });
  h.healthy(0);
  heartbeat(h);
  h.heartbeatRows[0].last_success_at = null;
  h.heartbeatRows[0].last_started_at = null;
  await h.tick();
  assert.equal((await h.status()).workflows.ingest.heartbeat.source, "checked_at_legacy");
  const call = h.calls.find(c => c.url.hostname.endsWith("supabase.co"));
  assert.equal(call.init.headers.Authorization, `Bearer ${key}`);
});

test("service-role JWT, secret key and untrusted Supabase URLs are rejected before any fetch", async () => {
  for (const value of ["sb_secret_private", `e30.${btoa(JSON.stringify({ role: "service_role" }))}.signature`]) {
    const h = harness({ env: { ...heartbeatEnv, SUPABASE_PUBLISHABLE_KEY: value } });
    await h.tick();
    assert.equal(h.calls.length, 0);
    assert.ok((await h.status()).config.errors.includes("invalid_public_heartbeat_config"));
  }
  for (const url of ["https://project.supabase.co.attacker.test", "http://project.supabase.co", "https://secret@project.supabase.co", "https://project.supabase.co?token=secret"]) {
    assert.ok(configuration({ ...TEST_ENV, ...heartbeatEnv, SUPABASE_URL: url }).errors.includes("invalid_public_heartbeat_config"));
  }
});

test("status requires exact bearer auth and exposes no public tick or mutation route", async () => {
  let forwarded = 0;
  const env = { ...TEST_ENV, SCHEDULER: { idFromName: name => name, get: () => ({ fetch: async () => { forwarded++; return Response.json({ ok: true }); } }) } };
  for (const authorization of [undefined, "wrong", `Bearer ${TEST_ENV.STATUS_TOKEN}suffix`]) {
    const response = await worker.fetch(new Request("https://scheduler.test/status", { headers: authorization ? { Authorization: authorization } : {} }), env);
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  }
  assert.equal(forwarded, 0);
  assert.equal((await worker.fetch(new Request(`https://scheduler.test/status?token=${TEST_ENV.STATUS_TOKEN}`), env)).status, 401);
  assert.equal((await worker.fetch(new Request("https://scheduler.test/tick", { method: "POST" }), env)).status, 404);
  assert.equal((await worker.fetch(new Request("https://scheduler.test/status", { method: "POST", headers: { Authorization: `Bearer ${TEST_ENV.STATUS_TOKEN}` } }), env)).status, 405);
  assert.equal((await worker.fetch(new Request("https://scheduler.test/status", { headers: { Authorization: `Bearer ${TEST_ENV.STATUS_TOKEN}` } }), env)).status, 200);
  assert.equal(forwarded, 1);
});

test("missing status secret fails closed; status never triggers external network calls", async () => {
  assert.equal((await worker.fetch(new Request("https://scheduler.test/status"), {})).status, 503);
  const h = harness();
  const coordinator = new SchedulerCoordinator({ storage: h.storage }, h.env);
  const response = await coordinator.fetch(new Request("https://internal/status"));
  assert.equal(response.status, 503);
  assert.equal((await response.json()).state, "not_started");
  assert.equal(h.calls.length, 0);
});

test("scheduled failures reject the invocation with only a constant safe message", async () => {
  const env = { SCHEDULER: { idFromName: name => name, get: () => ({ fetch: async () => { throw new Error("https://token@private.invalid"); } }) } };
  await assert.rejects(worker.scheduled({ scheduledTime: BASE_TIME }, env), error => error.message === "scheduler_tick_failed");
});

test("protected status detects a stopped cron from persisted completion age", async () => {
  const h = harness();
  h.healthy(0);
  await h.tick();
  assert.equal((await h.status()).ok, true);
  h.advance(10);
  assert.equal((await h.status()).ok, false);
  assert.equal((await h.status()).tickAgeMs, 10 * MINUTE);
});

test("configuration changes cannot silently reset durable repository deduplication", async () => {
  const h = harness();
  await h.tick();
  h.env.GITHUB_REPO = "different-repo";
  h.advance(5);
  await h.tick();
  assert.equal(h.dispatches().length, 3);
  assert.ok((await h.state()).configErrors.includes("target_changed_requires_migration"));
});

test("pause continues watchdog observation without dispatching", async () => {
  const h = harness({ env: { DISPATCH_ENABLED: "false" } });
  await h.tick();
  assert.equal(h.dispatches().length, 0);
  assert.equal(h.calls.length, 6);
  assert.equal((await h.state()).workflows.ingest.decision, "dispatch_paused");
});

test("secrets and raw error payloads never enter state or status", async () => {
  const h = harness({ env: telegramEnv });
  h.override = () => new Response(`private ${h.env.GITHUB_TOKEN} ${h.env.TELEGRAM_BOT_TOKEN}`, { status: 401 });
  await h.tick();
  const serialized = JSON.stringify(await h.status());
  for (const secret of [h.env.GITHUB_TOKEN, h.env.STATUS_TOKEN, h.env.TELEGRAM_BOT_TOKEN, h.env.TELEGRAM_CHAT_ID]) assert.equal(serialized.includes(secret), false);
  assert.match(serialized, /github_http_401/);
});

test("bounded state and request counts stay within the free-plan design budget", async () => {
  const h = harness();
  for (let i = 0; i < 100; i++) {
    await h.tick();
    h.advance(5);
  }
  const state = await h.state();
  assert.ok(state.events.length <= 48);
  assert.ok(state.metrics.maxTickRequests <= 36);
  assert.ok(JSON.stringify(state).length < 32768);
  assert.equal(h.storage.values.size, 1);
  assert.ok(h.storage.writes < 15000);
});

test("invalid future and nonnumeric tick timestamps do not mutate storage", async () => {
  const h = harness();
  for (const value of [NaN, Infinity, 0, h.time + 2 * MINUTE]) await assert.rejects(h.tick(value), /invalid_tick/);
  assert.equal(await h.storage.get(STATE_KEY), undefined);
});

test("successful skipped fallback at :07 cannot postpone the real scan due at :15", async () => {
  const h = harness({ env: heartbeatEnv });
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  h.advance(15);
  h.healthy(8);
  heartbeat(h, BASE_TIME);
  h.heartbeatRows[1].last_started_at = new Date(BASE_TIME - 60 * MINUTE).toISOString();
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 1);
  assert.equal(h.dispatches("intel.yml").length, 1);
  assert.equal(h.calls[0].url.hostname, "project.supabase.co");
  assert.equal((await h.state()).workflows.ingest.reservation.at, h.time);
});

test("recent actual start prevents duplicate scans even if GitHub history is missing", async () => {
  const h = harness({ env: heartbeatEnv });
  heartbeat(h);
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 0);
  assert.equal((await h.state()).workflows.ingest.decision, "recent_actual_start");
  assert.equal(h.dispatches("intel.yml").length, 0);
  assert.equal(h.dispatches("notifications.yml").length, 1);
});

test("failed heartbeat read gates scan dispatch but still allows notification draining", async () => {
  const h = harness({ env: heartbeatEnv });
  h.override = url => url.hostname.endsWith("supabase.co") ? new Response(null, { status: 503 }) : undefined;
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 0);
  assert.equal(h.dispatches("intel.yml").length, 0);
  assert.equal(h.dispatches("notifications.yml").length, 1);
  assert.equal((await h.state()).workflows.ingest.decision, "heartbeat_unavailable");
});

test("modern null last_success_at cannot be replaced by a recent checked_at", async () => {
  const h = harness({ env: heartbeatEnv });
  h.healthy(0);
  heartbeat(h);
  h.heartbeatRows[0].last_success_at = null;
  await h.tick();
  assert.equal((await h.state()).workflows.ingest.lastHeartbeatSuccessAt, undefined);
  assert.equal((await h.status()).assessments.ingest.healthy, false);
  assert.equal((await h.state()).workflows.ingest.metrics.successesObserved || 0, 0);
});

test("pending outbox warns even when notifications workflow succeeds while channel is unconfigured", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  h.advance(30);
  h.healthy(0);
  heartbeat(h);
  Object.assign(h.heartbeatRows[2], { pending: "10", processing: "1", state: "unconfigured",
    oldest_pending_at: new Date(BASE_TIME).toISOString() });
  await h.tick();
  let state = await h.state();
  assert.equal(state.incidents.notifications.level, 1);
  assert.equal(state.workflows.notifications.heartbeat.outbox.channelUnavailable, true);
  assert.equal((await h.status()).assessments.notifications.backlogAgeMs, 30 * MINUTE);
  h.advance(30);
  h.healthy(0);
  heartbeat(h);
  Object.assign(h.heartbeatRows[2], { pending: "10", state: "unconfigured", oldest_pending_at: new Date(BASE_TIME).toISOString() });
  await h.tick();
  assert.equal((await h.state()).incidents.notifications.level, 2);
  h.advance(5);
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  state = await h.state();
  assert.equal(state.incidents.notifications.notice.kind, "recovery");
  assert.equal(state.incidents.notifications.notice.state, "sent");
});

test("outbox dead letters produce critical even with a fresh successful workflow", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  h.healthy(0);
  heartbeat(h);
  h.heartbeatRows[2].dead = "2";
  await h.tick();
  assert.equal((await h.state()).incidents.notifications.level, 2);
  assert.equal(h.alerts().length, 1);
  assert.equal((await h.status()).ok, false);
});

test("absent public outbox row is visible and never misreported as an empty backlog", async () => {
  const h = harness({ env: heartbeatEnv });
  h.healthy(0);
  heartbeat(h, BASE_TIME - 15 * MINUTE);
  h.heartbeatRows.pop();
  await h.tick();
  assert.equal((await h.state()).workflows.notifications.heartbeatError, "missing_heartbeat_row");
  assert.equal((await h.state()).heartbeat.error, null);
  assert.equal(h.dispatches("ingest.yml").length, 1);
  assert.equal((await h.status()).ok, false);
});

test("repeated ambiguous alert delivery reaches a visible dead letter after five attempts", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(60);
  h.override = url => { if (url.hostname === "api.telegram.org") throw new Error("lost response"); };
  await h.tick();
  const key = (await h.state()).incidents.ingest.notice.key;
  for (let i = 1; i < 5; i++) {
    const state = await h.state();
    h.time = Math.max(state.incidents.ingest.notice.retryAt, state.telegram.retryAt, h.time + 5 * MINUTE);
    await h.tick();
  }
  let state = await h.state();
  assert.equal(state.incidents.ingest.notice.attempts, 5);
  assert.equal(state.incidents.ingest.notice.state, "dead_letter");
  assert.equal(state.incidents.ingest.notice.key, key);
  const before = h.alerts().filter(c => JSON.parse(c.init.body).text.includes("ingest:")).length;
  h.advance(120);
  await h.tick();
  assert.equal(h.alerts().filter(c => JSON.parse(c.init.body).text.includes("ingest:")).length, before);
  assert.ok((await h.state()).metrics.alertDeadLetters >= 1);
});

test("nonexpired sending lease cannot be taken over by a second delivery attempt", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.advance(30);
  await h.tick();
  await h.storage.seed(s => {
    s.incidents.ingest.notice.state = "sending";
    s.incidents.ingest.notice.leaseUntil = h.time + 10 * MINUTE;
  });
  const before = h.alerts().length;
  h.advance(5);
  await h.tick();
  assert.equal(h.alerts().length, before);
  assert.equal((await h.state()).incidents.ingest.notice.state, "sending");
});

test("actual start/success metrics dedupe heartbeat snapshots and survive restart", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  h.advance(5);
  await h.tick();
  let metrics = (await h.state()).workflows.ingest.metrics;
  assert.equal(metrics.startsObserved, 1);
  assert.equal(metrics.successesObserved, 1);
  assert.equal(metrics.firstActualStartObservedAt, BASE_TIME);
  h.advance(10);
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  metrics = (await h.state()).workflows.ingest.metrics;
  assert.equal(metrics.startsObserved, 2);
  assert.equal(metrics.successesObserved, 2);
  assert.equal(metrics.maxActualStartGapMs, 15 * MINUTE);
  assert.equal(metrics.maxActualSuccessGapMs, 15 * MINUTE);
  assert.equal((await h.state()).soak.workflows.ingest.startsObserved, 2);
});

test("unconfigured startup cannot accrue configured duration or actual soak metrics", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv, GITHUB_TOKEN: "" } });
  await h.tick();
  h.advance(24 * 60);
  assert.equal((await h.status()).soak, null);
  h.env.GITHUB_TOKEN = TEST_ENV.GITHUB_TOKEN;
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  const state = await h.state();
  assert.equal(state.configuredSince, h.time);
  assert.equal(state.soak.activeSince, h.time);
  assert.equal(state.soak.observedActiveMs, 0);
  assert.equal(state.soak.workflows.ingest.startsObserved, 1);
});

test("elapsed 24h cannot count as observed 24h when cron stopped or alert channel is absent", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  h.advance(24 * 60);
  let status = await h.status();
  assert.equal(status.soak.active, false);
  assert.equal(status.soak.observedActiveMs, 0);
  assert.equal(status.soak.validation, "not_evaluated");
  h.healthy(0);
  heartbeat(h);
  await h.tick();
  status = await h.status();
  assert.equal(status.soak.unobservedGaps, 1);
  assert.equal(status.soak.observedActiveMs, 0);
  assert.equal(status.soak.workflows.ingest.maxActualStartGapMs, 24 * 60 * MINUTE);
  h.advance(5);
  delete h.env.TELEGRAM_BOT_TOKEN;
  delete h.env.TELEGRAM_CHAT_ID;
  await h.tick();
  assert.equal((await h.status()).soak.active, false);
});

test("simulated full day records cadence evidence without asserting a real soak pass", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  for (let minute = 0; minute <= 24 * 60; minute += 5) {
    h.time = BASE_TIME + minute * MINUTE;
    h.healthy(0);
    heartbeat(h, BASE_TIME + Math.floor(minute / 15) * 15 * MINUTE);
    const hourly = new Date(BASE_TIME + Math.floor(minute / 60) * 60 * MINUTE).toISOString();
    h.heartbeatRows[1].last_started_at = hourly;
    h.heartbeatRows[1].last_success_at = hourly;
    const quarter = new Date(BASE_TIME + Math.floor(minute / 15) * 15 * MINUTE).toISOString();
    h.heartbeatRows[2].started_at = quarter;
    h.heartbeatRows[2].finished_at = quarter;
    await h.tick();
  }
  const status = await h.status();
  assert.equal(status.soak.observedActiveMs, 24 * 60 * MINUTE);
  assert.equal(status.soak.workflows.ingest.startsObserved, 97);
  assert.equal(status.soak.workflows.ingest.successesObserved, 97);
  assert.equal(status.soak.workflows.intel.startsObserved, 25);
  assert.equal(status.soak.workflows.notifications.startsObserved, 97);
  assert.equal(status.soak.workflows.ingest.maxActualStartGapMs, 15 * MINUTE);
  assert.equal(status.soak.workflows.ingest.maxActualSuccessGapMs, 15 * MINUTE);
  assert.equal(status.soak.maxTickGapMs, 5 * MINUTE);
  assert.equal(status.soak.validation, "not_evaluated");
  assert.ok(status.events.length <= 48);
});

test("real Telegram HTTP 429 honors its JSON retry_after across worker restarts", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.override = url => url.hostname === "api.telegram.org" ? Response.json({ ok: false, error_code: 429,
    description: "private error must not be persisted", parameters: { retry_after: 7200 } }, { status: 429 }) : undefined;
  h.advance(30);
  await h.tick();
  assert.equal((await h.state()).telegram.retryAt, h.time + 120 * MINUTE);
  assert.equal((await h.state()).incidents.ingest.notice.retryAt, h.time + 120 * MINUTE);
  h.advance(60);
  await h.tick();
  assert.equal(h.alerts().length, 1);
  assert.equal(JSON.stringify(await h.status()).includes("private error"), false);
});

test("30-second actual queue delays plus skipped fallback overlaps sustain 15m CT cadence for a day", async () => {
  const h = harness({ env: { ...heartbeatEnv, ...telegramEnv } });
  h.dispatchStatus = 200;
  for (const w of WORKFLOWS) h.rows[w.file] = [run(h.time)];
  h.override = (_, init) => { if (init.method === "POST") h.time += 250; };
  for (let minute = 0; minute <= 1440; minute += 5) {
    h.time = BASE_TIME + minute * MINUTE;
    // The native :07/:22/:37/:52 fallback completes successfully but its scan is skipped.
    for (let prior = Math.max(0, minute - 4); prior <= minute; prior++) {
      if (prior % 15 === 7) {
        const at = BASE_TIME + prior * MINUTE;
        h.rows["ingest.yml"].push(run(at, { id: h.nextId++, created_at: new Date(at).toISOString(),
          run_started_at: new Date(at).toISOString(), updated_at: new Date(at).toISOString() }));
      }
      if (prior % 60 === 7) {
        const at = BASE_TIME + prior * MINUTE;
        h.rows["intel.yml"].push(run(at, { id: h.nextId++, created_at: new Date(at).toISOString(),
          run_started_at: new Date(at).toISOString(), updated_at: new Date(at).toISOString() }));
      }
    }
    heartbeat(h);
    for (const [index, w] of WORKFLOWS.entries()) {
      let actualStart = BASE_TIME - w.interval;
      let actualSuccess = actualStart;
      for (const r of h.rows[w.file].filter(r => r.event === "workflow_dispatch")) {
        const created = Date.parse(r.created_at);
        const started = created + 30000;
        const success = created + 90000;
        if (started <= h.time) actualStart = Math.max(actualStart, started);
        if (success <= h.time) {
          actualSuccess = Math.max(actualSuccess, success);
          Object.assign(r, { status: "completed", conclusion: "success",
            run_started_at: new Date(started).toISOString(), updated_at: new Date(success).toISOString() });
        }
      }
      Object.assign(h.heartbeatRows[index], { last_started_at: new Date(actualStart).toISOString(),
        last_success_at: new Date(actualSuccess).toISOString(), checked_at: new Date(actualSuccess).toISOString(),
        scheduler_trigger: "cloudflare", finished_at: new Date(actualSuccess).toISOString() });
    }
    await h.tick(BASE_TIME + minute * MINUTE);
  }
  const state = await h.state();
  assert.equal(h.dispatches("ingest.yml").length, 97);
  assert.equal(h.dispatches("intel.yml").length, 25);
  assert.equal(h.dispatches("notifications.yml").length, 97);
  const metrics = state.soak.workflows.ingest;
  assert.equal(metrics.startsObserved, 96);
  assert.equal(metrics.successesObserved, 96);
  assert.equal(metrics.maxActualStartGapMs, 15 * MINUTE);
  assert.equal(metrics.maxActualSuccessGapMs, 15 * MINUTE);
  assert.equal(state.workflows.ingest.reservation.origin, "cloudflare");
  assert.equal(state.workflows.ingest.heartbeat.origin, "cloudflare");
  assert.ok(state.soak.observedActiveMs >= 24 * 60 * MINUTE);
});

test("malformed intel heartbeat cannot gate a CT scan with valid due data", async () => {
  const h = harness({ env: heartbeatEnv });
  h.healthy(0);
  heartbeat(h, BASE_TIME - 15 * MINUTE);
  h.heartbeatRows[1].checked_at = "invalid";
  assert.equal((await h.tick()).ok, false);
  assert.equal(h.dispatches("ingest.yml").length, 1);
  assert.equal(h.dispatches("intel.yml").length, 0);
  const state = await h.state();
  assert.equal(state.workflows.intel.heartbeatError, "invalid_run_timestamp");
  assert.equal(state.workflows.ingest.heartbeatError, null);
  assert.equal(state.workflows.intel.decision, "heartbeat_unavailable");
});

test("invalid outbox counts are isolated from both valid scan heartbeats", async () => {
  const h = harness({ env: heartbeatEnv });
  heartbeat(h, BASE_TIME - 15 * MINUTE);
  h.heartbeatRows[1].last_started_at = new Date(BASE_TIME - 60 * MINUTE).toISOString();
  h.heartbeatRows[2].pending = "invalid";
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 1);
  assert.equal(h.dispatches("intel.yml").length, 1);
  assert.equal((await h.state()).workflows.notifications.heartbeatError, "invalid_outbox_counts");
  assert.equal((await h.status()).assessments.notifications.backlogMonitoring, "unknown");
});

test("a missing first intel heartbeat bootstraps from GitHub while CT remains independent", async () => {
  const h = harness({ env: heartbeatEnv });
  heartbeat(h, BASE_TIME - 15 * MINUTE);
  h.heartbeatRows.splice(1, 1);
  await h.tick();
  assert.equal(h.dispatches("ingest.yml").length, 1);
  assert.equal(h.dispatches("intel.yml").length, 1);
  assert.equal((await h.state()).workflows.intel.reservation.heartbeatBootstrap, true);
  h.advance(5);
  await h.tick();
  assert.equal(h.dispatches("intel.yml").length, 1);
});

test("recovery retains a rejected warning and delivers a summary after its 429 cooldown", async () => {
  const h = harness({ env: telegramEnv });
  h.healthy(0);
  await h.tick();
  h.override = url => url.hostname === "api.telegram.org" ? Response.json({ ok: false, error_code: 429,
    parameters: { retry_after: 3600 } }, { status: 429 }) : undefined;
  h.advance(30);
  await h.tick();
  assert.equal((await h.state()).incidents.ingest.notice.state, "failed");
  assert.equal(h.alerts().length, 1);
  h.advance(5);
  h.healthy(0);
  h.override = undefined;
  await h.tick();
  let state = await h.state();
  const recoveryKey = state.incidents.ingest.notice.key;
  assert.equal(state.incidents.ingest.active, false);
  assert.equal(state.incidents.ingest.previousNotice.state, "failed");
  assert.equal(state.incidents.ingest.previousNotice.attempts, 1);
  assert.equal(state.incidents.ingest.notice.kind, "recovery");
  assert.equal(state.incidents.ingest.notice.summary, true);
  assert.equal(state.incidents.ingest.notice.state, "pending");
  assert.equal((await h.status()).ok, false);
  assert.equal(h.alerts().length, 1);
  h.advance(55);
  h.healthy(0);
  await h.tick();
  state = await h.state();
  assert.equal(state.incidents.ingest.notice.key, recoveryKey);
  assert.equal(state.incidents.ingest.notice.state, "sent");
  assert.equal(state.incidents.ingest.previousNotice.state, "failed");
  const texts = h.alerts().map(c => JSON.parse(c.init.body).text);
  assert.ok(texts.some(text => text.includes("RECOVERY: ingest") && text.includes("Outage already resolved")));
  assert.equal((await h.status()).ok, true);
});

test("stalled Telegram 429 body cannot shorten the received one-hour cooldown", { timeout: 10000 }, async () => {
  const h = harness({ env: telegramEnv, timeoutMs: 20 });
  h.healthy(0);
  await h.tick();
  h.override = url => url.hostname === "api.telegram.org"
    ? new Response(new ReadableStream({ start() {} }), { status: 429, headers: { "Retry-After": "3600" } }) : undefined;
  h.advance(30);
  await h.tick();
  const state = await h.state();
  assert.equal(state.telegram.retryAt, h.time + 60 * MINUTE);
  assert.equal(state.incidents.ingest.notice.retryAt, h.time + 60 * MINUTE);
  assert.equal(state.incidents.ingest.notice.state, "failed");
  h.advance(5);
  await h.tick();
  assert.equal(h.alerts().length, 1);
});

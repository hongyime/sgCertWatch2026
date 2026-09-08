import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

// SQL integration is opt-in against an EMPTY disposable local PostgreSQL database:
// OUTBOX_TEST_DATABASE_URL=postgres://...@127.0.0.1:port/notification_outbox_test
// OUTBOX_TEST_PG_MODULE=/absolute/path/to/pg/lib/index.js (or install pg outside repo).
// No credentials from the application environment are used for SQL tests.
// CI must supply the database URL. A pg dev dependency needs no PG_MODULE override.
// Bootstrap requires a fresh database and a role that can create roles/tables.
const databaseUrl = process.env.OUTBOX_TEST_DATABASE_URL;
if (!databaseUrl && ((process.env.CI && !["false", "0"].includes(process.env.CI.toLowerCase()))
  || process.env.OUTBOX_REQUIRE_SQL === "1")) {
  throw new Error("Mandatory SQL tests require OUTBOX_TEST_DATABASE_URL pointing to disposable localhost notification_outbox_test");
}
process.env.SUPABASE_URL = "https://outbox-test.invalid";
process.env.SUPABASE_SERVICE_ROLE_KEY = "outbox-test-service-key";
const { enqueueNotificationAlerts, drainNotificationOutbox, retryDeadNotifications, notificationIdentity, publishNotificationOutboxStatus } =
  await import("../lib/notification-outbox.js");
const { runNotifications } = await import("./run-notifications.mjs");
let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log(`ok ${passed} - ${name}`);
}
const finding = (i, extra = {}) => ({
  id: `finding-${i}`, registrable: `lure-${i}.test`, score: 85, severity: "high",
  observed_at: "2026-09-08T00:00:00Z", matched_brands: ["Example"], signals: [], ...extra
});
const telegramEnv = { TELEGRAM_BOT_TOKEN: "outbox:secret-token", TELEGRAM_CHAT_ID: "123" };
const success = async () => Response.json({ ok: true, result: { message_id: 42, chat: { id: 123 } } });
const drainOptions = { env: telegramEnv, spacingMs: 0, maxRunMs: 600000, fetch: success };

await check("eligible jobs enqueue in full, stable batches; unconfigured Telegram retains work", async () => {
  const batches = [];
  const inputs = Array.from({ length: 451 }, (_, i) => finding(i));
  inputs.push(finding("low", { score: 20 }), finding("suppressed", { suppressed: true }));
  const result = await enqueueNotificationAlerts(inputs, { env: {}, rpc: async (name, args) => {
    assert.equal(name, "notification_outbox_enqueue");
    batches.push(args.p_jobs);
    assert.equal(args.p_max_attempts, 8);
    return { queued: args.p_jobs.length, deduped: 0 };
  } });
  assert.deepEqual(result, { candidates: 451, queued: 451, deduped: 0 });
  assert.deepEqual(batches.map(batch => batch.length), [200, 200, 51]);
  assert.equal(new Set(batches.flat().map(job => job.id)).size, 451);
  assert.equal(batches[0][0].id, notificationIdentity(inputs[0]));
  assert.equal(batches[0][0].payload.registrable, inputs[0].registrable);
  assert.ok(!JSON.stringify(batches).includes("secret-token"));
});

await check("enqueue rejects incomplete receipts and later batch failure", async () => {
  await assert.rejects(enqueueNotificationAlerts([finding(1)], { rpc: async () => ({ queued: 0, deduped: 0 }) }), /receipt/);
  let calls = 0;
  await assert.rejects(enqueueNotificationAlerts(Array.from({ length: 201 }, (_, i) => finding(i)), {
    rpc: async (_name, args) => {
      if (++calls === 2) throw new Error("database unavailable");
      return { queued: args.p_jobs.length, deduped: 0 };
    }
  }), /database unavailable/);
  assert.equal(calls, 2);
  await assert.rejects(enqueueNotificationAlerts([finding(1, { id: undefined })]), /stable finding.id/);
});

await check("enqueue ownership loss before or after a batch prevents later writes", async () => {
  for (const loseAfterBatch of [false, true]) {
    let owned = loseAfterBatch;
    let writes = 0;
    await assert.rejects(enqueueNotificationAlerts(Array.from({ length: 201 }, (_, i) => finding(i)), {
      assertOwned: () => { if (!owned) throw new Error("mock lease lost"); },
      rpc: async (_name, args) => {
        writes++;
        owned = false;
        return { queued: args.p_jobs.length, deduped: 0 };
      }
    }), /mock lease lost/);
    assert.equal(writes, loseAfterBatch ? 1 : 0);
  }
});

await check("missing either Telegram credential never claims, retries or performs I/O", async () => {
  for (const env of [{}, { TELEGRAM_BOT_TOKEN: "x" }, { TELEGRAM_CHAT_ID: "x" }]) {
    const result = await drainNotificationOutbox({ env, rpc: () => assert.fail("must not claim"),
      fetch: () => assert.fail("must not send") });
    assert.equal(result.state, "unconfigured");
    assert.equal(result.claimed, 0);
  }
});

await check("explicit disable flag gates enqueue/drain without changing retained work", async () => {
  const rpc = () => assert.fail("disabled channel must not touch queue");
  assert.deepEqual(await enqueueNotificationAlerts([finding(1)], { enabled: false, rpc }), {
    candidates: 0, queued: 0, deduped: 0, state: "disabled"
  });
  assert.equal((await drainNotificationOutbox({ ...drainOptions, enabled: false, rpc })).state, "disabled");
  assert.equal((await drainNotificationOutbox({ env: { NOTIFICATIONS_ENABLED: "false" }, rpc })).state, "disabled");
  await assert.rejects(enqueueNotificationAlerts([finding(1)], { enabled: "maybe", rpc }), /enabled flag/);
});

await check("runner publishes fresh aggregate status without jobs, recipients or error strings", async () => {
  let published = false;
  const aggregate = { checked_at: new Date().toISOString(), pending: 2, processing: 0, dead: 0, sent: 0,
    suppressed: 0, ready: 2, oldest_pending_at: null, next_retry_at: null, last_sent_at: null };
  const result = await runNotifications([], { env: {}, rpc: async (name, args) => {
    assert.equal(name, "notification_outbox_status");
    assert.deepEqual(args, {});
    return aggregate;
  }, setState: async (key, value) => {
    assert.equal(key, "notifications_poll_status");
    assert.equal(value.state, "unconfigured");
    assert.equal(value.queued, 2);
    published = true;
  } });
  assert.ok(published);
  assert.equal(result.status.counts.pending, 2);
  const started = new Date().toISOString();
  await publishNotificationOutboxStatus({ state: "partial", claimed: 1, errors: [{
    id: "private-job-id", error: "private-error", recipient: "private-recipient"
  }] }, started, { rpc: async () => ({ ...aggregate, unwanted: "private-data" }), setState: async (_key, value) => {
    assert.equal(value.run.errors, 1);
    assert.ok(!JSON.stringify(value).includes("private-"));
  } });
});

await check("100 notifications drain across bounded runs without the old 20-job loss", async () => {
  const pending = Array.from({ length: 100 }, (_, i) => ({ id: notificationIdentity(finding(i)), payload: finding(i) }));
  const owners = new Map();
  const sent = new Set();
  const rpc = async (name, args) => {
    if (name === "notification_outbox_claim") {
      const job = pending.shift();
      if (!job) return [];
      owners.set(job.id, args.p_owner);
      return [job];
    }
    assert.equal(name, "notification_outbox_ack");
    assert.equal(owners.get(args.p_id), args.p_owner);
    assert.equal(args.p_message_id, 42);
    assert.ok(!sent.has(args.p_id));
    sent.add(args.p_id);
    return true;
  };
  const first = await drainNotificationOutbox({ ...drainOptions, rpc, maxJobs: 20 });
  assert.equal(first.telegram, 20);
  assert.equal(first.state, "partial", "A bounded batch does not establish an empty queue");
  assert.deepEqual(first.errors, []);
  assert.equal(pending.length, 80);
  const second = await drainNotificationOutbox({ ...drainOptions, rpc });
  assert.equal(second.telegram, 80);
  assert.equal(second.state, "drained", "Completion requires an actual empty claim");
  assert.equal(sent.size, 100);
  assert.equal(new Set(owners.values()).size, 100, "fresh ownership token on every attempt");
});

await check("429 persists Retry-After and stops claiming; transport secrets stay out of retry", async () => {
  for (const rateLimited of [true, false]) {
    const calls = [];
    const result = await drainNotificationOutbox({ ...drainOptions, maxJobs: 1,
      fetch: rateLimited ? async () => Response.json({ ok: false, error_code: 429,
        parameters: { retry_after: 7200 }, description: telegramEnv.TELEGRAM_BOT_TOKEN }, { status: 429 })
        : async url => { throw new Error(url); },
      rpc: async (name, args) => {
        calls.push({ name, args });
        if (name === "notification_outbox_claim") return [{ id: notificationIdentity(finding(1)), payload: finding(1) }];
        assert.equal(name, "notification_outbox_retry");
        assert.equal(args.p_rate_limited, rateLimited);
        assert.equal(args.p_retry_after_seconds, rateLimited ? 7200 : 0);
        return "pending";
      }
    });
    assert.equal(calls.length, 2);
    assert.equal(result.telegram, 0);
    assert.equal(result.retried, 1);
    assert.ok(!JSON.stringify({ calls, result }).includes(telegramEnv.TELEGRAM_BOT_TOKEN));
  }
});

await check("stalled and malformed 429 bodies persist header cooldown and stop further claims", async () => {
  for (const stalled of [false, true]) {
    const calls = [];
    const result = await drainNotificationOutbox({ ...drainOptions, timeoutMs: 20,
      fetch: async () => ({ ok: false, status: 429, headers: new Headers({ "Retry-After": "7200" }),
        json: stalled ? () => new Promise(() => {}) : async () => { throw new Error(telegramEnv.TELEGRAM_BOT_TOKEN); } }),
      rpc: async (name, args) => {
        calls.push(name);
        if (name === "notification_outbox_claim") return [{ id: notificationIdentity(finding(1)), payload: finding(1) }];
        assert.equal(name, "notification_outbox_retry");
        assert.equal(args.p_rate_limited, true);
        assert.equal(args.p_retry_after_seconds, 7200);
        return "pending";
      }
    });
    assert.deepEqual(calls, ["notification_outbox_claim", "notification_outbox_retry"]);
    assert.equal(result.retried, 1);
    assert.equal(result.state, "partial");
    assert.ok(!JSON.stringify(result).includes(telegramEnv.TELEGRAM_BOT_TOKEN));
  }
});

await check("send/ack failure leaves lease for recovery and does not issue immediate retry", async () => {
  const calls = [];
  const result = await drainNotificationOutbox({ ...drainOptions, rpc: async name => {
    calls.push(name);
    if (name === "notification_outbox_claim") return [{ id: notificationIdentity(finding(1)), payload: finding(1) }];
    throw new Error("ack response lost");
  } });
  assert.deepEqual(calls, ["notification_outbox_claim", "notification_outbox_ack"]);
  assert.equal(result.state, "failed");
  assert.equal(result.claimed, 1);
  assert.equal(result.telegram, 0, "An ambiguous ack is not a confirmed delivery");
  assert.deepEqual(result.errors, [{ error: "notification_worker_failed" }]);
});

await check("later claim/ack/retry RPC failures preserve confirmed counters in published status", async () => {
  for (const failAt of ["claim", "ack", "retry"]) {
    let claimed = 0;
    let sent = 0;
    let pending = 0;
    let dead = 0;
    let published;
    const result = await runNotifications([], { ...drainOptions,
      fetch: async () => claimed === 2 || claimed === 3 || (claimed === 4 && failAt === "retry")
        ? Response.json({ ok: false, error_code: 503 }, { status: 503 }) : success(),
      rpc: async (name) => {
        if (name === "notification_outbox_status") return {
          checked_at: new Date().toISOString(), pending, processing: 0, dead, sent, suppressed: 0, ready: pending,
          oldest_pending_at: null, next_retry_at: null, last_sent_at: null
        };
        if (name === "notification_outbox_claim") {
          if (claimed === 3 && failAt === "claim") throw new Error(telegramEnv.TELEGRAM_BOT_TOKEN);
          if (claimed >= 4) assert.fail("Must stop after an ambiguous RPC failure");
          claimed++;
          return [{ id: notificationIdentity(finding(claimed)), payload: finding(claimed) }];
        }
        if (claimed === 4) throw new Error(telegramEnv.TELEGRAM_BOT_TOKEN);
        if (name === "notification_outbox_ack") { sent++; return true; }
        assert.equal(name, "notification_outbox_retry");
        if (claimed === 2) { pending++; return "pending"; }
        dead++;
        return "dead";
      },
      setState: async (_key, value) => { published = value; }
    });
    assert.equal(result.state, "partial");
    assert.equal(result.telegram, 1);
    assert.equal(result.retried, 1);
    assert.equal(result.dead, 1);
    assert.equal(result.claimed, failAt === "claim" ? 3 : 4);
    assert.equal(published.state, "partial");
    assert.deepEqual(published.run, { claimed: result.claimed, sent: 1, retried: 1, dead: 1, errors: 3 });
    assert.ok(!JSON.stringify({ result, published }).includes(telegramEnv.TELEGRAM_BOT_TOKEN));
  }
});

await check("lease and runtime budgets prevent unsafe or unused claims", async () => {
  await assert.rejects(drainNotificationOutbox({ ...drainOptions, leaseSeconds: 15 }), /leaseSeconds/);
  const result = await drainNotificationOutbox({ ...drainOptions, maxRunMs: 1,
    rpc: () => assert.fail("no time for a claim") });
  assert.equal(result.claimed, 0);
  assert.equal(result.state, "partial");
  let clock = 0;
  const timed = await drainNotificationOutbox({ ...drainOptions, maxRunMs: 40000, now: () => clock,
    rpc: async (name) => {
      if (name === "notification_outbox_claim") return [{ id: notificationIdentity(finding(1)), payload: finding(1) }];
      assert.equal(name, "notification_outbox_ack");
      clock = 3000;
      return true;
    }
  });
  assert.equal(timed.telegram, 1);
  assert.equal(timed.state, "partial", "Runtime exhaustion cannot imply a drained queue");
  assert.deepEqual(timed.errors, []);
});

await check("published drained status accounts for deferred or concurrently processing jobs", async () => {
  for (const processing of [0, 1]) {
    const aggregate = { checked_at: new Date().toISOString(), pending: 1 - processing, processing, dead: 0,
      sent: 1, suppressed: 0, ready: 0, oldest_pending_at: null, next_retry_at: null, last_sent_at: null };
    const status = await publishNotificationOutboxStatus({ state: "drained", telegram: 1, claimed: 1 }, aggregate.checked_at, {
      rpc: async () => aggregate, setState: async () => {}
    });
    assert.equal(status.state, "partial");
    assert.equal(status.run.sent, 1);
  }
});

await check("service RPC uses existing authorization and never exposes response credentials", async () => {
  await enqueueNotificationAlerts([finding(1)], { dbFetch: async (url, options) => {
    assert.equal(url, "https://outbox-test.invalid/rest/v1/rpc/notification_outbox_enqueue");
    assert.equal(options.headers.apikey, "outbox-test-service-key");
    assert.equal(options.headers.Authorization, "Bearer outbox-test-service-key");
    assert.ok(options.signal instanceof AbortSignal);
    return Response.json({ queued: 1, deduped: 0 });
  } });
  await assert.rejects(enqueueNotificationAlerts([finding(1)], {
    dbFetch: async () => { throw new Error("outbox-test-service-key"); }
  }), error => !error.stack.includes("outbox-test-service-key"));
  await assert.rejects(enqueueNotificationAlerts([finding(1)], {
    rpcTimeoutMs: 20, dbFetch: async () => ({ ok: true, json: () => new Promise(() => {}) })
  }), /failed/);
  const child = spawnSync(process.execPath, ["--input-type=module", "-e",
    "import { enqueueNotificationAlerts } from './lib/notification-outbox.js'; await enqueueNotificationAlerts([{id:'a',registrable:'a.test',score:80}]);"],
  { cwd: new URL("../", import.meta.url), encoding: "utf8", env: {
    ...process.env, SUPABASE_SERVICE_ROLE_KEY: "", SUPABASE_ANON_KEY: "anon-only"
  } });
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /service credentials are required/);
});

await check("retry command accepts only explicit dead-letter IDs and returns a count", async () => {
  const id = notificationIdentity(finding(1));
  const options = { rpc: async (name, args) => {
    assert.equal(name, "notification_outbox_retry_dead");
    assert.deepEqual(args.p_ids, [id]);
    return 1;
  } };
  assert.deepEqual(await runNotifications(["retry", id], options), { retried: 1 });
  await assert.rejects(retryDeadNotifications([], options), /explicit/);
  await assert.rejects(runNotifications(["retry", "all"], options), /explicit/);
  await assert.rejects(runNotifications(["drain", id], options), /Usage/);
});

if (databaseUrl) {
  const url = new URL(databaseUrl);
  if (!["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || url.pathname !== "/notification_outbox_test") {
    throw new Error("SQL tests require disposable localhost database notification_outbox_test");
  }
  const pg = await import(process.env.OUTBOX_TEST_PG_MODULE
    ? pathToFileURL(process.env.OUTBOX_TEST_PG_MODULE).href : "pg");
  const pool = new pg.default.Pool({ connectionString: databaseUrl, max: 8 });
  const query = (sql, params = []) => pool.query(sql, params);
  const migration = await readFile(new URL("../supabase/notification-outbox.sql", import.meta.url), "utf8");
  const names = new Set(["notification_outbox_enqueue", "notification_outbox_claim", "notification_outbox_ack",
    "notification_outbox_retry", "notification_outbox_retry_dead", "notification_outbox_status"]);
  async function rpc(name, args, role = "service_role") {
    assert.ok(names.has(name));
    assert.ok(["anon", "authenticated", "service_role"].includes(role));
    const client = await pool.connect();
    try {
      await client.query("begin");
      await client.query(`set local role ${role}`);
      const keys = Object.keys(args);
      assert.ok(keys.every(key => /^p_[a-z_]+$/.test(key)));
      const call = `public.${name}(${keys.map((key, i) => `${key} => $${i + 1}`).join(", ")})`;
      const values = Object.values(args).map((value, i) => keys[i] === "p_jobs" ? JSON.stringify(value) : value);
      const result = await client.query(name === "notification_outbox_claim"
        ? `select * from ${call}` : `select ${call} as result`, values);
      await client.query("commit");
      return name === "notification_outbox_claim" ? result.rows : result.rows[0].result;
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally { client.release(); }
  }
  const reset = () => query("truncate public.notification_outbox, public.alert_log; update public.notification_outbox_channel set available_at = now() - interval '1 day'");
  const state = async id => (await query("select * from public.notification_outbox where id = $1", [id])).rows[0];
  const enqueue = (rows, options = {}) => enqueueNotificationAlerts(rows, { rpc, ...options });
  const writeStatus = (key, value) => query("insert into public.ingest_state(key,value) values($1,$2) on conflict(key) do update set value=excluded.value", [key, value]);
  const claim = (owner = randomUUID()) => rpc("notification_outbox_claim", { p_owner: owner, p_lease_seconds: 60, p_spacing_ms: 0 });
  const expire = id => query("update public.notification_outbox set lease_until = now() - interval '1 second' where id = $1", [id]);
  const due = id => query("update public.notification_outbox set available_at = now() - interval '1 second' where id = $1", [id]);
  try {
    const existing = await query("select to_regclass('public.notification_outbox') as existing");
    assert.equal(existing.rows[0].existing, null, "SQL tests require an empty disposable database");
    await query("create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls; create table public.alert_log(registrable text primary key, alerted_at timestamptz not null default now()); alter table public.alert_log enable row level security; revoke all on public.alert_log from public, anon, authenticated; grant select, insert, update on public.alert_log to service_role; create table public.ingest_state(key text primary key, value jsonb not null, updated_at timestamptz not null default now())");
    await query("alter table public.ingest_state enable row level security; grant select on public.ingest_state to anon; create policy test_existing_state_policy on public.ingest_state for select to anon using (key='public_test_key')");
    await check("SQL migration executes and is repeatable", async () => { await query(migration); await query(migration); });

    await check("SQL and dispatcher drain 100 real persisted jobs over independent runs", async () => {
      await reset();
      assert.equal((await enqueue(Array.from({ length: 100 }, (_, i) => finding(i)))).queued, 100);
      assert.equal((await drainNotificationOutbox({ ...drainOptions, rpc, maxJobs: 20 })).telegram, 20);
      assert.equal((await query("select count(*)::int as n from public.notification_outbox where state='pending'")).rows[0].n, 80);
      assert.equal((await drainNotificationOutbox({ ...drainOptions, rpc })).telegram, 80);
      assert.equal((await query("select count(*)::int as n from public.alert_log")).rows[0].n, 100);
      assert.equal((await enqueue(Array.from({ length: 100 }, (_, i) => finding(i)))).deduped, 100);
    });

    await check("SQL concurrent enqueues/claims dedupe by identity and registrable", async () => {
      await reset();
      const results = await Promise.all(Array.from({ length: 8 }, (_, i) => enqueue([finding(i, { registrable: "same.test" })])));
      assert.equal(results.reduce((sum, result) => sum + result.queued, 0), 1);
      const claims = await Promise.all(Array.from({ length: 8 }, () => claim()));
      assert.equal(claims.flat().length, 1);
      const identical = await Promise.all(Array.from({ length: 8 }, () => enqueue([finding("identity")])));
      assert.equal(identical.reduce((sum, result) => sum + result.queued, 0), 1);
    });

    await check("SQL legacy 72-hour alert_log and active jobs suppress duplicates", async () => {
      await reset();
      await query("insert into public.alert_log values ('recent.test', now() - interval '71 hours'), ('old.test', now() - interval '73 hours')");
      assert.equal((await enqueue([finding(1, { registrable: "recent.test" })])).deduped, 1);
      assert.equal((await enqueue([finding(2, { registrable: "old.test" })])).queued, 1);
      assert.equal((await enqueue([finding(3, { registrable: "old.test" })])).deduped, 1);
      await query("insert into public.alert_log values ('race.test', now())");
      await enqueue([finding(4)]);
      await query("insert into public.alert_log values ('lure-4.test', now())");
      const rows = await claim();
      assert.equal(rows[0].registrable, "old.test");
      await claim();
      assert.equal((await state(notificationIdentity(finding(4)))).state, "suppressed");
    });

    await check("SQL expired leases recover; old and wrong owners cannot ack or retry", async () => {
      await reset();
      await enqueue([finding(1)]);
      const owner = randomUUID();
      const [job] = await claim(owner);
      assert.equal(job.attempts, 1);
      assert.deepEqual(await claim(), []);
      const ack = (who) => rpc("notification_outbox_ack", { p_id: job.id, p_owner: who, p_message_id: 42 });
      assert.equal(await ack(randomUUID()), false);
      await expire(job.id);
      assert.equal(await ack(owner), false);
      const newOwner = randomUUID();
      const [reclaimed] = await claim(newOwner);
      assert.equal(reclaimed.attempts, 2);
      assert.equal(await ack(owner), false);
      assert.equal(await rpc("notification_outbox_retry", { p_id: job.id, p_owner: owner, p_error: "telegram_timeout" }), "lease_lost");
      assert.equal(await ack(newOwner), true);
      assert.equal(await ack(owner), false);
      assert.equal(await ack(newOwner), true);
      assert.equal((await state(job.id)).state, "sent");
    });

    await check("SQL ack atomically writes dedupe and sent, including rollback and concurrent ack", async () => {
      await reset();
      await enqueue([finding(1)]);
      const owner = randomUUID();
      const [job] = await claim(owner);
      await query("alter table public.notification_outbox add constraint test_reject_sent check (state <> 'sent')");
      await assert.rejects(rpc("notification_outbox_ack", { p_id: job.id, p_owner: owner, p_message_id: 42 }), /test_reject_sent/);
      assert.equal((await query("select * from public.alert_log")).rows.length, 0);
      assert.equal((await state(job.id)).state, "processing");
      await query("alter table public.notification_outbox drop constraint test_reject_sent");
      const results = await Promise.all(Array.from({ length: 4 }, () => rpc("notification_outbox_ack", {
        p_id: job.id, p_owner: owner, p_message_id: 42
      })));
      assert.deepEqual(results, [true, true, true, true]);
      assert.equal((await query("select * from public.alert_log")).rows.length, 1);
    });

    await check("SQL retry backoff, dead letters and explicit retry survive dispatcher restart", async () => {
      await reset();
      await enqueue([finding(1)], { maxAttempts: 2 });
      const id = notificationIdentity(finding(1));
      const failure = async () => Response.json({ ok: false, error_code: 503 }, { status: 503 });
      assert.equal((await drainNotificationOutbox({ ...drainOptions, rpc, fetch: failure })).retried, 1);
      let row = await state(id);
      assert.equal(row.attempts, 1);
      assert.ok(row.available_at - row.updated_at >= 30000);
      assert.deepEqual(await claim(), []);
      await due(id);
      assert.equal((await drainNotificationOutbox({ ...drainOptions, rpc, fetch: failure })).dead, 1);
      row = await state(id);
      assert.equal(row.state, "dead");
      assert.ok(row.available_at - row.updated_at >= 60000);
      assert.deepEqual(await claim(), []);
      assert.deepEqual(await retryDeadNotifications([id], { rpc }), { retried: 1 });
      assert.equal((await drainNotificationOutbox({ ...drainOptions, rpc })).telegram, 1);
    });

    await check("SQL 429 pauses other processes across restart and overrides backoff cap", async () => {
      await reset();
      await enqueue([finding(1), finding(2)]);
      const result = await drainNotificationOutbox({ ...drainOptions, rpc, baseSeconds: 1, maxSeconds: 2,
        fetch: async () => Response.json({ ok: false, error_code: 429, parameters: { retry_after: 7200 } }, { status: 429 }) });
      assert.equal(result.claimed, 1);
      assert.equal(result.retried, 1);
      assert.deepEqual(await claim(), []);
      assert.equal((await drainNotificationOutbox({ ...drainOptions, rpc })).claimed, 0);
      const retry = (await query("select * from public.notification_outbox where attempts=1")).rows[0];
      assert.ok(retry.available_at - retry.updated_at >= 7200000);
    });

    await check("SQL bounded crash attempts end in dead letter; send/ack crash can duplicate", async () => {
      await reset();
      await enqueue([finding(1)], { maxAttempts: 2 });
      const [first] = await claim();
      await expire(first.id);
      const [second] = await claim();
      assert.equal(second.attempts, 2);
      await expire(first.id);
      assert.deepEqual(await claim(), []);
      assert.equal((await state(first.id)).state, "dead");
      await retryDeadNotifications([first.id], { rpc });
      let sent = 0;
      const send = async () => { sent++; return success(); };
      const interrupted = await drainNotificationOutbox({ ...drainOptions, fetch: send, rpc: async (name, args) => {
        if (name === "notification_outbox_ack") throw new Error("process lost before ack");
        return rpc(name, args);
      } });
      assert.equal(interrupted.state, "failed");
      assert.equal(interrupted.claimed, 1);
      assert.equal(interrupted.telegram, 0);
      assert.deepEqual(interrupted.errors, [{ error: "notification_worker_failed" }]);
      await expire(first.id);
      await drainNotificationOutbox({ ...drainOptions, rpc, fetch: send });
      assert.equal(sent, 2, "at-least-once ambiguity is explicit");
      assert.equal((await state(first.id)).state, "sent");
    });

    await check("SQL eight concurrent dispatchers deliver each of 100 jobs once without claim races", async () => {
      await reset();
      await enqueue(Array.from({ length: 100 }, (_, i) => finding(i)));
      const delivered = new Set();
      const results = await Promise.all(Array.from({ length: 8 }, () => drainNotificationOutbox({ ...drainOptions, rpc,
        fetch: async (_url, options) => {
          const text = JSON.parse(options.body).text;
          assert.ok(!delivered.has(text));
          delivered.add(text);
          return success();
        }
      })));
      assert.equal(results.reduce((sum, result) => sum + result.telegram, 0), 100);
      assert.equal(delivered.size, 100);
    });

    await check("SQL status snapshot is public-safe, fresh, and unconfigured polls preserve queue", async () => {
      await reset();
      await enqueue([finding("private-id-a"), finding("private-id-b")]);
      const result = await runNotifications([], { env: {}, rpc, setState: writeStatus });
      assert.equal(result.state, "unconfigured");
      assert.deepEqual(result.status.counts, { pending: 2, processing: 0, dead: 0, sent: 0, suppressed: 0, ready: 2 });
      assert.deepEqual(result.status.run, { claimed: 0, sent: 0, retried: 0, dead: 0, errors: 0 });
      assert.ok(Date.parse(result.status.finished_at) >= Date.parse(result.status.started_at));
      assert.ok(result.status.next_retry_at);
      assert.ok(result.status.oldest_pending_at);
      assert.equal(result.status.last_sent_at, null);
      const saved = (await query("select value from public.ingest_state where key='notifications_poll_status'")).rows[0].value;
      assert.deepEqual(saved, result.status);
      assert.ok(!JSON.stringify(saved).includes("private-id"));
      assert.ok(!JSON.stringify(saved).includes(telegramEnv.TELEGRAM_BOT_TOKEN));
      assert.ok((await query("select attempts from public.notification_outbox")).rows.every(row => row.attempts === 0));
      const sent = await runNotifications([], { ...drainOptions, rpc, setState: writeStatus });
      assert.equal(sent.status.counts.sent, 2);
      assert.equal(sent.status.run.sent, 2);
      assert.equal(sent.status.counts.pending, 0);
      assert.ok(sent.status.last_sent_at);
    });

    await check("SQL separate public aggregate policy preserves existing policy and hides private state", async () => {
      await writeStatus("public_test_key", { test: true });
      await writeStatus("private_test_key", { private: true });
      const client = await pool.connect();
      try {
        await client.query("begin; set local role anon");
        const rows = await client.query("select key from public.ingest_state order by key");
        assert.deepEqual(rows.rows.map(row => row.key), ["notifications_poll_status", "public_test_key"]);
      } finally { await client.query("rollback"); client.release(); }
      const policies = await query("select polname from pg_policy where polrelid='public.ingest_state'::regclass order by polname");
      assert.deepEqual(policies.rows.map(row => row.polname), ["notifications_status_public_read", "test_existing_state_policy"]);
    });

    await check("SQL service-only privileges reject anon/authenticated RPCs and direct mutations", async () => {
      for (const role of ["anon", "authenticated"]) {
        for (const [name, args] of [
          ["notification_outbox_enqueue", { p_jobs: [] }],
          ["notification_outbox_claim", { p_owner: randomUUID() }],
          ["notification_outbox_ack", { p_id: "a", p_owner: randomUUID(), p_message_id: 42 }],
          ["notification_outbox_retry", { p_id: "a", p_owner: randomUUID(), p_error: "telegram_timeout" }],
          ["notification_outbox_retry_dead", { p_ids: ["a"] }],
          ["notification_outbox_status", {}]
        ]) await assert.rejects(rpc(name, args, role), /permission denied/);
        const client = await pool.connect();
        try {
          await client.query("begin");
          await client.query(`set local role ${role}`);
          await assert.rejects(client.query("select * from public.notification_outbox"), /permission denied/);
        } finally { await client.query("rollback"); client.release(); }
      }
      const client = await pool.connect();
      try {
        await client.query("begin; set local role service_role");
        await assert.rejects(client.query("update public.notification_outbox set state='dead'"), /permission denied/);
      } finally { await client.query("rollback"); client.release(); }
      const functions = await query("select prosecdef, proconfig from pg_proc where proname like 'notification_outbox_%'");
      assert.equal(functions.rows.length, 6);
      assert.ok(functions.rows.every(row => row.prosecdef && row.proconfig.includes('search_path=""')));
    });

    await check("SQL capacity rejection is atomic, duplicates remain accepted at capacity", async () => {
      await reset();
      await query("insert into public.notification_outbox(id,registrable,payload) select lpad(to_hex(i),64,'0'), 'capacity-' || i || '.test', '{}'::jsonb from generate_series(1,9999) i");
      await assert.rejects(enqueue([finding("capacity-a"), finding("capacity-b")]), /capacity reached/);
      assert.equal((await query("select count(*)::int as n from public.notification_outbox")).rows[0].n, 9999);
      assert.equal((await enqueue([finding("capacity-a")])).queued, 1);
      assert.equal((await enqueue([finding("capacity-a")])).deduped, 1);
      await assert.rejects(enqueue([finding("capacity-b")]), /capacity reached/);
    });

    await check("standalone SQL assertions execute and roll back every synthetic row", async () => {
      await reset();
      const sql = await readFile(new URL("./test_notification_outbox.sql", import.meta.url), "utf8");
      await query(sql);
      assert.equal((await query("select count(*)::int as n from public.notification_outbox")).rows[0].n, 0);
      assert.equal((await query("select count(*)::int as n from public.alert_log")).rows[0].n, 0);
    });
  } finally { await pool.end(); }
} else {
  console.log("SQL integration skipped: set OUTBOX_TEST_DATABASE_URL and OUTBOX_TEST_PG_MODULE for disposable local PostgreSQL.");
}
console.log(`Notification outbox: ${passed} scenarios passed.`);

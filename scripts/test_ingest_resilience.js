import assert from "node:assert/strict";
import { test } from "node:test";
import { runIngest } from "./run-ingest.mjs";
import { summarizePrimaryHealth } from "../lib/ct/source-health.js";

function source(source, ok = true, entries = [], details = {}) {
  return { source, label: source, ok, entries, scanned_entries: entries.length, duration_ms: 1,
    errors: ok ? [] : [{ message: "provider unavailable" }], details,
    statePatch: { [source]: { index: 1 } } };
}

function harness() {
  const events = [];
  const store = {
    configured: () => true,
    tryAcquireRunLock: async (_key, lease) => { assert.equal(lease, 900); return true; },
    renewRunLock: async () => true,
    releaseRunLock: async () => { events.push({ action: "release" }); },
    getServiceState: async (key) => key === "ct_source_state" ? ({ value: { direct_ct: { index: 0 } } }) : null,
    upsertFindings: async (rows) => { events.push({ action: "findings" }); return rows; },
    upsertFindingSources: async (rows) => { events.push({ action: "sightings" }); return rows; },
    insertSourceRuns: async () => { events.push({ action: "source_runs" }); },
    setState: async (key, value) => { events.push({ action: key, value: structuredClone(value) }); },
    setRunState: async (_name, _owner, key, value) => { events.push({ action: key, value: structuredClone(value) }); },
  };
  return { events, store, options: { store, readData: () => ({}),
    scan: async () => [source("direct_ct", true, [{}]), source("static_ct")],
    score: () => ({ id: "example", registrable: "test.example", domains: ["test.example"], score: 75 }),
    enqueue: async () => { events.push({ action: "outbox" }); return { queued: 1 }; } } };
}

test("idle backups cannot mask unavailable primary sources; legitimate empty polls remain healthy", () => {
  const backups = [source("certstream", true, [], { state: "standby" }), source("crtsh", true, [], { state: "scheduled" })];
  assert.equal(summarizePrimaryHealth([source("direct_ct", false), source("static_ct", false), ...backups]).health, "down");
  assert.equal(summarizePrimaryHealth([source("direct_ct"), source("static_ct"), source("crtsh", false)]).health, "healthy");
  assert.equal(summarizePrimaryHealth([source("direct_ct", false, [{}]), source("static_ct", false)]).health, "partial");
  assert.equal(summarizePrimaryHealth([source("direct_ct", false, [], { successful_log_count: 1 })]).ok, true);
});

test("findings and sightings precede cursor checkpoint without a notification dependency", async () => {
  const { events, options } = harness();
  const result = await runIngest(options);
  assert.equal(result.health, "healthy");
  assert.equal(Object.hasOwn(result, "notifications"), false);
  assert.deepEqual(events.map(e => e.action), ["ct_poll_status", "findings", "sightings", "ct_source_state", "source_runs", "ct_poll_status", "release"]);
  assert.equal(events.find((e) => e.action === "ct_source_state").value.direct_ct.index, 1);
  assert.equal(events.at(-1).action, "release");
});

test("failed finding/sighting writes retain replay cursors and persist failed stage", async () => {
  for (const [method, stage] of [["upsertFindings", "findings"], ["upsertFindingSources", "sightings"]]) {
    const { store, events, options } = harness();
    store[method] = async () => { throw new Error("storage outage"); };
    options.enqueue = () => assert.fail("must not enqueue unsaved observations");
    await assert.rejects(runIngest(options), /storage outage/);
    assert.equal(events.some((e) => e.action === "ct_source_state"), false);
    const failure = events.findLast((e) => e.action === "ct_poll_status").value;
    assert.equal(failure.health, "down");
    assert.equal(failure.failed_stage, stage);
    assert.equal(events.at(-1).action, "release");
  }
});

test("fallback dispatches skip recently started scans without changing the successful heartbeat", async () => {
  const { store, events, options } = harness();
  options.now = () => Date.parse("2026-09-08T10:05:00Z");
  options.minIntervalMs = 14 * 60 * 1000;
  store.getServiceState = async () => ({ value: { last_started_at: "2026-09-08T10:00:00Z" } });
  options.scan = () => assert.fail("recent scan must not repeat");
  assert.equal(await runIngest(options), undefined);
  assert.deepEqual(events.map((e) => e.action), ["release"]);
});

test("lost database lease fences cursor and heartbeat writes after provider collection", async () => {
  const { store, events, options } = harness();
  let expired = false;
  store.setRunState = async (_name, _owner, key, value) => {
    if (expired) throw new Error("ownership lost");
    events.push({ action: key, value });
  };
  options.scan = async () => { expired = true; return [source("direct_ct", true, [{}])]; };
  await assert.rejects(runIngest(options), /ownership/);
  assert.equal(events.some((e) => e.action === "ct_source_state"), false);
  assert.equal(events.filter((e) => e.action === "ct_poll_status").length, 1);
});

test("retired notification options never enqueue or affect scan health", async () => {
  const { events, options } = harness();
  options.notificationsEnabled = true;
  options.enqueue = () => assert.fail("retired notification path must not enqueue");
  const result = await runIngest(options);
  assert.equal(Object.hasOwn(result, "notifications"), false);
  assert.ok(events.some((e) => e.action === "ct_source_state"));
});

test("notification storage outages no longer prevent saved CT checkpoints", async () => {
  const { events, options } = harness();
  options.enqueue = async () => { throw new Error("outbox unavailable"); };
  const result = await runIngest(options);
  assert.equal(result.state, "completed");
  assert.equal(events.some((e) => e.action === "ct_source_state"), true);
  assert.equal(events.findLast((e) => e.action === "ct_poll_status").value.failed_stage, undefined);
});

test("failed initial status read never erases history or reserves a fresh scan start", async () => {
  const { events, options, store } = harness();
  store.getServiceState = async () => { throw new Error("status read unavailable"); };
  options.scan = () => assert.fail("must not poll without prior status");
  await assert.rejects(runIngest(options), /status read unavailable/);
  assert.deepEqual(events.map(event => event.action), ["release"]);
});

test("known renewal loss after a findings write prevents sightings and checkpoint", async () => {
  const { events, options, store } = harness();
  let heartbeat;
  options.leaseOptions = { setTimer: fn => { heartbeat = fn; }, clearTimer: () => {} };
  store.renewRunLock = async () => false;
  store.upsertFindings = async rows => { await heartbeat(); return rows; };
  store.upsertFindingSources = () => assert.fail("lost lease must not write sightings");
  options.enqueue = () => assert.fail("lost lease must not enqueue");
  await assert.rejects(runIngest(options), /lease lost/);
  assert.equal(events.some(event => event.action === "ct_source_state"), false);
});

test("direct operator cooldown survives failed writes without advancing direct cursors", async () => {
  const { events, options, store } = harness();
  const run = source("direct_ct", false, [{}]);
  run.statePatch.direct_ct = { index: 4, cursors: { log: { next: 100 } }, cooldowns: { operator: "2026-09-09T00:00:00Z" } };
  options.scan = async () => [run];
  store.upsertFindings = async () => { throw new Error("storage outage"); };
  await assert.rejects(runIngest(options), /storage outage/);
  const saved = events.find(event => event.action === "ct_source_state").value.direct_ct;
  assert.equal(saved.index, 0);
  assert.equal(saved.cursors, undefined);
  assert.deepEqual(saved.cooldowns, run.statePatch.direct_ct.cooldowns);
});

test("backup cooldown survives failed finding writes without advancing primary cursors", async () => {
  const { events, store, options } = harness();
  const backup = source("crtsh", false);
  backup.statePatch.crtsh.next_poll_at = "2026-09-09T00:00:00Z";
  options.scan = async () => [source("direct_ct", true, [{}]), backup];
  store.upsertFindings = async () => { throw new Error("storage outage"); };
  await assert.rejects(runIngest(options), /storage outage/);
  const saved = events.find((e) => e.action === "ct_source_state").value;
  assert.equal(saved.direct_ct.index, 0);
  assert.equal(saved.crtsh.next_poll_at, backup.statePatch.crtsh.next_poll_at);
});

test("missing service credentials prevent scans and a busy runner skips cleanly", async () => {
  const { store, options } = harness();
  options.scan = () => assert.fail("must not scan");
  store.configured = () => false;
  await assert.rejects(runIngest(options), /service credentials/);
  store.configured = () => true;
  store.tryAcquireRunLock = async () => false;
  assert.equal(await runIngest(options), undefined);
});

test("static operator cooldowns survive write failure without advancing unsaved tile cursors", async () => {
  const { store, events, options } = harness();
  store.getServiceState = async () => ({ value: { static_ct: { index: 2, cursors: { log: { next: 10 } } } } });
  const run = source("static_ct", false, [{}]);
  run.statePatch.static_ct = { index: 3, cursors: { log: { next: 256 } }, cooldowns: { operator: "2026-09-09T00:00:00Z" } };
  options.scan = async () => [run];
  store.upsertFindings = async () => { throw new Error("storage outage"); };
  await assert.rejects(runIngest(options), /storage outage/);
  const saved = events.find((e) => e.action === "ct_source_state").value.static_ct;
  assert.equal(saved.index, 2);
  assert.equal(saved.cursors.log.next, 10);
  assert.deepEqual(saved.cooldowns, run.statePatch.static_ct.cooldowns);
});

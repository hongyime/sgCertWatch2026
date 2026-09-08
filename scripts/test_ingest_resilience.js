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
    releaseRunLock: async () => { events.push({ action: "release" }); },
    getServiceState: async () => ({ value: { direct_ct: { index: 0 } } }),
    upsertFindings: async (rows) => { events.push({ action: "findings" }); return rows; },
    upsertFindingSources: async (rows) => { events.push({ action: "sightings" }); return rows; },
    insertSourceRuns: async () => { events.push({ action: "source_runs" }); },
    setState: async (key, value) => { events.push({ action: key, value: structuredClone(value) }); },
    getRecentAlertRegistrables: async () => new Set(),
    recordAlerts: async (domains) => { events.push({ action: "alerts", domains }); }
  };
  return { events, store, options: { store, readData: () => ({}),
    scan: async () => [source("direct_ct", true, [{}]), source("static_ct")],
    score: () => ({ id: "example", registrable: "test.example", domains: ["test.example"], score: 75 }),
    notify: async () => ({ telegram: 0, delivered_registrables: [], errors: [] }) } };
}

test("idle backups cannot mask unavailable primary sources; legitimate empty polls remain healthy", () => {
  const backups = [source("certstream", true, [], { state: "standby" }), source("crtsh", true, [], { state: "scheduled" })];
  assert.equal(summarizePrimaryHealth([source("direct_ct", false), source("static_ct", false), ...backups]).health, "down");
  assert.equal(summarizePrimaryHealth([source("direct_ct"), source("static_ct"), source("crtsh", false)]).health, "healthy");
  assert.equal(summarizePrimaryHealth([source("direct_ct", false, [{}]), source("static_ct", false)]).health, "partial");
  assert.equal(summarizePrimaryHealth([source("direct_ct", false, [], { successful_log_count: 1 })]).ok, true);
});

test("findings and sightings precede cursors; checkpoint and scan status precede notifications", async () => {
  const { events, options } = harness();
  options.notify = async () => {
    assert.deepEqual(events.map((e) => e.action), ["findings", "sightings", "ct_source_state", "source_runs", "ct_poll_status"]);
    throw new Error("notification service stalled/failed");
  };
  const result = await runIngest(options);
  assert.equal(result.health, "healthy");
  assert.equal(result.notifications.state, "failed");
  assert.equal(events.find((e) => e.action === "ct_source_state").value.direct_ct.index, 1);
  assert.equal(events.at(-1).action, "release");
});

test("failed finding/sighting writes retain replay cursors and persist failed stage", async () => {
  for (const [method, stage] of [["upsertFindings", "findings"], ["upsertFindingSources", "sightings"]]) {
    const { store, events, options } = harness();
    store[method] = async () => { throw new Error("storage outage"); };
    options.notify = () => assert.fail("must not notify unsaved observations");
    await assert.rejects(runIngest(options), /storage outage/);
    assert.equal(events.some((e) => e.action === "ct_source_state"), false);
    const failure = events.find((e) => e.action === "ct_poll_status").value;
    assert.equal(failure.health, "down");
    assert.equal(failure.failed_stage, stage);
    assert.equal(events.at(-1).action, "release");
  }
});

test("only actually delivered notifications enter dedupe history", async () => {
  const { events, options } = harness();
  options.notify = async () => ({ telegram: 0, delivered_registrables: [], errors: [] });
  await runIngest(options);
  assert.deepEqual(events.find((e) => e.action === "alerts").domains, []);
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

import assert from "node:assert/strict";
import { test } from "node:test";
import { runIntel } from "./run-intel.mjs";

function harness() {
  const events = [];
  const store = {
    configured: () => true,
    tryAcquireRunLock: async (name, seconds, owner) => {
      assert.equal(name, "intel_poll_run"); assert.equal(seconds, 600); assert.ok(owner); return true;
    },
    renewRunLock: async () => true,
    releaseRunLock: async () => events.push("release"),
    getServiceState: async () => null,
    setRunState: async (_name, _owner, key) => events.push(key),
    listIntelCandidates: async () => [],
    upsertIntelEvidence: async () => [],
    pruneIntelEvidence: async () => events.push("prune")
  };
  return { events, store, pipeline: async ({ saveState }) => {
    await saveState({}); return { status: { sources: [] } };
  } };
}

test("intel run is leased and saves provider reservations before completed status", async () => {
  const options = harness();
  assert.equal((await runIntel(options)).ok, true);
  assert.deepEqual(options.events, ["intel_poll_status", "intel_source_state", "intel_poll_status", "prune", "release"]);
});
test("intel fallback skips recent runs and never contacts providers when lock fails", async () => {
  const options = harness();
  options.now = () => Date.parse("2026-09-08T10:05:00Z");
  options.minIntervalMs = 55 * 60000;
  options.store.getServiceState = async () => ({ value: { last_started_at: "2026-09-08T10:00:00Z" } });
  options.pipeline = () => assert.fail("must not call providers");
  assert.equal(await runIntel(options), undefined);
  assert.deepEqual(options.events, ["release"]);
  options.store.tryAcquireRunLock = async () => { throw new Error("database down"); };
  await assert.rejects(runIntel(options), /database down/);
});
test("intel failed writes expose failure and release the lease", async () => {
  const options = harness();
  options.pipeline = async () => { throw new Error("write failed"); };
  await assert.rejects(runIntel(options), /write failed/);
  assert.deepEqual(options.events, ["intel_poll_status", "intel_poll_status", "release"]);
});
test("intel initial status failure preserves the existing successful history", async () => {
  const options = harness();
  options.store.getServiceState = async () => { throw new Error("status read failed"); };
  options.pipeline = () => assert.fail("must not poll");
  await assert.rejects(runIntel(options), /status read failed/);
  assert.deepEqual(options.events, ["release"]);
});

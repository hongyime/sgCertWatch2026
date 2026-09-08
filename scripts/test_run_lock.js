import assert from "node:assert/strict";
import { test } from "node:test";

process.env.SUPABASE_URL = "https://locks.example";
process.env.SUPABASE_SERVICE_ROLE_KEY = "test-only-service-key";
const db = await import("../lib/supabase.js");
const { acquireRunLease } = await import("../lib/run-lease.js");

test("lock acquisition uses one owner-scoped RPC and never fails open", async () => {
  const original = globalThis.fetch;
  try {
    const calls = [];
    globalThis.fetch = async (url, options) => {
      calls.push({ url: String(url), body: JSON.parse(options.body) });
      return Response.json(true);
    };
    const owner = "00000000-0000-4000-8000-000000000001";
    assert.equal(await db.tryAcquireRunLock("ct_poll_run", 900, owner), true);
    assert.deepEqual(calls, [{ url: "https://locks.example/rest/v1/rpc/acquire_run_lock",
      body: { lock_name: "ct_poll_run", owner_id: owner, lease_seconds: 900 } }]);
    globalThis.fetch = async () => new Response("unavailable", { status: 503 });
    await assert.rejects(db.tryAcquireRunLock("ct_poll_run", 900, owner), /503/);
    globalThis.fetch = async () => { throw new Error("network unavailable"); };
    await assert.rejects(db.tryAcquireRunLock("ct_poll_run", 900, owner), /network unavailable/);
    await assert.rejects(db.tryAcquireRunLock("ct_poll_run", 900), /owner/i);
  } finally { globalThis.fetch = original; }
});

test("renew, release and checkpoint retain owner identity and reject stale ownership", async () => {
  const original = globalThis.fetch;
  const owner = "00000000-0000-4000-8000-000000000002";
  try {
    const calls = [];
    globalThis.fetch = async (url, options) => {
      calls.push({ url: String(url), body: JSON.parse(options.body) });
      return Response.json(false);
    };
    assert.equal(await db.renewRunLock("ct_poll_run", 900, owner), false);
    assert.equal(await db.releaseRunLock("ct_poll_run", owner), false);
    await assert.rejects(db.setRunState("ct_poll_run", owner, "ct_source_state", { index: 1 }), /ownership/);
    assert.equal(calls.length, 3);
    assert.ok(calls.every((call) => call.body.owner_id === owner));
    assert.equal(calls[2].body.state_key, "ct_source_state");
  } finally { globalThis.fetch = original; }
});

test("runner heartbeat failures and hard deadline prevent checkpoints; close retains ownership", async () => {
  let clock = 0;
  let renew = true;
  const events = [];
  const store = {
    tryAcquireRunLock: async (...args) => { events.push(["acquire", ...args]); return true; },
    renewRunLock: async () => renew,
    releaseRunLock: async (...args) => events.push(["release", ...args]),
    setRunState: async (...args) => events.push(["state", ...args])
  };
  const options = { now: () => clock, maxRunMs: 100, setTimer: () => null, clearTimer: () => {} };
  const lease = await acquireRunLease(store, options);
  await lease.setState("ct_source_state", {});
  renew = false;
  await lease.heartbeat();
  await assert.rejects(lease.setState("ct_source_state", {}), /lease/);
  await lease.close();
  assert.equal(events[0][3], events.at(-1)[2]);
  assert.equal(events.filter((event) => event[0] === "state").length, 1);
  const second = await acquireRunLease(store, options);
  clock = 100;
  assert.throws(second.assertOwned, /deadline/);
  await second.close();
  store.tryAcquireRunLock = async () => false;
  assert.equal(await acquireRunLease(store, options), null);
  store.tryAcquireRunLock = async () => { throw new Error("offline"); };
  await assert.rejects(acquireRunLease(store, options), /offline/);
});

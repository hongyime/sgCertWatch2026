import assert from "node:assert/strict";
import { test } from "node:test";
import { visiblePoller } from "../refresh.js";

const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

function harness(task, interval = 120000) {
  const visibility = new EventTarget();
  visibility.hidden = false;
  let now = 0;
  let id = 0;
  const timers = new Map();
  const poll = visiblePoller(task, interval, {
    document: visibility,
    setTimer(fn, delay) { const key = ++id; timers.set(key, { at: now + delay, fn }); return key; },
    clearTimer(key) { timers.delete(key); }
  });
  return {
    poll, timers,
    async advance(ms) {
      const end = now + ms;
      while (true) {
        const next = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        const [key, timer] = next;
        timers.delete(key);
        now = timer.at;
        timer.fn();
        await flush();
      }
      now = end;
      await flush();
    },
    async hidden(value) { visibility.hidden = value; visibility.dispatchEvent(new Event("visibilitychange")); await flush(); }
  };
}

test("findings use two minutes and status uses one minute after each completed read", async () => {
  let feed = 0, status = 0;
  const a = harness(async () => { feed++; });
  const b = harness(async () => { status++; }, 60000);
  a.poll.refresh(); b.poll.refresh(); await flush();
  await a.advance(60000); await b.advance(60000);
  assert.deepEqual([feed, status], [1, 2]);
  await a.advance(60000); await b.advance(60000);
  assert.deepEqual([feed, status], [2, 3]);
  a.poll.stop(); b.poll.stop();
});

test("hidden pages start no work and resume with one immediate refresh", async () => {
  let calls = 0;
  const h = harness(async () => { calls++; });
  await h.hidden(true); h.poll.refresh(); await h.advance(3600000);
  assert.equal(calls, 0);
  await h.hidden(false); assert.equal(calls, 1);
  await h.hidden(true); await h.advance(3600000); assert.equal(calls, 1);
  await h.hidden(false); assert.equal(calls, 2);
  h.poll.stop();
});

test("hidden pages abort an active read without accumulating work", async () => {
  let calls = 0, signal;
  const h = harness((s) => new Promise((resolve) => {
    calls++; signal = s; s.addEventListener("abort", () => resolve(false), { once: true });
  }));
  h.poll.refresh(); await flush(); await h.hidden(true);
  assert.equal(signal.aborted, true);
  await h.advance(3600000); assert.equal(calls, 1); assert.equal(h.timers.size, 0);
  await h.hidden(false); assert.equal(calls, 2);
  h.poll.stop(); await flush();
});

test("rapid filter changes coalesce and wait for the previous request to settle", async () => {
  const calls = [];
  const h = harness((signal) => new Promise((resolve) => calls.push({ signal, resolve })));
  h.poll.refresh(); await flush();
  h.poll.refresh(); h.poll.refresh(); h.poll.refresh();
  assert.equal(calls.length, 1); assert.equal(calls[0].signal.aborted, true);
  calls[0].resolve(false); await flush(); assert.equal(calls.length, 2);
  calls[1].resolve(true); await flush();
  await h.advance(119999); assert.equal(calls.length, 2);
  h.poll.stop();
});

test("slow or noncooperative requests cannot overlap after their deadline", async () => {
  const calls = [];
  const h = harness((signal) => new Promise((resolve) => calls.push({ signal, resolve })));
  h.poll.refresh(); await h.advance(3600000);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].signal.reason.name, "TimeoutError");
  calls[0].resolve(true); await flush();
  await h.advance(239999); assert.equal(calls.length, 1);
  await h.advance(1); assert.equal(calls.length, 2);
  h.poll.stop(); calls[1].resolve(false); await flush();
});

test("failures back off to ten minutes and success restores the normal cadence", async () => {
  let calls = 0, ok = false;
  const h = harness(async () => { calls++; return ok; });
  h.poll.refresh(); await flush();
  for (const delay of [240000, 480000, 600000, 600000]) {
    const before = calls; await h.advance(delay - 1); assert.equal(calls, before);
    await h.advance(1); assert.equal(calls, before + 1);
  }
  ok = true; await h.advance(600000);
  const before = calls; await h.advance(120000); assert.equal(calls, before + 1);
  h.poll.stop();
});

test("explicit refresh bypasses backoff while stop removes every future refresh", async () => {
  let calls = 0;
  const h = harness(async () => { calls++; throw new Error("offline"); });
  h.poll.refresh(); await flush(); h.poll.refresh(); await flush();
  assert.equal(calls, 2);
  h.poll.stop(); h.poll.refresh(); await h.hidden(true); await h.hidden(false);
  await h.advance(3600000); assert.equal(calls, 2); assert.equal(h.timers.size, 0);
});

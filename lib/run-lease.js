import { randomUUID } from "node:crypto";

export async function acquireRunLease(store, { name = "ct_poll_run", leaseSeconds = 900,
  maxRunMs = 13 * 60 * 1000, heartbeatMs = 60000, now = Date.now,
  setTimer = setInterval, clearTimer = clearInterval } = {}) {
  const owner = randomUUID();
  const started = now();
  if (!await store.tryAcquireRunLock(name, leaseSeconds, owner)) return null;
  let lost = false;
  let stopped = false;
  let renewal = null;
  const assertOwned = () => {
    if (lost || stopped || now() - started >= maxRunMs) {
      throw new Error("Run lease lost or execution deadline exceeded");
    }
  };
  const heartbeat = () => {
    if (renewal || stopped || lost) return renewal;
    renewal = (async () => {
      try {
        assertOwned();
        if (!await store.renewRunLock(name, leaseSeconds, owner)) lost = true;
      } catch { lost = true; }
    })().finally(() => { renewal = null; });
    return renewal;
  };
  const timer = setTimer(heartbeat, heartbeatMs);
  timer?.unref?.();
  return {
    owner, assertOwned, heartbeat,
    async setState(key, value) {
      assertOwned();
      await store.setRunState(name, owner, key, value);
    },
    async close() {
      stopped = true;
      clearTimer(timer);
      await renewal;
      try { await store.releaseRunLock(name, owner); }
      catch { console.error("Run lease release failed; database expiry remains active"); }
    }
  };
}

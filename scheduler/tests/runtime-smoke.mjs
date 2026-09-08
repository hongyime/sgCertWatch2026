import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { TEST_ENV } from "./helpers.mjs";

// Optional workerd/SQLite smoke check using an already-installed Miniflare module.
// Usage: node scheduler/tests/runtime-smoke.mjs [path-to-miniflare]
const require = createRequire(import.meta.url);
const { Miniflare, Response: RuntimeResponse } = require(process.argv[2] || "miniflare");
let dispatches = 0;
const options = {
  modules: true,
  scriptPath: fileURLToPath(new URL("../worker.mjs", import.meta.url)),
  compatibilityDate: "2026-08-08",
  bindings: TEST_ENV,
  durableObjects: { SCHEDULER: { className: "SchedulerCoordinator", useSQLite: true } },
  resourcePersistencePath: fileURLToPath(new URL(`../.wrangler/runtime-${randomUUID()}`, import.meta.url)),
  outboundService: async request => {
    const url = new URL(request.url);
    assert.equal(url.hostname, "api.github.com");
    if (url.pathname.endsWith("/dispatches")) {
      assert.equal((await request.json()).inputs.scheduler, "cloudflare");
      dispatches++;
      return new RuntimeResponse(null, { status: 204 });
    }
    return RuntimeResponse.json({ total_count: 0, workflow_runs: [] });
  }
};
let runtime = new Miniflare(options);
try {
  const scheduledAt = Date.now();
  const namespace = await runtime.getDurableObjectNamespace("SCHEDULER");
  const object = namespace.get(namespace.idFromName("sgcertwatch-scheduler-v1"));
  const responses = await Promise.all(Array.from({ length: 8 }, () => object.fetch(
    `https://internal/tick?scheduledAt=${scheduledAt}`, { method: "POST" })));
  for (const response of responses) assert.equal(response.status, 200);
  assert.equal(dispatches, 3);
  assert.equal((await runtime.dispatchFetch("https://worker.test/status")).status, 401);
  let status = await (await runtime.dispatchFetch("https://worker.test/status", {
    headers: { Authorization: `Bearer ${TEST_ENV.STATUS_TOKEN}` }
  })).json();
  assert.equal(status.metrics.ticksProcessed, 1);
  assert.equal(status.metrics.ticksReceived, 8);
  await runtime.dispose();
  runtime = new Miniflare(options);
  const restarted = await runtime.getDurableObjectNamespace("SCHEDULER");
  const response = await restarted.get(restarted.idFromName("sgcertwatch-scheduler-v1")).fetch(
    `https://internal/tick?scheduledAt=${scheduledAt}`, { method: "POST" });
  assert.equal(response.status, 200);
  assert.equal(dispatches, 3);
  status = await (await runtime.dispatchFetch("https://worker.test/status", {
    headers: { Authorization: `Bearer ${TEST_ENV.STATUS_TOKEN}` }
  })).json();
  assert.equal(status.metrics.ticksProcessed, 1);
  assert.equal(status.metrics.ticksReceived, 9);
  console.log("Miniflare SQLite smoke passed: concurrent ticks, reservation durability, restart, provenance, protected status.");
} finally {
  await runtime.dispose();
}

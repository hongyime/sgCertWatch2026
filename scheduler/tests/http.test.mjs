import test from "node:test";
import assert from "node:assert/strict";
import { boundedJson, retryTime } from "../http.mjs";
import { BASE_TIME, harness } from "./helpers.mjs";

test("fetch and response body deadlines remain bounded when abort is ignored", { timeout: 10000 }, async () => {
  for (const fetcher of [() => new Promise(() => {}), async () => new Response(new ReadableStream({ start() {} }))]) {
    const start = performance.now();
    let signal;
    await assert.rejects(boundedJson((url, init) => { signal = init.signal; return fetcher(url, init); },
      "https://api.github.com", { method: "POST" }, 20), error => error.code === "request_timeout" && error.ambiguous);
    assert.equal(signal.aborted, true);
    assert.ok(performance.now() - start < 5000);
  }
});

test("oversized, malformed and missing JSON is rejected without recording payloads", async () => {
  for (const [body, code] of [["x".repeat(200), "response_too_large"], ["private-token-not-json", "invalid_json"]]) {
    await assert.rejects(boundedJson(async () => new Response(body), "https://api.github.com", {}, 500, 100), error => error.code === code && !error.message.includes("private"));
  }
  await assert.rejects(boundedJson(async () => new Response(null), "https://api.github.com"), /invalid_response/);
});

test("error response bodies and redirects are not read or followed", async () => {
  let cancelled = false;
  const result = await boundedJson(async (_, init) => {
    assert.equal(init.redirect, "manual");
    return new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 302, headers: { Location: "https://attacker.invalid/" } });
  }, "https://api.github.com", {}, 50);
  assert.equal(result.status, 302);
  assert.equal(result.data, null);
  assert.equal(cancelled, true);
});

test("Retry-After supports seconds, HTTP dates, resets, malformed and very long values", () => {
  assert.equal(retryTime(new Headers({ "Retry-After": "120" }), BASE_TIME), BASE_TIME + 120000);
  assert.equal(retryTime(new Headers({ "Retry-After": new Date(BASE_TIME + 7200000).toUTCString() }), BASE_TIME), BASE_TIME + 7200000);
  assert.equal(retryTime(new Headers({ "Retry-After": "bad" }), BASE_TIME), BASE_TIME + 60000);
  assert.equal(retryTime(new Headers({ "Retry-After": "-10" }), BASE_TIME), BASE_TIME + 60000);
});

test("hung GitHub reads produce a failed tick and no dispatch within a bounded time", { timeout: 10000 }, async () => {
  const h = harness({ timeoutMs: 20 });
  h.override = () => new Promise(() => {});
  const before = performance.now();
  const result = await h.tick();
  assert.equal(result.ok, false);
  assert.ok(performance.now() - before < 5000);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].init.signal.aborted, true);
  assert.equal(h.dispatches().length, 0);
  assert.equal((await h.state()).github.lastError, "request_timeout");
});

test("overall tick budget bounds slow sequential calls and never drops the lease fence", async () => {
  const h = harness();
  h.override = () => { h.time += 6000; };
  const before = h.time;
  const result = await h.tick();
  assert.equal(result.ok, false);
  assert.ok(h.time - before <= 96000);
  assert.ok(h.calls.length <= 16);
  assert.ok((await h.state()).lastTickErrors.includes("tick_budget_exhausted"));
});

test("HTTP 429 status and Retry-After survive a stalled body", { timeout: 10000 }, async () => {
  let signal;
  const result = await boundedJson(async (_, init) => {
    signal = init.signal;
    return new Response(new ReadableStream({ start() {} }), { status: 429, headers: { "Retry-After": "3600" } });
  }, "https://alerts.example.test/private", { method: "POST" }, 20, 131072, false);
  assert.equal(result.status, 429);
  assert.equal(result.headers.get("Retry-After"), "3600");
  assert.equal(result.data, null);
  assert.equal(signal.aborted, true);
});

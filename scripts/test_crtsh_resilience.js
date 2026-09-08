import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { crtShQueryUrl, runCrtShSource } from "../lib/ct/crtsh.js";
import { fetchWithTimeout } from "../lib/ct/common.js";
import { mergeSourceState } from "../lib/ct/orchestrator.js";

const now = Date.parse("2026-09-08T08:00:00Z");
const hour = 3600000;
const data = { watchlist: { brands: [{ tokens: ["fairprice", "edusave"] }] }, schemes: { schemes: [] } };
const json = (value) => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
const options = (fetchImpl, state = {}, at = now) => ({ data, state, now: at, fetchImpl });

test("supported root JSON route uses structured encoding and excludes expired certificates", () => {
  const url = crtShQueryUrl("test & name");
  assert.equal(url.origin, "https://crt.sh");
  assert.equal(url.pathname, "/");
  assert.equal(url.searchParams.get("identity"), "test & name");
  assert.equal(url.searchParams.get("output"), "json");
  assert.equal(url.searchParams.get("exclude"), "expired");
  assert.equal(url.searchParams.has("minNotBefore"), false);
});

test("502 pauses after one request; cooldown survives serialized state in a fresh runner", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return new Response("bad gateway", { status: 502 }); };
  const failed = await runCrtShSource(options(fetchImpl));
  assert.equal(calls, 1);
  assert.equal(failed.ok, false);
  assert.equal(failed.details.state, "cooldown");
  assert.match(failed.errors[0].message, /HTTP 502/);
  const saved = JSON.parse(JSON.stringify(mergeSourceState({ direct_ct: { index: 4 } }, [failed])));
  assert.equal(saved.direct_ct.index, 4);
  assert.equal(saved.crtsh.index, 1);
  assert.equal(Date.parse(saved.crtsh.next_poll_at), now + hour);
  const skipped = await runCrtShSource(options(fetchImpl, saved.crtsh, now + hour / 4));
  assert.equal(calls, 1);
  assert.equal(skipped.ok, false);
  assert.equal(skipped.details.skipped, true);
  assert.equal(skipped.details.last_attempt_at, failed.details.last_attempt_at);
  const second = await runCrtShSource(options(fetchImpl, saved.crtsh, now + hour));
  assert.equal(calls, 2);
  assert.deepEqual(second.details.batch, ["fairprice"]);
  assert.equal(Date.parse(second.details.next_poll_at), now + 3 * hour);
  assert.equal(second.details.consecutive_failures, 2);
});

test("404 is a provider failure, while a valid empty JSON array is a successful check", async () => {
  const failed = await runCrtShSource(options(async () => new Response("not found", { status: 404 })));
  assert.equal(failed.ok, false);
  assert.match(failed.errors[0].message, /HTTP 404/);
  const success = await runCrtShSource(options(async () => json([]), failed.statePatch.crtsh, now + hour));
  assert.equal(success.ok, true);
  assert.equal(success.scanned_entries, 0);
  assert.equal(success.details.consecutive_failures, 0);
  assert.equal(success.statePatch.crtsh.last_error, null);
  assert.equal(success.details.last_success_at, new Date(now + hour).toISOString());
  const skipped = await runCrtShSource(options(() => assert.fail("must not repoll before due"), success.statePatch.crtsh, now + hour + 1));
  assert.equal(skipped.ok, true);
  assert.equal(skipped.details.state, "scheduled");
  assert.equal(skipped.details.last_attempt_at, success.details.last_attempt_at);
});

test("429 respects longer Retry-After seconds/date and has a 24-hour minimum", async () => {
  for (const [header, delay] of [["172800", 48 * hour], [new Date(now + 36 * hour).toUTCString(), 36 * hour], ["10", 24 * hour], ["bad", 24 * hour]]) {
    const run = await runCrtShSource(options(async () => new Response("limited", { status: 429, headers: { "Retry-After": header } })));
    assert.equal(Date.parse(run.details.next_poll_at), now + delay);
    assert.equal(run.errors[0].status, 429);
  }
});

test("malformed JSON, wrong shapes and oversized bodies are failures, not no matches", async () => {
  for (const body of ["<html>upstream error</html>", "{}", "null", " ".repeat(4 * 1024 * 1024 + 1)]) {
    const run = await runCrtShSource(options(async () => new Response(body)));
    assert.equal(run.ok, false);
    assert.equal(run.details.state, "cooldown");
  }
});

test("records are sorted before local limit, old/undated records excluded and scanned count retained", async () => {
  const records = Array.from({ length: 20 }, (_, i) => ({ id: i + 1, name_value: `edusave-${i}.example`, entry_timestamp: new Date(now - (20 - i) * hour).toISOString() }));
  records.push({ id: 90, name_value: "old.example", entry_timestamp: "2020-01-01" }, { id: 91, name_value: "undated.example" }, null);
  const run = await runCrtShSource(options(async () => json(records)));
  assert.equal(run.ok, true);
  assert.equal(run.scanned_entries, 23);
  assert.equal(run.entries.length, 15);
  assert.equal(run.entries[0].source_ref, "crtsh:20");
});

test("an empty token set makes no requests and never stores NaN cursors", async () => {
  const run = await runCrtShSource({ ...options(() => assert.fail("no tokens")), data: { watchlist: { brands: [] }, schemes: { schemes: [] } } });
  assert.equal(run.ok, false);
  assert.equal(run.details.state, "unconfigured");
  assert.equal(run.statePatch.crtsh.index, 0);
});

test("timeouts cover stalled response bodies and preserve caller cancellation", async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.write("[");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    const startedAt = Date.now();
    const run = await runCrtShSource({ ...options((_url, init) => fetch(url, init)), timeoutMs: 100 });
    assert.equal(run.ok, false);
    assert.match(run.errors[0].message, /timed out/);
    assert.ok(Date.now() - startedAt < 2000);
    const controller = new AbortController();
    const response = await fetchWithTimeout(url, { timeoutMs: 5000, signal: controller.signal });
    controller.abort();
    await assert.rejects(response.json(), { name: "AbortError" });
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import { fetchJson } from "../lib/ct/common.js";
import { CERTSPOTTER_LOG_LIST_URL, GOOGLE_V3_LOG_LIST_URL } from "../lib/ct/loglist.js";

process.env.DIRECT_CT_LOGS_PER_RUN = "2";
process.env.DIRECT_CT_ENTRIES_PER_LOG = "2";
const { runDirectCtSource } = await import("../lib/ct/direct-logs.js");
const epoch = Date.parse("2026-09-08T08:00:00Z");
const hour = 3600000;
const json = (value) => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
const logs = ["first", "second", "third"].map((name, i) => ({
  log_id: name,
  description: name,
  url: `https://${name}.invalid/`,
  operator: i < 2 ? "Shared operator" : "Other operator",
  state: { usable: {} }
}));

// Generate a certificate locally so healthy responses exercise actual leaf parsing.
function der(tag, ...parts) {
  const body = Buffer.concat(parts);
  const length = body.length < 128 ? [body.length] : [0x82, body.length >> 8, body.length & 255];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
function rawEntry(withDns = true) {
  const algorithm = Buffer.from("300a06082a8648ce3d040302", "hex");
  const name = der(0x30, der(0x31, der(0x30,
    Buffer.from(withDns ? "0603550403" : "060355040a", "hex"),
    der(0x0c, Buffer.from(withDns ? "direct-fixture.example" : "Fixture Organization"))
  )));
  const tbs = der(0x30, Buffer.from([2, 1, 1]), algorithm, name,
    der(0x30, der(0x17, Buffer.from("260101000000Z")), der(0x17, Buffer.from("270101000000Z"))),
    name, publicKey.export({ format: "der", type: "spki" }));
  const certificate = der(0x30, tbs, algorithm,
    der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, privateKey)));
  const header = Buffer.alloc(15);
  header.writeBigUInt64BE(BigInt(epoch), 2);
  header.writeUIntBE(certificate.length, 12, 3);
  return { leaf_input: Buffer.concat([header, certificate, Buffer.alloc(2)]).toString("base64"), extra_data: "" };
}
const certificateEntry = rawEntry();
const noDnsEntry = rawEntry(false);
const invalidCertificateLeaf = Buffer.from(certificateEntry.leaf_input, "base64");
invalidCertificateLeaf[15] = 0;
const invalidCertificateEntry = { leaf_input: invalidCertificateLeaf.toString("base64") };

function savedState() {
  return { index: 0, cursors: Object.fromEntries(logs.map((log, i) => [log.url,
    { next: 13 + i, tree_size: 100, checked_at: "2026-09-08T07:00:00Z" }
  ])) };
}

function fixture(t, configuredLogs = logs) {
  const requests = [];
  let now = epoch;
  let reply = (url) => url.pathname.endsWith("get-sth")
    ? json({ tree_size: 100 }) : json({ entries: [certificateEntry] });
  t.mock.method(Date, "now", () => now);
  t.mock.method(globalThis, "fetch", async (value) => {
    const url = new URL(value);
    if (url.href === CERTSPOTTER_LOG_LIST_URL || url.href === GOOGLE_V3_LOG_LIST_URL) {
      return json({ operators: configuredLogs.map((log) => ({ name: log.operator, logs: [log] })) });
    }
    assert.ok(configuredLogs.some((log) => url.href.startsWith(log.url)), `Unexpected request: ${url}`);
    requests.push(url);
    return reply(url);
  });
  return { requests, setTime: (value) => { now = value; }, respond: (handler) => { reply = handler; } };
}

test("fetchJson preserves HTTP status and Retry-After and cancels the failed body", async (t) => {
  t.mock.method(Date, "now", () => epoch);
  let cancelled = 0;
  const body = new ReadableStream({ cancel() { cancelled++; } });
  await assert.rejects(fetchJson("https://first.invalid/ct/v1/get-sth", {
    fetchImpl: async () => new Response(body, { status: 429, headers: { "Retry-After": "7200" } })
  }), (error) => {
    assert.equal(error.status, 429);
    assert.equal(error.retry_at, epoch + 2 * hour);
    return true;
  });
  assert.equal(cancelled, 1);
});

for (const endpoint of ["get-sth", "get-entries"]) {
  test(`429 at ${endpoint} pauses siblings, preserves failed cursors and lets healthy operators progress`, async (t) => {
    const f = fixture(t);
    const state = savedState();
    const original = structuredClone(state);
    f.respond((url) => {
      if (url.hostname === "first.invalid" && url.pathname.endsWith(endpoint)) {
        return new Response("limited", { status: 429, headers: { "Retry-After": endpoint === "get-sth"
          ? "7200" : new Date(epoch + 2 * hour).toUTCString() } });
      }
      return url.pathname.endsWith("get-sth") ? json({ tree_size: 100 }) : json({ entries: [certificateEntry] });
    });
    const run = await runDirectCtSource({ state });
    assert.equal(run.ok, false);
    assert.equal(f.requests.some((url) => url.hostname === "second.invalid"), false, "Never retry a sibling after 429");
    assert.equal(run.details.attempted_log_count, 2);
    assert.equal(run.details.cooldown_skipped_log_count, 1);
    assert.equal(run.details.successful_log_count, 1, "Cooling logs do not consume the healthy polling budget");
    assert.equal(run.scanned_entries, 1);
    assert.equal(run.entries[0].common_name, "direct-fixture.example");
    assert.equal(run.entries[0].cert_index, 15);
    assert.deepEqual(run.statePatch.direct_ct.cursors[logs[0].url], state.cursors[logs[0].url]);
    assert.deepEqual(run.statePatch.direct_ct.cursors[logs[1].url], state.cursors[logs[1].url]);
    assert.equal(run.statePatch.direct_ct.cursors[logs[2].url].next, 16);
    assert.equal(Date.parse(run.statePatch.direct_ct.cooldowns["Shared operator"]), epoch + 2 * hour);
    assert.equal(Date.parse(run.details.next_retry_at), epoch + 2 * hour);
    assert.equal(run.errors[0].status, 429);
    assert.equal(run.errors[0].retry_at, epoch + 2 * hour);
    assert.equal(run.errors[0].operator, "Shared operator");
    assert.equal(f.requests.length, endpoint === "get-sth" ? 3 : 4, "No in-run retry after failure");
    assert.deepEqual(state, original, "The caller's committed state remains unchanged");

    // Reproduce the parent's early persistence: retain old cursors, save only pauses.
    const persisted = JSON.parse(JSON.stringify({ ...state, cooldowns: run.statePatch.direct_ct.cooldowns }));
    const fresh = await import(`../lib/ct/direct-logs.js?restart=${endpoint}`);
    f.requests.length = 0;
    const replay = await fresh.runDirectCtSource({ state: persisted });
    assert.deepEqual(f.requests.map((url) => url.hostname), ["third.invalid", "third.invalid"]);
    assert.equal(replay.entries[0].cert_index, 15, "Unsaved healthy entries replay from the committed cursor");
    assert.equal(replay.details.cooldown_skipped_log_count, 2);
    assert.deepEqual(replay.statePatch.direct_ct.cooldowns, persisted.cooldowns);

    f.setTime(epoch + 2 * hour);
    f.requests.length = 0;
    f.respond(() => json({ tree_size: 100 }));
    const caughtUp = { ...persisted, cursors: Object.fromEntries(logs.map((log) => [log.url, { next: 100 }])) };
    const recovered = await fresh.runDirectCtSource({ state: caughtUp });
    assert.equal(recovered.ok, true);
    assert.deepEqual(f.requests.map((url) => url.hostname), ["first.invalid", "second.invalid"]);
    assert.equal(recovered.details.cooldown_operator_count, 0);
    assert.equal(recovered.details.next_retry_at, null);
    assert.deepEqual(recovered.statePatch.direct_ct.cooldowns, {});
  });
}

for (const header of [undefined, "1", "bad", "-10", "1e999", new Date(epoch - hour).toUTCString()]) {
  test(`429 uses a one-hour minimum for Retry-After ${String(header)}`, async (t) => {
    const f = fixture(t, [logs[0]]);
    f.respond(() => new Response("limited", { status: 429, headers: header === undefined ? {} : { "Retry-After": header } }));
    const run = await runDirectCtSource({ state: savedState() });
    assert.equal(Date.parse(run.statePatch.direct_ct.cooldowns["Shared operator"]), epoch + hour);
    assert.equal(Date.parse(run.details.next_retry_at), epoch + hour);
    assert.equal(f.requests.length, 1);
  });
}

test("all cooling operators make no provider requests and remain unhealthy", async (t) => {
  const f = fixture(t);
  const state = { ...savedState(), index: 2, cooldowns: {
    "Shared operator": new Date(epoch + 2 * hour).toISOString(),
    "Other operator": new Date(epoch + hour).toISOString(),
    expired: new Date(epoch - hour).toISOString(), invalid: "bad"
  } };
  const run = await runDirectCtSource({ state });
  assert.equal(f.requests.length, 0);
  assert.equal(run.ok, false);
  assert.equal(run.details.attempted_log_count, 0);
  assert.equal(run.details.successful_log_count, 0);
  assert.equal(run.details.cooldown_skipped_log_count, 3);
  assert.equal(run.details.cooldown_operator_count, 2);
  assert.equal(Date.parse(run.details.next_retry_at), epoch + hour);
  assert.equal(run.statePatch.direct_ct.index, 2);
  assert.deepEqual(run.statePatch.direct_ct.cursors, state.cursors);
  assert.equal(run.errors.length, 3);
  assert.equal(run.errors.every((error) => error.status === 429 && error.retry_at > epoch), true);
});

test("list failure retains cooldowns and cursor rotation for restart", async (t) => {
  fixture(t);
  const requests = [];
  t.mock.method(globalThis, "fetch", async (url) => {
    requests.push(String(url));
    return new Response("unavailable", { status: 503 });
  });
  const state = { ...savedState(), index: 2, cooldowns: { "Shared operator": new Date(epoch + hour).toISOString() } };
  const run = await runDirectCtSource({ state });
  assert.equal(run.ok, false);
  assert.deepEqual(run.statePatch.direct_ct, state);
  assert.deepEqual(requests, [CERTSPOTTER_LOG_LIST_URL, GOOGLE_V3_LOG_LIST_URL]);
  assert.equal(run.details.attempted_log_count, 0);
});

for (const failure of ["503", "timeout", "json"]) {
  test(`${failure} failure preserves the cursor and leaves sibling capacity available`, async (t) => {
    const f = fixture(t);
    const state = savedState();
    f.respond((url) => {
      if (url.hostname === "first.invalid") {
        if (failure === "timeout") throw new DOMException("Provider timed out", "TimeoutError");
        return new Response(failure === "503" ? "unavailable" : "{", { status: failure === "503" ? 503 : 200 });
      }
      return url.pathname.endsWith("get-sth") ? json({ tree_size: 100 }) : json({ entries: [certificateEntry] });
    });
    const run = await runDirectCtSource({ state });
    assert.equal(run.ok, false);
    assert.equal(run.details.successful_log_count, 1);
    assert.deepEqual(run.statePatch.direct_ct.cursors[logs[0].url], state.cursors[logs[0].url]);
    assert.equal(run.statePatch.direct_ct.cursors[logs[1].url].next, 15);
    assert.deepEqual(run.statePatch.direct_ct.cooldowns, {});
    assert.equal(run.statePatch.direct_ct.index, 2);
    assert.equal(f.requests.length, 3);
  });
}

for (const sth of [null, {}, { tree_size: "100" }, { tree_size: -1 }, { tree_size: 1.5 },
  { tree_size: Number.MAX_SAFE_INTEGER + 1 }, { tree_size: 0 }, { tree_size: 12 }]) {
  test(`invalid or regressed tree ${JSON.stringify(sth)} cannot reset a committed cursor`, async (t) => {
    const f = fixture(t, [logs[0]]);
    const state = savedState();
    f.respond(() => json(sth));
    const run = await runDirectCtSource({ state });
    assert.equal(run.ok, false);
    assert.equal(run.details.successful_log_count, 0);
    assert.deepEqual(run.statePatch.direct_ct.cursors, state.cursors);
    assert.equal(f.requests.length, 1);
  });
}

for (const payload of [null, {}, { entries: null }, { entries: [] }, { entries: [null] },
  { entries: [{}] }, { entries: [certificateEntry, certificateEntry, certificateEntry] },
  { entries: [{ leaf_input: "not-a-leaf" }] }, { entries: [invalidCertificateEntry] },
  { entries: [certificateEntry, { leaf_input: "not-a-leaf" }] }]) {
  test(`invalid entry response ${JSON.stringify(payload).slice(0, 45)} cannot advance a cursor`, async (t) => {
    const f = fixture(t, [logs[0]]);
    const state = savedState();
    f.respond((url) => url.pathname.endsWith("get-sth") ? json({ tree_size: 100 }) : json(payload));
    const run = await runDirectCtSource({ state });
    assert.equal(run.ok, false);
    assert.equal(run.details.successful_log_count, 0);
    assert.deepEqual(run.statePatch.direct_ct.cursors, state.cursors);
    assert.equal(run.scanned_entries, 0);
    assert.equal(f.requests.length, 2);
  });
}

test("bounded batches accept short responses, including certificates without DNS names", async (t) => {
  const f = fixture(t);
  const state = savedState();
  f.respond((url) => {
    if (url.pathname.endsWith("get-sth")) return json({ tree_size: 100 });
    assert.equal(Number(url.searchParams.get("end")) - Number(url.searchParams.get("start")), 1);
    return json({ entries: [url.hostname === "first.invalid" ? certificateEntry : noDnsEntry] });
  });
  const run = await runDirectCtSource({ state });
  assert.equal(run.ok, true);
  assert.equal(run.details.attempted_log_count, 2);
  assert.equal(run.scanned_entries, 2);
  assert.equal(run.entries.length, 1);
  assert.equal(run.statePatch.direct_ct.cursors[logs[0].url].next, 14);
  assert.equal(run.statePatch.direct_ct.cursors[logs[1].url].next, 15);
  assert.deepEqual(run.statePatch.direct_ct.cursors[logs[2].url], state.cursors[logs[2].url]);
  assert.equal(run.statePatch.direct_ct.index, 2);
  assert.equal(f.requests.length, 4);
});

test("empty and caught-up trees are healthy with no entry requests", async (t) => {
  const f = fixture(t);
  f.respond((url) => json({ tree_size: url.hostname === "first.invalid" ? 0 : 14 }));
  const run = await runDirectCtSource({ state: { cursors: { [logs[1].url]: { next: 14 } } } });
  assert.equal(run.ok, true);
  assert.equal(run.details.successful_log_count, 2);
  assert.equal(run.scanned_entries, 0);
  assert.equal(run.statePatch.direct_ct.cursors[logs[0].url].next, 0);
  assert.equal(run.statePatch.direct_ct.cursors[logs[1].url].next, 14);
  assert.equal(f.requests.length, 2);
});

test("invalid saved rotation restarts safely at the first log", async (t) => {
  const f = fixture(t);
  f.respond(() => json({ tree_size: 0 }));
  const run = await runDirectCtSource({ state: { index: -1 } });
  assert.equal(run.ok, true);
  assert.deepEqual(f.requests.map((url) => url.hostname), ["first.invalid", "second.invalid"]);
  assert.equal(run.statePatch.direct_ct.index, 2);
});

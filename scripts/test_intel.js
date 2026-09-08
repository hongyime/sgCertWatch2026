import assert from "node:assert/strict";
import test from "node:test";
import { attachIntelEvidence, makeEvidence, normalizeIntelHost } from "../lib/intel/evidence.js";
import { fetchSource, parseOpenPhish, parseThreatFox, parseUrlhaus, parseUrlscanResult, requestIntel } from "../lib/intel/sources.js";
import { runIntelPipeline } from "../lib/intel/pipeline.js";

const now = Date.parse("2026-09-08T03:00:00Z");
const date = new Date(now).toISOString();
const finding = { id: "test", registrable: "example.test", domains: ["login.example.test"], score: 68, suppressed: false };
assert.equal(normalizeIntelHost("https://LOGIN.example.test./path?token=secret"), "login.example.test");
for (const bad of ["http://127.0.0.1/", "https://[::1]/", "javascript:alert(1)", "http://user:pass@example.test/", "https://bad_host.test/"]) assert.equal(normalizeIntelHost(bad), null);
const phishing = parseOpenPhish("https://login.example.test/a?token=private\nhttps://sibling.example.test/\n", now);
assert.equal(phishing.length, 2);
assert.equal(JSON.stringify(phishing).includes("private"), false);
assert.throws(() => parseOpenPhish("<html>unavailable</html>", now));
const joined = attachIntelEvidence(finding, phishing, now);
assert.equal(joined.intel_evidence.length, 1);
assert.equal(joined.score, 68);
assert.equal(joined.priority_score, 78);
assert.equal(attachIntelEvidence({ ...finding, score: 59 }, phishing, now).intel_priority_boost, 0);
assert.equal(attachIntelEvidence({ ...finding, suppressed: true }, phishing, now).intel_hit_count, 0);
assert.equal(attachIntelEvidence(finding, phishing, now + 25 * 3600000).intel_priority_boost, 0);
assert.equal(attachIntelEvidence({ ...finding, domains: ["clean.example.test"] }, phishing, now).intel_hit_count, 0);
const malware = parseUrlhaus(JSON.stringify({ query_status: "ok", urls: [{ id: 123, url: "https://login.example.test/payload", date_added: date, url_status: "offline", threat: "malware_download" }] }), now);
assert.equal(attachIntelEvidence(finding, malware, now).intel_priority_boost, 0);
assert.equal(attachIntelEvidence(finding, [{ ...malware[0], details: { url_status: "online" } }], now).intel_priority_boost, 10);
const fox = parseThreatFox(JSON.stringify({ query_status: "ok", data: [
  { id: 12, ioc: "login.example.test", ioc_type: "domain", confidence_level: 50, first_seen: date },
  { id: 13, ioc: "127.0.0.1:443", ioc_type: "ip:port", confidence_level: 100, first_seen: date }
] }), now);
assert.equal(fox.length, 1);
assert.equal(attachIntelEvidence(finding, fox, now).intel_priority_boost, 0);
assert.equal(attachIntelEvidence(finding, [{ ...fox[0], details: { confidence: 80 } }], now).intel_priority_boost, 10);
assert.equal(makeEvidence({ source: "threatfox", indicator: "login.example.test", observed_at: "2020-01-01" }, now), null);
const scan = { task: { uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", url: "https://login.example.test/", time: date, visibility: "public" },
  page: { url: "https://login.example.test/", title: "Sign in" } };
const observed = parseUrlscanResult(scan, "login.example.test", now);
assert.equal(observed.verdict, "observed");
assert.equal(attachIntelEvidence(finding, [observed], now).intel_priority_boost, 0);
assert.equal(parseUrlscanResult(scan, "sibling.example.test", now), null);
assert.equal(parseUrlscanResult({ ...scan, task: { ...scan.task, visibility: "private" } }, "login.example.test", now), null);
const confirmed = parseUrlscanResult({ ...scan, verdicts: { urlscan: { malicious: true, categories: ["phishing"] } } }, "login.example.test", now);
assert.equal(attachIntelEvidence(finding, [confirmed, ...phishing], now).intel_priority_boost, 10);
assert.equal(attachIntelEvidence(finding, [confirmed, ...phishing], now).intel_hit_count, 2);

const env = { ABUSECH_AUTH_KEY: "test-abuse-key", URLSCAN_API_KEY: "test-urlscan-key" };
let state = {};
const calls = [];
const stored = [];
const fetchImpl = async (url, options) => {
  const address = String(url);
  calls.push(address);
  assert.ok(Object.values(state.sources).some((row) => Date.parse(row.next_poll_at) > now), "request budget reserved first");
  assert.equal(options.redirect, "error");
  if (address.includes("raw.githubusercontent")) return new Response("https://login.example.test/phish\nhttps://unrelated.test/\n");
  if (address.includes("urlhaus-api")) {
    assert.equal(options.headers["Auth-Key"], env.ABUSECH_AUTH_KEY);
    return Response.json({ query_status: "no_results" });
  }
  if (address.includes("threatfox-api")) return Response.json({ query_status: "no_results" });
  assert.equal(options.headers["api-key"], env.URLSCAN_API_KEY);
  return Response.json({ results: [] });
};
const options = { env, candidates: [finding], now, fetchImpl,
  saveState: async (value) => { state = structuredClone(value); },
  saveEvidence: async (rows) => { stored.push(...rows); return rows; } };
const first = await runIntelPipeline(options);
assert.equal(calls.length, 4);
assert.equal(stored.length, 1);
assert.ok(first.status.sources.every((source) => source.ok));
await runIntelPipeline({ ...options, state, now: now + 3600000 });
assert.equal(calls.length, 4, "scheduled runs reuse persistent polling slots");

let limitedCalls = 0;
const limited = await runIntelPipeline({ ...options, state: {},
  fetchImpl: async (url) => {
    limitedCalls++;
    if (String(url).includes("raw.githubusercontent")) return new Response("https://login.example.test/phish");
    if (String(url).includes("urlhaus-api")) return new Response("key echoed by remote", { status: 429, headers: { "Retry-After": "60" } });
    assert.equal(String(url).includes("threatfox-api"), false, "abuse.ch sibling blocked by shared cooldown");
    return Response.json({ results: [] });
  }
});
assert.equal(limitedCalls, 3);
assert.equal(Date.parse(limited.state.abuse_cooldown_until), now + 72 * 3600000);
assert.equal(limited.status.sources.find((row) => row.source === "threatfox").status, "cooldown");
assert.equal(JSON.stringify(limited.status).includes("key echoed"), false);
const missing = await runIntelPipeline({ ...options, env: {}, state: first.state });
assert.equal(missing.status.sources.filter((row) => row.status === "not_configured").length, 3);
await assert.rejects(requestIntel("https://urlscan.io/api/v1/search/", {}, {
  now, fetchImpl: async () => new Response("wait", { status: 429, headers: { "Retry-After": "Wed, 09 Sep 2026 03:00:00 GMT" } })
}), (error) => error.status === 429 && error.retryAt === now + 86400000);

let searches = 0;
const rotation = await fetchSource("urlscan", { env, now, cursor: 1,
  candidates: [finding, { ...finding, domains: ["two.example.test", "three.example.test", "four.example.test"] }],
  fetchImpl: async (url) => { searches++; assert.ok(new URL(url).searchParams.get("q").includes("task.visibility:public")); return Response.json({ results: [] }); }
});
assert.equal(searches, 3);
assert.equal(rotation.cursor, 0);
let quotaCalls = 0;
await fetchSource("urlscan", { env, now, candidates: [finding, { ...finding, domains: ["two.example.test"] }],
  fetchImpl: async () => { quotaCalls++; return Response.json({ results: [] }, { headers: { "X-Rate-Limit-Remaining": "0" } }); }
});
assert.equal(quotaCalls, 1);
console.log("Intel parsing, provenance, exact-host matching, priority, budgets and cooldown tests passed.");

await test("missing provider timestamps cannot create fresh malicious evidence", () => {
  for (const timestamp of [undefined, null, "", "not-a-date", new Date(now + 300001).toISOString()]) {
    const haus = parseUrlhaus(JSON.stringify({ query_status: "ok", urls: [{
      id: 123, url: "https://login.example.test/payload", threat: "malware_download",
      url_status: "online", date_added: timestamp
    }] }), now);
    const threatfox = parseThreatFox(JSON.stringify({ query_status: "ok", data: [{
      id: 12, ioc: "login.example.test", ioc_type: "domain", confidence_level: 100,
      first_seen: timestamp, last_seen: timestamp
    }] }), now);
    assert.deepEqual(haus, [], `URLhaus rejects timestamp ${String(timestamp)}`);
    assert.deepEqual(threatfox, [], `ThreatFox rejects timestamp ${String(timestamp)}`);
    assert.equal(attachIntelEvidence(finding, [...haus, ...threatfox], now).intel_priority_boost, 0);
  }
  for (const timestamps of [{ first_seen: date }, { last_seen: date }]) {
    const rows = parseThreatFox(JSON.stringify({ query_status: "ok", data: [{
      id: 12, ioc: "login.example.test", ioc_type: "domain", confidence_level: 100, ...timestamps
    }] }), now);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].observed_at, date);
  }
  assert.equal(phishing[0].observed_at, date, "OpenPhish explicitly uses retrieval time");
  assert.equal(Date.parse(phishing[0].expires_at), now + 24 * 3600000);
});

await test("wildcard-only findings neither match apex evidence nor query the apex", async () => {
  const wildcard = { ...finding, domains: ["*.example.test"] };
  const apex = parseOpenPhish("https://example.test/phish", now);
  for (const host of ["*.example.test", "https://*.example.test/phish"]) {
    assert.equal(normalizeIntelHost(host), null);
  }
  const attached = attachIntelEvidence(wildcard, [...apex, ...phishing], now);
  assert.deepEqual(attached.intel_evidence, []);
  assert.equal(attached.intel_priority_boost, 0);
  assert.equal(attachIntelEvidence({ ...finding, domains: ["*.example.test", "example.test"] }, apex, now).intel_priority_boost, 10);
  const requests = [];
  const result = await fetchSource("urlscan", { env, now, candidates: [wildcard],
    fetchImpl: async (url) => { requests.push(String(url)); return Response.json({ results: [] }); }
  });
  assert.deepEqual(requests, []);
  assert.equal(result.scanned_entries, 0);
});

await test("abuse.ch in-flight guard survives failed completion and recovery saves", async (t) => {
  const cooldownEnd = new Date(now + 72 * 3600000).toISOString();
  const deferOpenPhish = { next_poll_at: new Date(now + 96 * 3600000).toISOString() };
  for (const source of ["urlhaus", "threatfox"]) {
    for (const status of [200, 429]) {
      await t.test(`${source} HTTP ${status}`, async () => {
        let durable = { sources: { openphish: deferOpenPhish } };
        if (source === "threatfox") durable.sources.urlhaus = { next_poll_at: new Date(now + 3600000).toISOString() };
        const failure = new Error("mock state save failure");
        const requests = [];
        const guardsAtRequest = [];
        let writes = 0;
        const base = { env: { ABUSECH_AUTH_KEY: "mock-abuse-key" }, now, candidates: [finding],
          saveEvidence: async (rows) => rows };
        // Only cloned, successfully saved snapshots survive a simulated worker restart.
        await assert.rejects(runIntelPipeline({ ...base, state: durable,
          saveState: async (value) => {
            if (++writes === 2) throw failure;
            durable = structuredClone(value);
          },
          fetchImpl: async (url) => {
            requests.push(new URL(url).hostname);
            guardsAtRequest.push(durable.abuse_inflight_at);
            return status === 429 ? new Response("mock rate limit", { status: 429 })
              : Response.json({ query_status: "no_results" });
          }
        }), (error) => error === failure);
        assert.equal(writes, 2);
        assert.deepEqual(requests, [`${source}-api.abuse.ch`]);
        assert.deepEqual(guardsAtRequest, [date], "shared guard is durable before the provider request");
        assert.equal(durable.abuse_inflight_at, date, "failed completion cannot clear the durable guard");

        requests.length = 0;
        const restart = { ...base, fetchImpl: async (url) => {
          requests.push(new URL(url).hostname);
          return Response.json({ query_status: "no_results" });
        } };
        await assert.rejects(runIntelPipeline({ ...restart, state: durable, now: now + 60000,
          saveState: async () => { throw failure; }
        }), (error) => error === failure);
        assert.deepEqual(requests, [], "failed recovery save stops all provider requests");
        assert.equal(durable.abuse_inflight_at, date);

        const saveState = async (value) => { durable = structuredClone(value); };
        for (const elapsed of [120000, 6 * 3600000, 72 * 3600000 - 1]) {
          const recovered = await runIntelPipeline({ ...restart, state: durable, now: now + elapsed, saveState });
          assert.deepEqual(requests, [], "both endpoints stay blocked after individual reservations expire");
          assert.equal(durable.abuse_inflight_at, undefined);
          assert.equal(durable.abuse_cooldown_until, cooldownEnd, "restarts do not extend the original guard deadline");
          for (const row of recovered.status.sources.filter((item) => ["urlhaus", "threatfox"].includes(item.source))) {
            assert.equal(row.status, "cooldown");
            assert.equal(row.next_poll_at, cooldownEnd);
          }
        }
        const resumed = await runIntelPipeline({ ...restart, state: durable, now: now + 72 * 3600000, saveState });
        assert.deepEqual(requests, ["urlhaus-api.abuse.ch", "threatfox-api.abuse.ch"]);
        assert.equal(durable.abuse_inflight_at, undefined);
        assert.ok(resumed.status.sources.filter((row) => ["urlhaus", "threatfox"].includes(row.source)).every((row) => row.ok));
      });
    }
  }
  await t.test("failed reservation save prevents the initial request", async () => {
    const failure = new Error("mock reservation failure");
    const requests = [];
    await assert.rejects(runIntelPipeline({ now, candidates: [finding], env: { ABUSECH_AUTH_KEY: "mock-abuse-key" },
      state: { sources: { openphish: deferOpenPhish } },
      saveState: async () => { throw failure; }, saveEvidence: async (rows) => rows,
      fetchImpl: async (url) => { requests.push(String(url)); return Response.json({ query_status: "no_results" }); }
    }), (error) => error === failure);
    assert.deepEqual(requests, []);
  });
});

await test("urlscan persists the longest exhausted quota through later failures", async (t) => {
  const resetAt = new Date(now + 72 * 3600000).toISOString();
  const quotaHeaders = { "X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": resetAt };
  const scenarios = [
    { name: "search reset survives detail 429", searchExhausted: true, status: "cooldown",
      detail: () => new Response("mock rate limit", { status: 429, headers: { "Retry-After": "60" } }) },
    { name: "search reset survives malformed detail JSON", searchExhausted: true, status: "degraded",
      detail: () => new Response("{") },
    { name: "shorter detail reset cannot overwrite search reset", searchExhausted: true, status: "ok",
      detail: () => Response.json(scan, { headers: { ...quotaHeaders, "X-Rate-Limit-Reset": new Date(now + 6 * 3600000).toISOString() } }) },
    { name: "detail reset survives malformed detail JSON", searchExhausted: false, status: "degraded",
      detail: () => new Response("{", { headers: quotaHeaders }) },
    { name: "search reset survives failed evidence persistence", searchExhausted: true, status: "degraded", storageFailure: true,
      detail: () => Response.json(scan) }
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      let durable = { sources: { openphish: { next_poll_at: new Date(now + 96 * 3600000).toISOString() } } };
      const requests = [];
      const saveState = async (value) => { durable = structuredClone(value); };
      const base = { now, candidates: [finding], env: { URLSCAN_API_KEY: "mock-urlscan-key" }, saveState,
        saveEvidence: async (rows) => {
          if (scenario.storageFailure) throw new Error("mock evidence save failure");
          return rows;
        },
        fetchImpl: async (url) => {
          const address = new URL(url);
          requests.push(address.pathname);
          return address.pathname === "/api/v1/search/"
            ? Response.json({ results: [{ _id: scan.task.uuid, page: { domain: "login.example.test" } }] },
              { headers: scenario.searchExhausted ? quotaHeaders : {} })
            : scenario.detail();
        }
      };
      const result = await runIntelPipeline({ ...base, state: durable });
      assert.deepEqual(requests, ["/api/v1/search/", `/api/v1/result/${scan.task.uuid}/`]);
      assert.equal(result.state.sources.urlscan.status, scenario.status);
      assert.equal(durable.sources.urlscan.next_poll_at, resetAt, "the full provider reset must survive in durable state");
      requests.length = 0;
      await runIntelPipeline({ ...base, state: durable, now: now + 6 * 3600000 });
      assert.deepEqual(requests, [], "restart cannot query urlscan before the provider reset");
    });
  }
});

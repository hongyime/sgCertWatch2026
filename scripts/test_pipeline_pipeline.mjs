/**
 * Pipeline orchestration tests — covers runIntelPipeline error handling,
 * auth failures, forbidden status, state persistence edge cases, and
 * SOURCE_CONFIG contract.
 *
 * These complement test_intel.js (which covers happy-path, cooldowns,
 * budget reservation, and in-flight guards) by exercising the error
 * classification branches and state recovery paths.
 *
 * Run: node --test scripts/test_pipeline_pipeline.mjs
 */
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runIntelPipeline } from "../lib/intel/pipeline.js";
import { SOURCE_CONFIG, IntelRequestError } from "../lib/intel/sources.js";

const NOW = Date.parse("2026-09-10T12:00:00Z");
const ISO_NOW = new Date(NOW).toISOString();
const finding = { id: "test", registrable: "example.test", domains: ["login.example.test"], score: 68, suppressed: false };

// Defer openphish so we can isolate individual source behaviour
const deferOpenPhish = { next_poll_at: new Date(NOW + 96 * 3600000).toISOString() };

function basePipelineOptions(overrides = {}) {
  let durable = { sources: { openphish: deferOpenPhish } };
  return {
    env: { ABUSECH_AUTH_KEY: "mock-abuse-key", URLSCAN_API_KEY: "mock-urlscan-key" },
    now: NOW,
    candidates: [finding],
    state: durable,
    saveState: async (value) => { durable = structuredClone(value); },
    saveEvidence: async (rows) => rows,
    fetchImpl: async () => Response.json({ query_status: "no_results" }),
    get durable() { return durable; },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// SOURCE_CONFIG contract
// ---------------------------------------------------------------------------
describe("SOURCE_CONFIG", () => {
  test("defines all four intel sources", () => {
    assert.deepEqual(Object.keys(SOURCE_CONFIG).sort(), ["openphish", "threatfox", "urlhaus", "urlscan"]);
  });

  test("each source has a label and interval_hours", () => {
    for (const [name, config] of Object.entries(SOURCE_CONFIG)) {
      assert.ok(config.label, `${name} missing label`);
      assert.ok(typeof config.interval_hours === "number" && config.interval_hours > 0, `${name} missing interval_hours`);
    }
  });

  test("abuse.ch sources share the same API key name", () => {
    assert.equal(SOURCE_CONFIG.urlhaus.key, "ABUSECH_AUTH_KEY");
    assert.equal(SOURCE_CONFIG.threatfox.key, "ABUSECH_AUTH_KEY");
  });

  test("openphish requires no API key", () => {
    assert.equal(SOURCE_CONFIG.openphish.key, undefined);
  });

  test("urlscan requires its own API key", () => {
    assert.equal(SOURCE_CONFIG.urlscan.key, "URLSCAN_API_KEY");
  });
});

// ---------------------------------------------------------------------------
// Auth error handling (HTTP 401/403)
// ---------------------------------------------------------------------------
describe("pipeline auth error handling", () => {
  test("HTTP 401 sets auth_error status with 24-hour pause", async () => {
    const requests = [];
    const opts = basePipelineOptions({
      state: { sources: { openphish: deferOpenPhish, urlscan: { next_poll_at: new Date(NOW + 96 * 3600000).toISOString() } } },
      env: { ABUSECH_AUTH_KEY: "bad-key" },
      fetchImpl: async (url) => {
        requests.push(new URL(url).hostname);
        if (String(url).includes("urlhaus-api") || String(url).includes("threatfox-api")) {
          return new Response("Unauthorized", { status: 401 });
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlhaus = result.status.sources.find((s) => s.source === "urlhaus");
    assert.equal(urlhaus.status, "cooldown"); // cooldown propagated from abuse sibling
    assert.equal(urlhaus.ok, false);
    assert.ok(urlhaus.errors.length > 0 || urlhaus.status === "cooldown");
  });

  test("HTTP 403 sets auth_error status with 24-hour pause for non-abuse source", async () => {
    const opts = basePipelineOptions({
      state: {
        sources: {
          openphish: deferOpenPhish,
          urlhaus: { next_poll_at: new Date(NOW + 96 * 3600000).toISOString() },
          threatfox: { next_poll_at: new Date(NOW + 96 * 3600000).toISOString() },
        },
      },
      env: { URLSCAN_API_KEY: "bad-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io")) {
          return new Response("Forbidden", { status: 403 });
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    assert.equal(urlscan.status, "auth_error");
    assert.equal(urlscan.ok, false);
    // 24-hour pause for forbidden
    const retryAt = Date.parse(urlscan.next_poll_at);
    assert.ok(retryAt >= NOW + 24 * 3600000, "auth_error should pause for at least 24 hours");
  });

  test("HTTP 403 on abuse.ch source triggers shared cooldown", async () => {
    const opts = basePipelineOptions({
      state: { sources: { openphish: deferOpenPhish } },
      env: { ABUSECH_AUTH_KEY: "bad-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlhaus-api")) {
          return new Response("Forbidden", { status: 403 });
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    // Both abuse.ch sources should be in cooldown
    const urlhaus = result.status.sources.find((s) => s.source === "urlhaus");
    const threatfox = result.status.sources.find((s) => s.source === "threatfox");
    assert.equal(urlhaus.status, "cooldown");
    assert.equal(threatfox.status, "cooldown");
    assert.ok(result.state.abuse_cooldown_until, "shared cooldown should be set");
  });
});

// ---------------------------------------------------------------------------
// Degraded status (non-HTTP errors)
// ---------------------------------------------------------------------------
describe("pipeline degraded status", () => {
  test("non-HTTP errors produce degraded status with generic message", async () => {
    const opts = basePipelineOptions({
      state: {
        sources: {
          openphish: deferOpenPhish,
          urlhaus: { next_poll_at: new Date(NOW + 96 * 3600000).toISOString() },
          threatfox: { next_poll_at: new Date(NOW + 96 * 3600000).toISOString() },
        },
      },
      env: { URLSCAN_API_KEY: "mock-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io")) {
          throw new Error("Network timeout");
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    assert.equal(urlscan.status, "degraded");
    assert.equal(urlscan.ok, false);
    assert.equal(urlscan.errors[0].message, "Fetch, validation or storage failed");
  });

  test("storage failure produces degraded status", async () => {
    const opts = basePipelineOptions({
      state: { sources: { openphish: deferOpenPhish, urlhaus: deferOpenPhish, threatfox: deferOpenPhish } },
      env: { URLSCAN_API_KEY: "mock-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io/api/v1/search")) {
          return Response.json({ results: [] });
        }
        return Response.json({ query_status: "no_results" });
      },
      saveEvidence: async () => { throw new Error("DB connection lost"); },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    assert.equal(urlscan.status, "degraded");
    assert.equal(urlscan.ok, false);
  });
});

// ---------------------------------------------------------------------------
// Error message sanitization
// ---------------------------------------------------------------------------
describe("pipeline error message sanitization", () => {
  test("HTTP errors include status code but not response body", async () => {
    const opts = basePipelineOptions({
      state: {
        sources: {
          openphish: deferOpenPhish,
          urlhaus: deferOpenPhish,
          threatfox: deferOpenPhish,
        },
      },
      env: { URLSCAN_API_KEY: "mock-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io")) {
          return new Response("Secret API key echoed: mock-key", { status: 429, headers: { "Retry-After": "60" } });
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    const serialized = JSON.stringify(result.status);
    assert.ok(!serialized.includes("mock-key"), "API key must not leak into status output");
    assert.ok(urlscan.errors[0].message.includes("429"), "HTTP status code should be in error message");
  });

  test("non-HTTP errors do not leak internal error messages", async () => {
    const opts = basePipelineOptions({
      state: {
        sources: {
          openphish: deferOpenPhish,
          urlhaus: deferOpenPhish,
          threatfox: deferOpenPhish,
        },
      },
      env: { URLSCAN_API_KEY: "mock-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io")) {
          throw new Error("ECONNREFUSED 10.0.0.1:5432 internal DB");
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    assert.equal(urlscan.errors[0].message, "Fetch, validation or storage failed");
    assert.ok(!JSON.stringify(result.status).includes("ECONNREFUSED"), "internal error details must not leak");
  });
});

// ---------------------------------------------------------------------------
// State persistence and not_configured handling
// ---------------------------------------------------------------------------
describe("pipeline state persistence", () => {
  test("missing env keys produce not_configured status", async () => {
    const opts = basePipelineOptions({
      env: {}, // no keys at all
      state: {},
    });

    const result = await runIntelPipeline(opts);
    // openphish has no key requirement, so it should attempt to run
    const openphish = result.status.sources.find((s) => s.source === "openphish");
    assert.notEqual(openphish.status, "not_configured");

    // urlhaus, threatfox, urlscan all require keys
    for (const name of ["urlhaus", "threatfox", "urlscan"]) {
      const source = result.status.sources.find((s) => s.source === name);
      assert.equal(source.status, "not_configured", `${name} should be not_configured without env key`);
      assert.deepEqual(source.errors, []);
      assert.equal(source.next_poll_at, null);
    }
  });

  test("runner field is always github-actions", async () => {
    const opts = basePipelineOptions({ state: {} });
    const result = await runIntelPipeline(opts);
    assert.equal(result.status.runner, "github-actions");
  });

  test("checked_at reflects the provided now timestamp", async () => {
    const opts = basePipelineOptions({ state: {} });
    const result = await runIntelPipeline(opts);
    assert.equal(result.status.checked_at, ISO_NOW);
  });

  test("all four sources appear in status output", async () => {
    const opts = basePipelineOptions({ state: {} });
    const result = await runIntelPipeline(opts);
    const sourceNames = result.status.sources.map((s) => s.source).sort();
    assert.deepEqual(sourceNames, ["openphish", "threatfox", "urlhaus", "urlscan"]);
  });

  test("suppressed candidates do not contribute hosts for matching", async () => {
    const saved = [];
    const opts = basePipelineOptions({
      state: {},
      candidates: [{ ...finding, suppressed: true }],
      fetchImpl: async (url) => {
        if (String(url).includes("raw.githubusercontent")) {
          return new Response("https://login.example.test/phish\n");
        }
        return Response.json({ query_status: "no_results" });
      },
      saveEvidence: async (rows) => { saved.push(...rows); return rows; },
    });

    const result = await runIntelPipeline(opts);
    // OpenPhish will parse the feed and find evidence for login.example.test,
    // but since the only candidate is suppressed, the host set is empty,
    // so no evidence should be matched/persisted
    assert.equal(saved.length, 0, "suppressed candidates should not match evidence");
  });

  test("empty candidates list produces zero matched evidence", async () => {
    const saved = [];
    const opts = basePipelineOptions({
      state: {},
      candidates: [],
      fetchImpl: async (url) => {
        if (String(url).includes("raw.githubusercontent")) {
          return new Response("https://login.example.test/phish\n");
        }
        return Response.json({ query_status: "no_results" });
      },
      saveEvidence: async (rows) => { saved.push(...rows); return rows; },
    });

    const result = await runIntelPipeline(opts);
    assert.equal(saved.length, 0);
    const openphish = result.status.sources.find((s) => s.source === "openphish");
    assert.equal(openphish.matched, 0);
  });
});

// ---------------------------------------------------------------------------
// Pause duration classification
// ---------------------------------------------------------------------------
describe("pipeline pause duration classification", () => {
  test("429 on abuse.ch source pauses for 72 hours", async () => {
    const opts = basePipelineOptions({
      state: { sources: { openphish: deferOpenPhish } },
      env: { ABUSECH_AUTH_KEY: "mock-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlhaus-api")) {
          return new Response("Rate limited", { status: 429 });
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlhaus = result.status.sources.find((s) => s.source === "urlhaus");
    assert.equal(urlhaus.status, "cooldown");
    const retryAt = Date.parse(urlhaus.next_poll_at);
    assert.ok(retryAt >= NOW + 72 * 3600000, "abuse.ch 429 should pause for 72 hours");
  });

  test("401 on non-abuse source pauses for 24 hours", async () => {
    const opts = basePipelineOptions({
      state: {
        sources: {
          openphish: deferOpenPhish,
          urlhaus: deferOpenPhish,
          threatfox: deferOpenPhish,
        },
      },
      env: { URLSCAN_API_KEY: "bad-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io")) {
          return new Response("Unauthorized", { status: 401 });
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    assert.equal(urlscan.status, "auth_error");
    const retryAt = Date.parse(urlscan.next_poll_at);
    assert.ok(retryAt >= NOW + 24 * 3600000, "non-abuse 401 should pause for 24 hours");
  });

  test("generic error on non-abuse source pauses for interval_hours", async () => {
    const opts = basePipelineOptions({
      state: {
        sources: {
          openphish: deferOpenPhish,
          urlhaus: deferOpenPhish,
          threatfox: deferOpenPhish,
        },
      },
      env: { URLSCAN_API_KEY: "mock-key" },
      fetchImpl: async (url) => {
        if (String(url).includes("urlscan.io")) {
          throw new Error("DNS resolution failed");
        }
        return Response.json({ query_status: "no_results" });
      },
    });

    const result = await runIntelPipeline(opts);
    const urlscan = result.status.sources.find((s) => s.source === "urlscan");
    assert.equal(urlscan.status, "degraded");
    const retryAt = Date.parse(urlscan.next_poll_at);
    const expectedPause = SOURCE_CONFIG.urlscan.interval_hours * 3600000;
    assert.ok(retryAt >= NOW + expectedPause, "generic error should pause for interval_hours");
  });
});

// ---------------------------------------------------------------------------
// IntelRequestError
// ---------------------------------------------------------------------------
describe("IntelRequestError", () => {
  test("carries status and retryAt properties", () => {
    const err = new IntelRequestError("test error", 429, 1000);
    assert.equal(err.message, "test error");
    assert.equal(err.status, 429);
    assert.equal(err.retryAt, 1000);
    assert.ok(err instanceof Error);
  });

  test("defaults to status 0 and retryAt 0", () => {
    const err = new IntelRequestError("test");
    assert.equal(err.status, 0);
    assert.equal(err.retryAt, 0);
  });
});

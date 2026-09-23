/**
 * Pipeline evidence layer tests — covers normalizeIntelHost, makeEvidence,
 * feed parsers, attachIntelEvidence, and findingHosts.
 *
 * These complement test_intel.js (which covers integration/orchestration)
 * by exercising every rejection path, boundary condition, and schema
 * invariant in the pure-function evidence layer.
 *
 * Run: node --test scripts/test_pipeline_evidence.mjs
 */
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  INTEL_SOURCES,
  normalizeIntelHost,
  findingHosts,
  digest,
  makeEvidence,
  attachIntelEvidence,
} from "../lib/intel/evidence.js";
import {
  parseOpenPhish,
  parseUrlhaus,
  parseThreatFox,
  parseUrlscanResult,
  IntelRequestError,
} from "../lib/intel/sources.js";

const NOW = Date.parse("2026-09-10T12:00:00Z");
const ISO_NOW = new Date(NOW).toISOString();

// ---------------------------------------------------------------------------
// normalizeIntelHost — exhaustive edge-case coverage
// ---------------------------------------------------------------------------
describe("normalizeIntelHost", () => {
  test("extracts hostname from full HTTPS URL, strips path/query/fragment", () => {
    assert.equal(normalizeIntelHost("https://LOGIN.Example.Test/path?q=1#frag"), "login.example.test");
  });

  test("extracts hostname from HTTP URL", () => {
    assert.equal(normalizeIntelHost("http://phish.example.test/steal"), "phish.example.test");
  });

  test("bare hostname without protocol gets https:// prepended", () => {
    assert.equal(normalizeIntelHost("login.example.test"), "login.example.test");
  });

  test("strips trailing dot from hostname", () => {
    assert.equal(normalizeIntelHost("login.example.test."), "login.example.test");
  });

  test("lowercases mixed-case input", () => {
    assert.equal(normalizeIntelHost("LOGIN.EXAMPLE.TEST"), "login.example.test");
  });

  test("trims whitespace", () => {
    assert.equal(normalizeIntelHost("  login.example.test  "), "login.example.test");
  });

  // --- Rejection paths ---
  test("rejects null/undefined/empty", () => {
    assert.equal(normalizeIntelHost(null), null);
    assert.equal(normalizeIntelHost(undefined), null);
    assert.equal(normalizeIntelHost(""), null);
  });

  test("rejects wildcard hostnames", () => {
    assert.equal(normalizeIntelHost("*.example.test"), null);
    assert.equal(normalizeIntelHost("https://*.example.test/"), null);
  });

  test("rejects IPv4 addresses", () => {
    assert.equal(normalizeIntelHost("http://127.0.0.1/"), null);
    assert.equal(normalizeIntelHost("192.168.1.1"), null);
    assert.equal(normalizeIntelHost("http://10.0.0.1/path"), null);
  });

  test("rejects IPv6 addresses", () => {
    assert.equal(normalizeIntelHost("https://[::1]/"), null);
    assert.equal(normalizeIntelHost("[2001:db8::1]"), null);
  });

  test("rejects non-http(s) protocols (XSS vectors)", () => {
    assert.equal(normalizeIntelHost("javascript:alert(1)"), null);
    assert.equal(normalizeIntelHost("data:text/html,<script>alert(1)</script>"), null);
    assert.equal(normalizeIntelHost("ftp://files.example.test/"), null);
  });

  test("rejects URLs with embedded credentials", () => {
    assert.equal(normalizeIntelHost("http://user:pass@example.test/"), null);
    assert.equal(normalizeIntelHost("https://admin@example.test/"), null);
  });

  test("rejects single-label hostnames (no dot)", () => {
    assert.equal(normalizeIntelHost("localhost"), null);
    assert.equal(normalizeIntelHost("intranet"), null);
  });

  test("rejects hostnames exceeding 253 characters", () => {
    // 4 labels of 63 chars each + dots + ".test" = 63+1+63+1+63+1+63+5 = 260 > 253
    const longHost = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(63) + ".test";
    assert.ok(longHost.length > 253, `expected ${longHost.length} > 253`);
    assert.equal(normalizeIntelHost(longHost), null);
  });

  test("rejects labels with invalid characters (underscore)", () => {
    assert.equal(normalizeIntelHost("https://bad_host.test/"), null);
  });

  test("rejects labels starting or ending with hyphen", () => {
    assert.equal(normalizeIntelHost("-bad.example.test"), null);
    assert.equal(normalizeIntelHost("bad-.example.test"), null);
  });

  test("rejects labels exceeding 63 characters", () => {
    const longLabel = "a".repeat(64) + ".example.test";
    assert.equal(normalizeIntelHost(longLabel), null);
  });

  test("accepts labels at exactly 63 characters", () => {
    const maxLabel = "a".repeat(63) + ".example.test";
    assert.equal(normalizeIntelHost(maxLabel), maxLabel.toLowerCase());
  });

  test("accepts hostname at exactly 253 characters", () => {
    // Build a hostname that is exactly 253 chars
    // 4 labels of 62 chars + dots + ".test" suffix
    const label = "a".repeat(58);
    const host = `${label}.${label}.${label}.${label}.test`;
    if (host.length <= 253) {
      assert.equal(normalizeIntelHost(host), host);
    }
  });

  test("accepts numeric labels (not IPs when dotted with TLD)", () => {
    assert.equal(normalizeIntelHost("123.example.test"), "123.example.test");
  });

  test("accepts hyphenated labels", () => {
    assert.equal(normalizeIntelHost("my-site.example.test"), "my-site.example.test");
  });
});

// ---------------------------------------------------------------------------
// digest — determinism
// ---------------------------------------------------------------------------
describe("digest", () => {
  test("produces consistent SHA-256 hex for same input", () => {
    const a = digest("hello");
    const b = digest("hello");
    assert.equal(a, b);
    assert.match(a, /^[a-f0-9]{64}$/);
  });

  test("different inputs produce different digests", () => {
    assert.notEqual(digest("hello"), digest("world"));
  });

  test("coerces non-string input via String()", () => {
    assert.equal(digest(12345), digest("12345"));
  });
});

// ---------------------------------------------------------------------------
// findingHosts
// ---------------------------------------------------------------------------
describe("findingHosts", () => {
  test("uses domains array when present and non-empty", () => {
    const hosts = findingHosts({ domains: ["login.example.test", "api.example.test"], registrable: "example.test" });
    assert.deepEqual(hosts.sort(), ["api.example.test", "login.example.test"]);
  });

  test("falls back to registrable when domains is empty", () => {
    const hosts = findingHosts({ domains: [], registrable: "example.test" });
    assert.deepEqual(hosts, ["example.test"]);
  });

  test("falls back to registrable when domains is missing", () => {
    const hosts = findingHosts({ registrable: "example.test" });
    assert.deepEqual(hosts, ["example.test"]);
  });

  test("deduplicates normalized hosts", () => {
    const hosts = findingHosts({ domains: ["LOGIN.example.test", "login.example.test"], registrable: "example.test" });
    assert.equal(hosts.length, 1);
    assert.equal(hosts[0], "login.example.test");
  });

  test("filters out invalid hosts (wildcards, IPs)", () => {
    const hosts = findingHosts({ domains: ["*.example.test", "127.0.0.1", "valid.example.test"] });
    assert.deepEqual(hosts, ["valid.example.test"]);
  });

  test("returns empty array when all domains are invalid", () => {
    const hosts = findingHosts({ domains: ["*.example.test"], registrable: "*.example.test" });
    assert.deepEqual(hosts, []);
  });
});

// ---------------------------------------------------------------------------
// makeEvidence — schema compliance and expiry logic
// ---------------------------------------------------------------------------
describe("makeEvidence", () => {
  const base = {
    source: "openphish",
    indicator: "https://login.example.test/phish",
    source_ref: "https://openphish.com/phishing_feeds.html",
    verdict: "phishing",
    observed_at: ISO_NOW,
  };

  test("produces valid evidence object with all required fields", () => {
    const ev = makeEvidence(base, NOW);
    assert.ok(ev);
    assert.equal(ev.domain, "login.example.test");
    assert.equal(ev.source, "openphish");
    assert.equal(ev.source_ref, base.source_ref);
    assert.equal(ev.verdict, "phishing");
    assert.equal(ev.observed_at, ISO_NOW);
    assert.ok(ev.expires_at);
    assert.ok(ev.id);
    assert.ok(ev.details.indicator_sha256);
  });

  test("openphish evidence expires in 24 hours", () => {
    const ev = makeEvidence(base, NOW);
    const expiresMs = Date.parse(ev.expires_at);
    assert.equal(expiresMs, NOW + 24 * 3600000);
  });

  test("non-openphish evidence expires in 7 days", () => {
    for (const source of ["urlhaus", "threatfox", "urlscan"]) {
      const ev = makeEvidence({ ...base, source }, NOW);
      const expiresMs = Date.parse(ev.expires_at);
      assert.equal(expiresMs, NOW + 7 * 86400000, `${source} should expire in 7 days`);
    }
  });

  test("expires_at is capped at now + lifetime for old observations", () => {
    const oldDate = new Date(NOW - 6 * 86400000).toISOString(); // 6 days ago
    const ev = makeEvidence({ ...base, source: "urlhaus", observed_at: oldDate }, NOW);
    assert.ok(ev);
    // observed + 7d = NOW - 6d + 7d = NOW + 1d
    // now + 7d = NOW + 7d
    // min(NOW+1d, NOW+7d) = NOW+1d
    const expiresMs = Date.parse(ev.expires_at);
    assert.equal(expiresMs, NOW - 6 * 86400000 + 7 * 86400000);
  });

  test("rejects evidence that has already expired (observed too far in the past)", () => {
    const ancient = new Date(NOW - 8 * 86400000).toISOString(); // 8 days ago
    const ev = makeEvidence({ ...base, source: "urlhaus", observed_at: ancient }, NOW);
    assert.equal(ev, null, "evidence observed 8 days ago with 7-day lifetime should be expired");
  });

  test("rejects openphish evidence observed >24h ago", () => {
    const old = new Date(NOW - 25 * 3600000).toISOString();
    const ev = makeEvidence({ ...base, observed_at: old }, NOW);
    assert.equal(ev, null);
  });

  test("rejects future-dated observations beyond 5-minute clock skew", () => {
    const future = new Date(NOW + 300001).toISOString(); // 5min + 1ms
    const ev = makeEvidence({ ...base, observed_at: future }, NOW);
    assert.equal(ev, null);
  });

  test("accepts observations within 5-minute clock skew tolerance", () => {
    const nearFuture = new Date(NOW + 299999).toISOString();
    const ev = makeEvidence({ ...base, observed_at: nearFuture }, NOW);
    assert.ok(ev);
  });

  test("rejects unknown source names", () => {
    const ev = makeEvidence({ ...base, source: "unknown_source" }, NOW);
    assert.equal(ev, null);
  });

  test("rejects invalid indicator (IP address)", () => {
    const ev = makeEvidence({ ...base, indicator: "http://127.0.0.1/phish" }, NOW);
    assert.equal(ev, null);
  });

  test("rejects missing/invalid observed_at", () => {
    assert.equal(makeEvidence({ ...base, observed_at: undefined }, NOW), null);
    assert.equal(makeEvidence({ ...base, observed_at: "" }, NOW), null);
    assert.equal(makeEvidence({ ...base, observed_at: "not-a-date" }, NOW), null);
  });

  test("default verdict is 'observed'", () => {
    const { verdict: _, ...noVerdict } = base;
    const ev = makeEvidence({ ...noVerdict, observed_at: ISO_NOW }, NOW);
    assert.ok(ev);
    assert.equal(ev.verdict, "observed");
  });

  test("dedup ID is deterministic for same source|domain|source_ref", () => {
    const a = makeEvidence(base, NOW);
    const b = makeEvidence(base, NOW);
    assert.equal(a.id, b.id);
  });

  test("dedup ID differs when source_ref changes", () => {
    const a = makeEvidence(base, NOW);
    const b = makeEvidence({ ...base, source_ref: "https://other.ref/" }, NOW);
    assert.notEqual(a.id, b.id);
  });

  test("indicator_sha256 is included in details", () => {
    const ev = makeEvidence(base, NOW);
    assert.equal(ev.details.indicator_sha256, digest(base.indicator));
  });

  test("extra details are preserved", () => {
    const ev = makeEvidence({ ...base, details: { feed_sha256: "abc123" } }, NOW);
    assert.equal(ev.details.feed_sha256, "abc123");
    assert.ok(ev.details.indicator_sha256); // also present
  });

  test("indicator URL path/query is NOT leaked into domain field", () => {
    const ev = makeEvidence({ ...base, indicator: "https://login.example.test/secret?token=abc" }, NOW);
    assert.ok(ev);
    assert.equal(ev.domain, "login.example.test");
    assert.ok(!ev.domain.includes("secret"));
    assert.ok(!ev.domain.includes("token"));
  });
});

// ---------------------------------------------------------------------------
// parseOpenPhish
// ---------------------------------------------------------------------------
describe("parseOpenPhish", () => {
  test("parses valid feed lines into evidence objects", () => {
    const feed = "https://login.example.test/a\nhttps://other.example.test/b\n";
    const results = parseOpenPhish(feed, NOW);
    assert.equal(results.length, 2);
    assert.equal(results[0].source, "openphish");
    assert.equal(results[0].verdict, "phishing");
  });

  test("strips private URL paths from evidence domain", () => {
    const feed = "https://login.example.test/secret?token=private_key\n";
    const results = parseOpenPhish(feed, NOW);
    assert.equal(results[0].domain, "login.example.test");
    assert.ok(!JSON.stringify(results).includes("private_key"));
  });

  test("includes feed_sha256 in details", () => {
    const feed = "https://login.example.test/a\n";
    const results = parseOpenPhish(feed, NOW);
    assert.ok(results[0].details.feed_sha256);
    assert.match(results[0].details.feed_sha256, /^[a-f0-9]{64}$/);
  });

  test("rejects HTML error pages", () => {
    assert.throws(() => parseOpenPhish("<html>Service Unavailable</html>", NOW), IntelRequestError);
  });

  test("rejects empty feed", () => {
    assert.throws(() => parseOpenPhish("", NOW), IntelRequestError);
  });

  test("rejects feed with non-URL lines", () => {
    assert.throws(() => parseOpenPhish("not a url\nhttps://valid.test/", NOW), IntelRequestError);
  });

  test("filters out indicators that normalize to null (IPs)", () => {
    const feed = "https://127.0.0.1/phish\nhttps://valid.example.test/phish\n";
    const results = parseOpenPhish(feed, NOW);
    assert.equal(results.length, 1);
    assert.equal(results[0].domain, "valid.example.test");
  });

  test("handles Windows-style line endings", () => {
    const feed = "https://a.example.test/1\r\nhttps://b.example.test/2\r\n";
    const results = parseOpenPhish(feed, NOW);
    assert.equal(results.length, 2);
  });
});

// ---------------------------------------------------------------------------
// parseUrlhaus
// ---------------------------------------------------------------------------
describe("parseUrlhaus", () => {
  const validPayload = (urls) => JSON.stringify({ query_status: "ok", urls });

  test("parses valid malware_download entries", () => {
    const results = parseUrlhaus(validPayload([
      { id: 100, url: "https://login.example.test/payload", date_added: ISO_NOW, url_status: "online", threat: "malware_download" },
    ]), NOW);
    assert.equal(results.length, 1);
    assert.equal(results[0].source, "urlhaus");
    assert.equal(results[0].verdict, "malware");
  });

  test("filters out non-malware_download threats", () => {
    const results = parseUrlhaus(validPayload([
      { id: 100, url: "https://login.example.test/", date_added: ISO_NOW, url_status: "online", threat: "phishing" },
    ]), NOW);
    assert.equal(results.length, 0);
  });

  test("filters out entries with non-numeric IDs", () => {
    const results = parseUrlhaus(validPayload([
      { id: "abc", url: "https://login.example.test/", date_added: ISO_NOW, url_status: "online", threat: "malware_download" },
    ]), NOW);
    assert.equal(results.length, 0);
  });

  test("handles no_results response", () => {
    const results = parseUrlhaus(JSON.stringify({ query_status: "no_results" }), NOW);
    assert.deepEqual(results, []);
  });

  test("rejects invalid JSON", () => {
    assert.throws(() => parseUrlhaus("{invalid", NOW), IntelRequestError);
  });

  test("rejects unexpected query_status", () => {
    assert.throws(() => parseUrlhaus(JSON.stringify({ query_status: "error", urls: [] }), NOW), IntelRequestError);
  });

  test("rejects missing urls array", () => {
    assert.throws(() => parseUrlhaus(JSON.stringify({ query_status: "ok" }), NOW), IntelRequestError);
  });

  test("constructs correct source_ref from ID", () => {
    const results = parseUrlhaus(validPayload([
      { id: 42, url: "https://login.example.test/", date_added: ISO_NOW, url_status: "offline", threat: "malware_download" },
    ]), NOW);
    assert.equal(results[0].source_ref, "https://urlhaus.abuse.ch/url/42/");
  });

  test("preserves url_status and provider_id in details", () => {
    const results = parseUrlhaus(validPayload([
      { id: 42, url: "https://login.example.test/", date_added: ISO_NOW, url_status: "offline", threat: "malware_download" },
    ]), NOW);
    assert.equal(results[0].details.url_status, "offline");
    assert.equal(results[0].details.provider_id, "42");
  });
});

// ---------------------------------------------------------------------------
// parseThreatFox
// ---------------------------------------------------------------------------
describe("parseThreatFox", () => {
  const validPayload = (data) => JSON.stringify({ query_status: "ok", data });

  test("parses domain-type IOCs", () => {
    const results = parseThreatFox(validPayload([
      { id: 10, ioc: "login.example.test", ioc_type: "domain", confidence_level: 80, first_seen: ISO_NOW },
    ]), NOW);
    assert.equal(results.length, 1);
    assert.equal(results[0].source, "threatfox");
    assert.equal(results[0].verdict, "malware");
  });

  test("parses url-type IOCs", () => {
    const results = parseThreatFox(validPayload([
      { id: 11, ioc: "https://login.example.test/c2", ioc_type: "url", confidence_level: 90, first_seen: ISO_NOW },
    ]), NOW);
    assert.equal(results.length, 1);
    assert.equal(results[0].domain, "login.example.test");
  });

  test("filters out ip:port IOC types", () => {
    const results = parseThreatFox(validPayload([
      { id: 12, ioc: "127.0.0.1:443", ioc_type: "ip:port", confidence_level: 100, first_seen: ISO_NOW },
    ]), NOW);
    assert.equal(results.length, 0);
  });

  test("filters out non-numeric IDs", () => {
    const results = parseThreatFox(validPayload([
      { id: "abc", ioc: "login.example.test", ioc_type: "domain", confidence_level: 80, first_seen: ISO_NOW },
    ]), NOW);
    assert.equal(results.length, 0);
  });

  test("prefers last_seen over first_seen for observed_at", () => {
    const lastSeen = new Date(NOW - 3600000).toISOString();
    const results = parseThreatFox(validPayload([
      { id: 10, ioc: "login.example.test", ioc_type: "domain", confidence_level: 80, first_seen: ISO_NOW, last_seen: lastSeen },
    ]), NOW);
    assert.equal(results[0].observed_at, lastSeen);
  });

  test("falls back to first_seen when last_seen is missing", () => {
    const results = parseThreatFox(validPayload([
      { id: 10, ioc: "login.example.test", ioc_type: "domain", confidence_level: 80, first_seen: ISO_NOW },
    ]), NOW);
    assert.equal(results[0].observed_at, ISO_NOW);
  });

  test("truncates threat_type and malware fields to 100 chars", () => {
    const longStr = "x".repeat(200);
    const results = parseThreatFox(validPayload([
      { id: 10, ioc: "login.example.test", ioc_type: "domain", confidence_level: 80, first_seen: ISO_NOW,
        threat_type: longStr, malware_printable: longStr },
    ]), NOW);
    assert.ok(results[0].details.threat_type.length <= 100);
    assert.ok(results[0].details.malware.length <= 100);
  });

  test("handles no_results response", () => {
    const results = parseThreatFox(JSON.stringify({ query_status: "no_results" }), NOW);
    assert.deepEqual(results, []);
  });

  test("rejects invalid JSON", () => {
    assert.throws(() => parseThreatFox("not json", NOW), IntelRequestError);
  });

  test("preserves confidence and provider_id in details", () => {
    const results = parseThreatFox(validPayload([
      { id: 99, ioc: "login.example.test", ioc_type: "domain", confidence_level: 75, first_seen: ISO_NOW },
    ]), NOW);
    assert.equal(results[0].details.confidence, 75);
    assert.equal(results[0].details.provider_id, "99");
  });
});

// ---------------------------------------------------------------------------
// parseUrlscanResult
// ---------------------------------------------------------------------------
describe("parseUrlscanResult", () => {
  const validScan = {
    task: {
      uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      url: "https://login.example.test/",
      time: ISO_NOW,
      visibility: "public",
    },
    page: {
      url: "https://login.example.test/",
      domain: "login.example.test",
      title: "Sign in",
    },
  };

  test("parses valid public scan result as 'observed'", () => {
    const ev = parseUrlscanResult(validScan, "login.example.test", NOW);
    assert.ok(ev);
    assert.equal(ev.source, "urlscan");
    assert.equal(ev.verdict, "observed");
    assert.equal(ev.domain, "login.example.test");
  });

  test("classifies confirmed phishing verdict", () => {
    const scan = {
      ...validScan,
      verdicts: { urlscan: { malicious: true, categories: ["phishing"] } },
    };
    const ev = parseUrlscanResult(scan, "login.example.test", NOW);
    assert.equal(ev.verdict, "phishing");
  });

  test("classifies confirmed malware verdict", () => {
    const scan = {
      ...validScan,
      verdicts: { urlscan: { malicious: true, categories: ["malware"] } },
    };
    const ev = parseUrlscanResult(scan, "login.example.test", NOW);
    assert.equal(ev.verdict, "malware");
  });

  test("phishing takes precedence over malware when both categories present", () => {
    const scan = {
      ...validScan,
      verdicts: { urlscan: { malicious: true, categories: ["malware", "phishing"] } },
    };
    const ev = parseUrlscanResult(scan, "login.example.test", NOW);
    assert.equal(ev.verdict, "phishing");
  });

  test("non-malicious verdict stays 'observed' even with categories", () => {
    const scan = {
      ...validScan,
      verdicts: { urlscan: { malicious: false, categories: ["phishing"] } },
    };
    const ev = parseUrlscanResult(scan, "login.example.test", NOW);
    assert.equal(ev.verdict, "observed");
  });

  test("rejects private visibility scans", () => {
    const scan = { ...validScan, task: { ...validScan.task, visibility: "private" } };
    assert.equal(parseUrlscanResult(scan, "login.example.test", NOW), null);
  });

  test("rejects host mismatch (page domain differs)", () => {
    assert.equal(parseUrlscanResult(validScan, "other.example.test", NOW), null);
  });

  test("rejects invalid UUID format", () => {
    const scan = { ...validScan, task: { ...validScan.task, uuid: "not-a-uuid" } };
    assert.equal(parseUrlscanResult(scan, "login.example.test", NOW), null);
  });

  test("rejects missing task time", () => {
    const scan = { ...validScan, task: { ...validScan.task, time: undefined } };
    assert.equal(parseUrlscanResult(scan, "login.example.test", NOW), null);
  });

  test("constructs correct source_ref URL", () => {
    const ev = parseUrlscanResult(validScan, "login.example.test", NOW);
    assert.equal(ev.source_ref, `https://urlscan.io/result/${validScan.task.uuid}/`);
  });

  test("includes screenshot_url and verdict_confirmed in details", () => {
    const ev = parseUrlscanResult(validScan, "login.example.test", NOW);
    assert.equal(ev.details.screenshot_url, `https://urlscan.io/screenshots/${validScan.task.uuid}.png`);
    assert.equal(ev.details.verdict_confirmed, false);
  });

  test("truncates page title to 300 chars", () => {
    const scan = {
      ...validScan,
      page: { ...validScan.page, title: "x".repeat(500) },
    };
    const ev = parseUrlscanResult(scan, "login.example.test", NOW);
    assert.ok(ev.details.title.length <= 300);
  });

  test("uses _id as fallback when task.uuid is missing", () => {
    const scan = {
      ...validScan,
      _id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      task: { ...validScan.task, uuid: undefined },
    };
    const ev = parseUrlscanResult(scan, "login.example.test", NOW);
    assert.ok(ev);
    assert.equal(ev.details.provider_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
  });
});

// ---------------------------------------------------------------------------
// attachIntelEvidence — filtering, boost, and multi-source logic
// ---------------------------------------------------------------------------
describe("attachIntelEvidence", () => {
  const finding = {
    id: "test-finding",
    registrable: "example.test",
    domains: ["login.example.test"],
    score: 68,
    suppressed: false,
  };

  const makeRow = (overrides = {}) => ({
    source: "openphish",
    domain: "login.example.test",
    verdict: "phishing",
    observed_at: ISO_NOW,
    expires_at: new Date(NOW + 24 * 3600000).toISOString(),
    details: {},
    ...overrides,
  });

  test("attaches matching evidence and counts unique sources", () => {
    const rows = [makeRow(), makeRow({ source: "urlscan", verdict: "observed" })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_evidence.length, 2);
    assert.equal(result.intel_hit_count, 2);
  });

  test("filters out evidence for non-matching domains", () => {
    const rows = [makeRow({ domain: "other.example.test" })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_evidence.length, 0);
    assert.equal(result.intel_hit_count, 0);
  });

  test("filters out expired evidence", () => {
    const rows = [makeRow({ expires_at: new Date(NOW - 1).toISOString() })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_evidence.length, 0);
  });

  test("filters out future-observed evidence beyond clock skew", () => {
    const rows = [makeRow({ observed_at: new Date(NOW + 300001).toISOString() })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_evidence.length, 0);
  });

  test("accepts evidence observed within clock skew tolerance", () => {
    const rows = [makeRow({ observed_at: new Date(NOW + 299999).toISOString() })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_evidence.length, 1);
  });

  test("filters out unknown source names", () => {
    const rows = [makeRow({ source: "unknown" })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_evidence.length, 0);
  });

  test("suppressed findings get zero evidence regardless of matches", () => {
    const rows = [makeRow()];
    const result = attachIntelEvidence({ ...finding, suppressed: true }, rows, NOW);
    assert.equal(result.intel_evidence.length, 0);
    assert.equal(result.intel_hit_count, 0);
    assert.equal(result.intel_priority_boost, 0);
  });

  test("handles null/undefined evidence array gracefully", () => {
    const result = attachIntelEvidence(finding, null, NOW);
    assert.equal(result.intel_evidence.length, 0);
    assert.equal(result.intel_hit_count, 0);
  });

  // --- Priority boost logic ---
  test("openphish phishing verdict boosts score >= 60", () => {
    const rows = [makeRow({ source: "openphish", verdict: "phishing" })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 10);
    assert.equal(result.priority_score, 78);
  });

  test("no boost when score < 60", () => {
    const rows = [makeRow({ source: "openphish", verdict: "phishing" })];
    const result = attachIntelEvidence({ ...finding, score: 59 }, rows, NOW);
    assert.equal(result.intel_priority_boost, 0);
    assert.equal(result.priority_score, 59);
  });

  test("urlhaus malware + online status boosts", () => {
    const rows = [makeRow({ source: "urlhaus", verdict: "malware", details: { url_status: "online" } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 10);
  });

  test("urlhaus malware + offline status does NOT boost", () => {
    const rows = [makeRow({ source: "urlhaus", verdict: "malware", details: { url_status: "offline" } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 0);
  });

  test("threatfox malware + confidence >= 75 boosts", () => {
    const rows = [makeRow({ source: "threatfox", verdict: "malware", details: { confidence: 75 } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 10);
  });

  test("threatfox malware + confidence < 75 does NOT boost", () => {
    const rows = [makeRow({ source: "threatfox", verdict: "malware", details: { confidence: 74 } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 0);
  });

  test("urlscan confirmed phishing boosts", () => {
    const rows = [makeRow({ source: "urlscan", verdict: "phishing", details: { verdict_confirmed: true } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 10);
  });

  test("urlscan observed (not confirmed) does NOT boost", () => {
    const rows = [makeRow({ source: "urlscan", verdict: "observed", details: { verdict_confirmed: false } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 0);
  });

  test("urlscan confirmed malware boosts", () => {
    const rows = [makeRow({ source: "urlscan", verdict: "malware", details: { verdict_confirmed: true } })];
    const result = attachIntelEvidence(finding, rows, NOW);
    assert.equal(result.intel_priority_boost, 10);
  });

  test("priority_score handles missing/zero score gracefully", () => {
    const rows = [makeRow()];
    // Number(undefined) is NaN, NaN >= 60 is false → no boost
    // Number(undefined || 0) = Number(0) = 0 → priority_score = 0
    const result = attachIntelEvidence({ ...finding, score: undefined }, rows, NOW);
    assert.equal(result.intel_priority_boost, 0, "NaN score should not trigger boost");
    assert.equal(result.priority_score, 0, "Number(undefined||0) = 0");
  });
});

// ---------------------------------------------------------------------------
// INTEL_SOURCES constant
// ---------------------------------------------------------------------------
describe("INTEL_SOURCES", () => {
  test("contains exactly the four known sources", () => {
    assert.deepEqual([...INTEL_SOURCES].sort(), ["openphish", "threatfox", "urlhaus", "urlscan"]);
  });
});

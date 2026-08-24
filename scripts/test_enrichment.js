import assert from "node:assert/strict";
import { resolveDns, probeHttp, queryRdap, enrichDomain } from "../lib/domain/enrichment.js";

// 1. Mock fetch implementation for HTTP probe
const mockFetch = async (url) => {
  if (url.startsWith("https://mock-live-phish.xyz")) {
    return {
      status: 200,
      url: "https://mock-live-phish.xyz/login",
      headers: {
        get: (h) => (h.toLowerCase() === "server" ? "nginx/1.18" : h.toLowerCase() === "content-type" ? "text/html" : null)
      },
      text: async () => "<!DOCTYPE html><html><head><title>DBS Security Verification Portal</title></head><body>Login</body></html>"
    };
  }
  if (url.startsWith("https://rdap.org/domain/mock-live-phish.xyz")) {
    return {
      ok: true,
      json: async () => ({
        events: [
          { eventAction: "registration", eventDate: "2026-08-20T08:00:00Z" },
          { eventAction: "expiration", eventDate: "2027-08-20T08:00:00Z" }
        ],
        status: ["active", "clientTransferProhibited"],
        entities: [
          {
            roles: ["registrar"],
            vcardArray: ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]]
          }
        ]
      })
    };
  }
  throw new Error("Connection refused (mock)");
};

// 2. Test HTTP probe with mock
const httpResult = await probeHttp("mock-live-phish.xyz", 1000, mockFetch);
assert.equal(httpResult.live, true, "HTTP probe reports live");
assert.equal(httpResult.status, 200, "HTTP probe reports status 200");
assert.equal(httpResult.title, "DBS Security Verification Portal", "HTTP probe extracts HTML title");
assert.equal(httpResult.server, "nginx/1.18", "HTTP probe extracts server header");

// 3. Test RDAP query with mock
const rdapResult = await queryRdap("mock-live-phish.xyz", 1000, mockFetch);
assert.equal(rdapResult.created_at, "2026-08-20T08:00:00Z", "RDAP extracts registration date");
assert.equal(rdapResult.registrar, "NameCheap, Inc.", "RDAP extracts registrar");

// 4. Test enrichDomain combined pipeline
const enrichment = await enrichDomain("mock-live-phish.xyz", { timeoutMs: 1000, fetch: mockFetch });
assert.ok(enrichment.enriched_at, "Enrichment includes timestamp");
assert.equal(enrichment.live, true, "Domain is marked live");
assert.equal(enrichment.http.title, "DBS Security Verification Portal", "Enrichment includes HTTP title");
assert.equal(enrichment.rdap.registrar, "NameCheap, Inc.", "Enrichment includes RDAP registrar");

// 5. Test error resilience with non-responsive domain
const deadFetch = async () => {
  throw new Error("DNS resolution failed");
};
const deadResult = await enrichDomain("nonexistent-test-domain-12345.xyz", { timeoutMs: 200, fetch: deadFetch });
assert.equal(deadResult.live, false, "Dead domain reports live: false without throwing error");

console.log("Active capture & enrichment tests passed.");

/**
 * Workbench timeline tests — node:test
 * Tests lib/ui/evidence-timeline.js pure logic.
 *
 * Run: node --test scripts/test_workbench_timeline.mjs
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildTimeline, renderTimeline } from "../lib/ui/evidence-timeline.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-10"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Test 1 — chronology-and-provenance
// ---------------------------------------------------------------------------
test("chronology-and-provenance: events are sorted chronologically with correct labels", async () => {
  await ensureEvidence();

  const finding = {
    observed_at: "2026-09-20T10:00:00.000Z",
    created_at:  "2026-09-20T10:05:00.000Z",
    certificate_not_before: "2026-09-19T00:00:00.000Z",
    intel_evidence: [
      {
        source: "urlscan",
        verdict: "phishing",
        observed_at: "2026-09-20T12:00:00.000Z",
        expires_at: "2026-10-20T12:00:00.000Z",
        source_ref: "https://urlscan.io/result/abc/",
      },
    ],
  };

  const events = buildTimeline(finding);

  // Should have: cert_issued, ct_observed, record_created, provider_observed
  assert.equal(events.length, 4, `Expected 4 events, got ${events.length}`);

  // First event should be cert_issued (earliest timestamp)
  assert.equal(events[0].type, "cert_issued");
  assert.equal(events[0].timestamp, "2026-09-19T00:00:00.000Z");

  // Second: ct_observed
  assert.equal(events[1].type, "ct_observed");

  // Third: record_created (different from observed_at)
  assert.equal(events[2].type, "record_created");

  // Fourth: provider_observed
  assert.equal(events[3].type, "provider_observed");
  assert.equal(events[3].source, "urlscan");
  assert.ok(events[3].label.includes("phishing"));

  // Render and check HTML
  const html = renderTimeline(events, true);
  assert.ok(html.includes("timeline-list"), "Should render a timeline list");
  assert.ok(html.includes("not complete historical coverage"), "Should include coverage disclaimer");
});

// ---------------------------------------------------------------------------
// Test 2 — missing-is-unknown
// ---------------------------------------------------------------------------
test("missing-is-unknown: missing timestamps show Unknown, not now()", async () => {
  await ensureEvidence();

  const finding = {
    observed_at: null,  // missing
    created_at: null,
    intel_evidence: [],
  };

  const events = buildTimeline(finding);

  // ct_observed should have null timestamp
  const ctEvent = events.find((e) => e.type === "ct_observed");
  assert.ok(ctEvent, "Should have a ct_observed event");
  assert.equal(ctEvent.timestamp, null, "Missing timestamp should be null, not now()");

  // Render: null timestamp should show "Unknown"
  const html = renderTimeline(events, true);
  assert.ok(html.includes("Unknown"), "Should display Unknown for missing timestamp");

  // Should NOT contain a year-like string from now()
  const nowYear = new Date().getFullYear().toString();
  // The disclaimer text doesn't contain a year, so this checks the timestamp area
  const timeElements = html.match(/<time[^>]*>([^<]+)<\/time>/g) ?? [];
  assert.equal(timeElements.length, 0, "No <time> elements for missing timestamps");
});

// ---------------------------------------------------------------------------
// Test 3 — expiry-not-new-malicious-event
// ---------------------------------------------------------------------------
test("expiry-not-new-malicious-event: cert_not_before is cert validity start, not malicious event", async () => {
  await ensureEvidence();

  const finding = {
    observed_at: "2026-09-20T10:00:00.000Z",
    certificate_not_before: "2026-09-01T00:00:00.000Z",
    intel_evidence: [],
  };

  const events = buildTimeline(finding);
  const certEvent = events.find((e) => e.type === "cert_issued");

  assert.ok(certEvent, "Should have cert_issued event");
  assert.ok(
    certEvent.label.includes("validity start"),
    `cert_issued label should mention 'validity start', got: "${certEvent.label}"`
  );
  assert.ok(
    !certEvent.label.toLowerCase().includes("malicious"),
    "cert_issued label must not imply malicious activity"
  );
  assert.ok(
    !certEvent.label.toLowerCase().includes("registration"),
    "cert_issued label must not imply domain registration"
  );
});

// ---------------------------------------------------------------------------
// Test 4 — public-has-no-review-events
// ---------------------------------------------------------------------------
test("public-has-no-review-events: review events only appear when explicitly passed", async () => {
  await ensureEvidence();

  const finding = {
    observed_at: "2026-09-20T10:00:00.000Z",
    intel_evidence: [],
  };

  // Without review events
  const publicEvents = buildTimeline(finding);
  assert.ok(
    !publicEvents.some((e) => e.type === "review_event"),
    "Public timeline should have no review events"
  );

  // With review events (analyst-only)
  const reviewEvents = [
    {
      created_at: "2026-09-21T08:00:00.000Z",
      new_status: "investigating",
      new_disp: "unassessed",
    },
  ];
  const privateEvents = buildTimeline(finding, reviewEvents);
  assert.ok(
    privateEvents.some((e) => e.type === "review_event"),
    "Private timeline should include review events when passed"
  );

  // Render public: no review event content
  const publicHtml = renderTimeline(publicEvents, true);
  assert.ok(!publicHtml.includes("timeline-review_event"), "Public HTML must not contain review events");

  // Render private: includes review event
  const privateHtml = renderTimeline(privateEvents, false);
  assert.ok(privateHtml.includes("timeline-review_event"), "Private HTML should contain review events");
  // Private render should NOT include the public disclaimer
  assert.ok(!privateHtml.includes("not complete historical coverage"), "Private render should not have public disclaimer");
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { assessSoak } from "./verify_soak.mjs";

test("soak requires a measured day and independent committed scan history", () => {
  const now = Date.parse("2026-09-09T10:00:00Z");
  const day = 86400000;
  const activeSince = now - day;
  const status = { ok: true, at: now, config: { enabled: true, heartbeat: true, proactiveAlerts: true },
    soak: { active: true, activeSince, observedActiveMs: day, unobservedGaps: 0, maxTickGapMs: 300000,
      workflows: Object.fromEntries(["ingest", "intel", "notifications"].map(name => [name, {
        startsObserved: 96, successesObserved: 96, maxActualStartGapMs: 900000, maxActualSuccessGapMs: 900000,
        lastActualStartAt: now, lastActualSuccessAt: now
      }])) } };
  const rows = Array.from({ length: 96 }, (_, i) => ({ source: "direct_ct", ok: true,
    details: { run_started_at: new Date(activeSince + i * 900000).toISOString(), run_id: String(i) } }));
  assert.equal(assessSoak(status, rows, now).passed, true);
  assert.equal(assessSoak(status, [], now).passed, false);
  for (const patch of [{ active: false }, { observedActiveMs: 300000 }, { unobservedGaps: 1 }, { maxTickGapMs: 3600000 }]) {
    assert.equal(assessSoak({ ...status, soak: { ...status.soak, ...patch } }, rows, now).passed, false);
  }
  assert.equal(assessSoak({ ...status, ok: false }, rows, now).passed, false);
  assert.equal(assessSoak(status, rows.map(row => ({ ...row, ok: false })), now).passed, false);
  assert.equal(assessSoak({}, [], now).passed, false);
});

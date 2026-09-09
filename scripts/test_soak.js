import assert from "node:assert/strict";
import { test } from "node:test";
import { assessSoak } from "./verify_soak.mjs";
import { harness, BASE_TIME } from "../scheduler/tests/helpers.mjs";

const MINUTE = 60000;
const DAY = 24 * 60 * MINUTE;

function healthySoak(mode = "dashboard") {
  const now = Date.parse("2026-09-09T10:00:00Z");
  const activeSince = now - DAY;
  const status = { ok: true, at: now, config: { enabled: true, heartbeat: true,
    proactiveAlerts: mode === "webhook", monitoringMode: mode, alertChannel: mode === "webhook" ? "webhook" : "none" },
    soak: { active: true, monitoringMode: mode, activeSince, observedActiveMs: DAY, unobservedGaps: 0, maxTickGapMs: 300000,
      workflows: Object.fromEntries([["ingest", 15], ["intel", 60]].map(([name, interval]) => [name, {
        startsObserved: 1440 / interval, successesObserved: 1440 / interval,
        maxActualStartGapMs: interval * MINUTE, maxActualSuccessGapMs: interval * MINUTE,
        firstActualStartAt: activeSince, firstActualSuccessAt: activeSince,
        lastActualStartAt: now, lastActualSuccessAt: now
      }])) } };
  const rows = Array.from({ length: 96 }, (_, i) => ({ source: "direct_ct", ok: true,
    details: { run_started_at: new Date(activeSince + i * 900000).toISOString(), run_id: String(i) } }));
  return { now, activeSince, status, rows };
}

test("soak requires a measured day and independent committed scan history", () => {
  const { now, status, rows } = healthySoak();
  assert.equal(assessSoak(status, rows, now).passed, true);
  assert.equal(assessSoak(status, [], now).passed, false);
  for (const patch of [{ active: false }, { observedActiveMs: 300000 }, { unobservedGaps: 1 }, { maxTickGapMs: 3600000 }]) {
    assert.equal(assessSoak({ ...status, soak: { ...status.soak, ...patch } }, rows, now).passed, false);
  }
  assert.equal(assessSoak({ ...status, ok: false }, rows, now).passed, false);
  assert.equal(assessSoak({ ...status, config: { ...status.config, monitoringMode: undefined } }, rows, now).passed, false);
  assert.equal(assessSoak({ ...status, soak: { ...status.soak, monitoringMode: "webhook" } }, rows, now).passed, false);
  assert.equal(assessSoak({ ...status, soak: { ...status.soak,
    workflows: { ...status.soak.workflows, notifications: {} } } }, rows, now).passed, false);
  assert.equal(assessSoak({ ...status, incidents: { ingest: { active: true, notice: { state: "dashboard_only" } } } }, rows, now).passed, false);
  const historicalNotice = { ingest: { active: false, notice: { state: "failed" } } };
  assert.equal(assessSoak({ ...status, incidents: historicalNotice }, rows, now).passed, true);
  const webhook = { ...status, config: { ...status.config, monitoringMode: "webhook", alertChannel: "webhook", proactiveAlerts: true },
    soak: { ...status.soak, monitoringMode: "webhook" } };
  assert.equal(assessSoak(webhook, rows, now).passed, true);
  assert.equal(assessSoak({ ...webhook, incidents: historicalNotice }, rows, now).passed, false);
  assert.equal(assessSoak(status, rows.map(row => ({ ...row, ok: false })), now).passed, false);
  assert.equal(assessSoak({}, [], now).passed, false);
});

for (const mode of ["dashboard", "webhook"]) {
  for (const [name, allowedMinutes] of [["ingest", 30], ["intel", 90]]) {
    for (const kind of ["Start", "Success"]) {
      const field = `firstActual${kind}At`;
      const label = `${mode} ${name} first ${kind.toLowerCase()}`;
      test(`${label} accepts valid timestamps through the ${allowedMinutes}-minute boundary`, () => {
        const { now, activeSince, status, rows } = healthySoak(mode);
        for (const gap of [0, 1, allowedMinutes * MINUTE - 1, allowedMinutes * MINUTE]) {
          status.soak.workflows[name][field] = activeSince + gap;
          const result = assessSoak(status, rows, now);
          assert.equal(result.passed, true, `Initial gap ${gap}ms`);
          const details = result.checks.find(check => check.name === `${name}_observed_cadence`).details;
          assert.equal(details[`initial_${kind.toLowerCase()}_gap_ms`], gap);
          assert.equal(details.allowed_initial_gap_ms, allowedMinutes * MINUTE);
        }
      });

      test(`${label} rejects missing or malformed timestamps`, () => {
        const { now, activeSince, status, rows } = healthySoak(mode);
        for (const value of [undefined, null, NaN, Infinity, -Infinity, "invalid", String(activeSince),
          new Date(activeSince).toISOString(), false, {}]) {
          if (value === undefined) delete status.soak.workflows[name][field];
          else status.soak.workflows[name][field] = value;
          const result = assessSoak(status, rows, now);
          assert.equal(result.passed, false, `First timestamp ${String(value)}`);
          assert.deepEqual(result.checks.filter(check => !check.passed).map(check => check.name), [`${name}_observed_cadence`]);
          assert.equal(result.checks.find(check => check.name === `${name}_observed_cadence`)
            .details[`initial_${kind.toLowerCase()}_gap_ms`], null);
        }
      });

      test(`${label} rejects timestamps before the window, after the limit or in the future`, () => {
        const { now, activeSince, status, rows } = healthySoak(mode);
        for (const value of [activeSince - 1, activeSince + allowedMinutes * MINUTE + 1, now + 1]) {
          status.soak.workflows[name][field] = value;
          const result = assessSoak(status, rows, now);
          assert.equal(result.passed, false, `First timestamp ${value}`);
          assert.deepEqual(result.checks.filter(check => !check.passed).map(check => check.name), [`${name}_observed_cadence`]);
        }
      });
    }
  }
}

for (const intelDelay of [0, 120]) {
  test(`actual scheduler dashboard status ${intelDelay ? "rejects a two-hour initial intel gap" : "passes a healthy simulated day"}`, async () => {
    const h = harness({ env: {
      SUPABASE_URL: "https://project.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_local_fixture"
    } });
    const rows = [];
    for (let minute = 0; minute <= 1440; minute += 5) {
      h.time = BASE_TIME + minute * MINUTE;
      h.healthy(0);
      const ctAt = new Date(BASE_TIME + Math.floor(minute / 15) * 15 * MINUTE).toISOString();
      const intelAt = new Date(BASE_TIME + Math.floor(minute / 60) * 60 * MINUTE).toISOString();
      h.heartbeatRows = [{ key: "ct_poll_status", checked_at: ctAt, last_started_at: ctAt,
        last_success_at: ctAt, ok: "true", health: "healthy" }];
      if (minute >= intelDelay) h.heartbeatRows.push({ key: "intel_poll_status", checked_at: intelAt,
        last_started_at: intelAt, last_success_at: intelAt, ok: "true", health: "healthy" });
      if (minute % 15 === 0) rows.push({ source: "direct_ct", ok: true,
        details: { run_started_at: ctAt, run_id: String(minute) } });
      await h.tick();
    }
    const status = await h.status();
    assert.equal(status.ok, true);
    assert.equal(status.soak.observedActiveMs, DAY);
    assert.equal(status.soak.workflows.intel.startsObserved, intelDelay ? 23 : 25);
    assert.equal(status.soak.workflows.intel.successesObserved, intelDelay ? 23 : 25);
    const result = assessSoak(status, rows, h.time);
    assert.equal(result.passed, intelDelay === 0);
    assert.deepEqual(result.checks.filter(check => !check.passed).map(check => check.name),
      intelDelay ? ["intel_observed_cadence"] : []);
    const details = result.checks.find(check => check.name === "intel_observed_cadence").details;
    assert.equal(details.initial_start_gap_ms, intelDelay * MINUTE);
    assert.equal(details.initial_success_gap_ms, intelDelay * MINUTE);
    assert.equal(h.dispatches("notifications.yml").length, 0);
    assert.equal(h.alerts().length, 0);
  });
}

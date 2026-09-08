import { pathToFileURL } from "node:url";

const MINUTE = 60000;
const DAY = 24 * 60 * MINUTE;

export function assessSoak(status, sourceRuns, now = Date.now()) {
  const checks = [];
  const check = (name, passed, details) => checks.push({ name, passed: Boolean(passed), details });
  const soak = status?.soak;
  check("scheduler_active_and_healthy", status?.ok && soak?.active && status.config?.enabled
    && status.config?.heartbeat && status.config?.proactiveAlerts);
  check("observed_for_24_hours", soak?.observedActiveMs >= DAY && now - soak?.activeSince >= DAY);
  check("no_unobserved_scheduler_gaps", soak?.unobservedGaps === 0 && soak?.maxTickGapMs <= 10 * MINUTE);
  check("fresh_scheduler_observation", Number.isFinite(status?.at) && Math.abs(now - status.at) < 10 * MINUTE);
  for (const [name, interval, maxGap] of [["ingest", 15, 30], ["intel", 60, 90], ["notifications", 15, 30]]) {
    const metrics = soak?.workflows?.[name] || {};
    const expected = Math.floor(DAY / (interval * MINUTE)) - 1;
    check(`${name}_observed_cadence`, metrics.startsObserved >= expected && metrics.successesObserved >= expected
      && metrics.maxActualStartGapMs <= maxGap * MINUTE && metrics.maxActualSuccessGapMs <= maxGap * MINUTE
      && now - metrics.lastActualStartAt <= maxGap * MINUTE && now - metrics.lastActualSuccessAt <= maxGap * MINUTE,
    { starts: metrics.startsObserved, successes: metrics.successesObserved, minimum: expected,
      max_start_gap_ms: metrics.maxActualStartGapMs, max_success_gap_ms: metrics.maxActualSuccessGapMs });
  }
  // Independently compare committed per-run database evidence, not only Worker counters.
  const starts = new Map();
  for (const row of sourceRuns || []) {
    if (!["direct_ct", "static_ct"].includes(row.source)) continue;
    const started = Date.parse(row.details?.run_started_at);
    if (!Number.isFinite(started) || started < soak?.activeSince || started > now) continue;
    const key = `${row.details.run_id || "local"}:${row.details.run_started_at}`;
    const previous = starts.get(key);
    const progress = row.ok || row.scanned_entries > 0 || row.details?.successful_log_count > 0;
    starts.set(key, { started, successful: Boolean(previous?.successful || progress) });
  }
  const runs = [...starts.values()].sort((a, b) => a.started - b.started);
  const maxGap = Math.max(0, ...runs.slice(1).map((run, index) => run.started - runs[index].started));
  check("database_confirms_actual_ct_runs", runs.length >= 95 && runs.filter(run => run.successful).length >= 95
    && maxGap <= 30 * MINUTE && runs[0]?.started - soak?.activeSince <= 30 * MINUTE
    && now - runs.at(-1)?.started <= 30 * MINUTE,
  { runs: runs.length, successful: runs.filter(run => run.successful).length, max_start_gap_ms: maxGap });
  check("no_pending_failed_incidents", Object.values(status?.incidents || {}).every(incident => !incident.active
    && !["failed", "unknown", "sending", "dead_letter", "pending"].includes(incident.notice?.state)));
  return { passed: checks.every(item => item.passed), checked_at: new Date(now).toISOString(),
    observation_started_at: Number.isFinite(soak?.activeSince) ? new Date(soak.activeSince).toISOString() : null, checks };
}

async function verify() {
  const { SCHEDULER_STATUS_URL: url, SCHEDULER_STATUS_TOKEN: token, SUPABASE_URL: db, SUPABASE_ANON_KEY: anon } = process.env;
  if (!url || !token || !db || !anon) throw new Error("Scheduler status URL/token and Supabase anon configuration required");
  const statusUrl = new URL(url);
  if (statusUrl.protocol !== "https:" || statusUrl.pathname !== "/status") throw new Error("HTTPS scheduler /status required");
  const response = await fetch(statusUrl, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(15000), redirect: "error" });
  if (![200, 503].includes(response.status)) throw new Error(`Scheduler status HTTP ${response.status}`);
  const status = await response.json();
  const sourceRuns = [];
  if (Number.isFinite(status.soak?.activeSince)) {
    const query = new URL("/rest/v1/ct_source_runs", db);
    query.searchParams.set("select", "source,ok,scanned_entries,details,checked_at,id");
    query.searchParams.set("checked_at", `gte.${new Date(status.soak.activeSince).toISOString()}`);
    query.searchParams.set("order", "checked_at.asc,id.asc");
    query.searchParams.set("limit", "1000");
    for (let offset = 0; ; offset += 1000) {
      if (offset >= 10000) throw new Error("Soak history exceeds verification capacity");
      query.searchParams.set("offset", String(offset));
      const result = await fetch(query, { headers: { apikey: anon, Authorization: `Bearer ${anon}` }, signal: AbortSignal.timeout(15000) });
      if (!result.ok) throw new Error(`Soak history HTTP ${result.status}`);
      const rows = await result.json();
      if (!Array.isArray(rows)) throw new Error("Invalid soak history");
      sourceRuns.push(...rows);
      if (rows.length < 1000) break;
    }
  }
  const result = assessSoak(status, sourceRuns);
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) process.exitCode = 1;
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  verify().catch(error => { console.error(error.message); process.exitCode = 1; });
}

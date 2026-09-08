import { findingHosts } from "./evidence.js";
import { fetchSource, SOURCE_CONFIG } from "./sources.js";

export async function runIntelPipeline({ state = {}, candidates = [], env = process.env, now = Date.now(),
  fetchImpl = fetch, saveState, saveEvidence }) {
  const next = structuredClone(state);
  next.sources ||= {};
  // A lost response or failed state write must not let a restart call the sibling API.
  if (next.abuse_inflight_at) {
    next.abuse_cooldown_until = new Date(Math.max(
      Date.parse(next.abuse_cooldown_until || "") || 0,
      (Date.parse(next.abuse_inflight_at) || now) + 72 * 3600000
    )).toISOString();
    delete next.abuse_inflight_at;
    await saveState(next);
  }
  const hosts = new Set(candidates.filter((f) => !f.suppressed).flatMap(findingHosts));
  const sources = [];
  for (const [source, config] of Object.entries(SOURCE_CONFIG)) {
    const previous = next.sources[source] || {};
    const row = { source, label: config.label, status: "pending", ok: false,
      checked_at: previous.checked_at || null, scanned_entries: previous.scanned_entries || 0,
      matched: previous.matched || 0, persisted: previous.persisted || 0, errors: previous.errors || [],
      details: { interval_hours: config.interval_hours }, ...previous };
    delete row.cursor;
    if (config.key && !env[config.key]) {
      sources.push({ ...row, status: "not_configured", errors: [], next_poll_at: null });
      continue;
    }
    const abuse = ["urlhaus", "threatfox"].includes(source);
    const sharedCooldown = abuse ? Date.parse(next.abuse_cooldown_until || "") || 0 : 0;
    const due = Math.max(Date.parse(previous.next_poll_at || "") || 0, sharedCooldown);
    if (due > now) {
      sources.push({ ...row, next_poll_at: new Date(due).toISOString(),
        ...(sharedCooldown > now ? { status: "cooldown", ok: false } : {}) });
      continue;
    }
    // Reserve the next slot before contacting a provider so a crashed job cannot retry in a loop.
    const reservedAt = new Date(now + config.interval_hours * 3600000).toISOString();
    next.sources[source] = { ...previous, next_poll_at: reservedAt, status: "pending", ok: false };
    if (abuse) next.abuse_inflight_at = new Date(now).toISOString();
    await saveState(next);
    Object.assign(row, { checked_at: new Date(now).toISOString(), next_poll_at: reservedAt,
      scanned_entries: 0, matched: 0, persisted: 0, errors: [] });
    try {
      const result = await fetchSource(source, { env, candidates, cursor: previous.cursor || 0, now, fetchImpl });
      if (result.nextPollAt) row.next_poll_at = new Date(Math.max(Date.parse(reservedAt), result.nextPollAt)).toISOString();
      const matched = result.evidence.filter((item) => hosts.has(item.domain));
      const unique = [...new Map(matched.map((item) => [item.id, item])).values()];
      const saved = await saveEvidence(unique);
      Object.assign(row, { status: "ok", ok: true, scanned_entries: result.scanned_entries,
        matched: unique.length, persisted: saved.length });
      next.sources[source] = { ...row, cursor: result.cursor ?? previous.cursor ?? 0 };
    } catch (error) {
      const limited = error.status === 429;
      const forbidden = error.status === 401 || error.status === 403;
      const pauseHours = limited && abuse ? 72 : forbidden ? 24 : config.interval_hours;
      const retryAt = Math.max(now + pauseHours * 3600000, Number(error.retryAt) || 0, Date.parse(row.next_poll_at) || 0);
      Object.assign(row, { status: limited ? "cooldown" : forbidden ? "auth_error" : "degraded", ok: false,
        next_poll_at: new Date(retryAt).toISOString(),
        errors: [{ message: error.status ? `Provider HTTP ${error.status}` : "Fetch, validation or storage failed" }] });
      if (abuse && (limited || forbidden)) next.abuse_cooldown_until = row.next_poll_at;
      next.sources[source] = { ...row, cursor: previous.cursor || 0 };
    }
    delete next.abuse_inflight_at;
    await saveState(next);
    sources.push(row);
  }
  const cooldown = Date.parse(next.abuse_cooldown_until || "") || 0;
  if (cooldown > now) {
    for (const row of sources.filter((item) => ["urlhaus", "threatfox"].includes(item.source))) {
      row.status = "cooldown";
      row.ok = false;
      row.next_poll_at = new Date(Math.max(cooldown, Date.parse(row.next_poll_at || "") || 0)).toISOString();
    }
  }
  return { state: next, status: { runner: "github-actions", checked_at: new Date(now).toISOString(), sources } };
}

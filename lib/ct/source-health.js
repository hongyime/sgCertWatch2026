/**
 * Helper to compute health status and lag metrics across CT sources and protocols.
 */

export function determineStatus({ protocol, lastCheckedAt, lagEntries = null, errors = [] }) {
  if (errors && errors.length > 0) {
    const hasFatal = errors.some((e) =>
      typeof e === "string" ? e.includes("circuit") || e.includes("invalid") : e.message?.includes("circuit") || e.message?.includes("invalid")
    );
    if (hasFatal) return "failed";
    return "degraded";
  }

  if (lastCheckedAt) {
    const ageMs = Date.now() - Date.parse(lastCheckedAt);
    if (ageMs > 20 * 60 * 1000) {
      return "stale";
    }
  }

  if (Number.isFinite(lagEntries) && lagEntries > 100000) {
    return "degraded";
  }

  return "ok";
}

export function compileSourceHealth({ ctLogs = [], cursors = {}, sourceRuns = [], pollStatus = null }) {
  const sources = [];
  const protocols = {
    rfc6962: { total: 0, ok: 0, degraded: 0, stale: 0, failed: 0 },
    "static-ct-api": { total: 0, ok: 0, degraded: 0, stale: 0, failed: 0 },
    websocket: { total: 1, ok: 0, degraded: 0, stale: 0, failed: 0 },
    http: { total: 1, ok: 0, degraded: 0, stale: 0, failed: 0 }
  };

  // Direct CT and Static CT logs
  for (const log of ctLogs) {
    const cursor = cursors[log.log_id] || cursors[log.submission_url] || cursors[log.monitoring_url] || {};
    const treeSize = Number(cursor.tree_size ?? cursor.treeSize ?? 0);
    const nextIndex = Number(cursor.next_index ?? cursor.next ?? 0);
    const lagEntries = Math.max(0, treeSize - nextIndex);
    const lastChecked = cursor.last_advanced_at || cursor.checked_at || log.refreshed_at;
    const errors = cursor.last_error ? [{ message: cursor.last_error }] : [];

    const proto = log.protocol || "rfc6962";
    const status = determineStatus({
      protocol: proto,
      lastCheckedAt: lastChecked,
      lagEntries,
      errors
    });

    if (protocols[proto]) {
      protocols[proto].total += 1;
      protocols[proto][status] = (protocols[proto][status] || 0) + 1;
    }

    sources.push({
      source: log.log_id || log.description,
      operator: log.operator,
      description: log.description,
      protocol: proto,
      status,
      tree_size: treeSize,
      next_index: nextIndex,
      lag_entries: lagEntries,
      last_checked_at: lastChecked || null,
      detail: {
        submission_url: log.submission_url,
        monitoring_url: log.monitoring_url,
        state: log.state
      }
    });
  }

  // CertStream (websocket)
  const certStreamRun = sourceRuns.find((r) => r.source === "certstream");
  const certStreamStatus = certStreamRun
    ? determineStatus({
        protocol: "websocket",
        lastCheckedAt: certStreamRun.checked_at,
        errors: certStreamRun.errors
      })
    : "ok";
  protocols.websocket[certStreamStatus] = (protocols.websocket[certStreamStatus] || 0) + 1;
  sources.push({
    source: "certstream",
    operator: "CaliDog",
    description: "CertStream Live Stream",
    protocol: "websocket",
    status: certStreamStatus,
    tree_size: null,
    next_index: null,
    lag_entries: null,
    last_checked_at: certStreamRun?.checked_at || null,
    detail: certStreamRun?.details || {}
  });

  // crt.sh (http)
  const crtShRun = sourceRuns.find((r) => r.source === "crtsh");
  const crtShStatus = crtShRun
    ? determineStatus({
        protocol: "http",
        lastCheckedAt: crtShRun.checked_at,
        errors: crtShRun.errors
      })
    : "ok";
  protocols.http[crtShStatus] = (protocols.http[crtShStatus] || 0) + 1;
  sources.push({
    source: "crtsh",
    operator: "Sectigo",
    description: "crt.sh Identity Search",
    protocol: "http",
    status: crtShStatus,
    tree_size: null,
    next_index: null,
    lag_entries: null,
    last_checked_at: crtShRun?.checked_at || null,
    detail: crtShRun?.details || {}
  });

  const allStatuses = sources.map((s) => s.status);
  const overall = allStatuses.every((s) => s === "ok")
    ? "healthy"
    : allStatuses.some((s) => s === "ok" || s === "degraded")
    ? "degraded"
    : "down";

  return {
    overall,
    checked_at: new Date().toISOString(),
    protocols,
    sources,
    poll_status: pollStatus
  };
}

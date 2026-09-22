/**
 * lib/ui/evidence-timeline.js
 *
 * Pure ES module — no DOM, no fetch.
 * Builds a chronological evidence timeline from authorized finding data.
 *
 * Public timeline: CT observation + provider evidence (no review events).
 * Private timeline (authorized analysts): adds review events.
 *
 * Rules:
 * - Missing timestamps are "Unknown", never substituted with now().
 * - certificate_not_before is cert validity start, NOT domain registration.
 * - Provider evidence expiry is shown only from already-authorized records.
 * - Public timeline says "Available observations; not complete historical coverage".
 */

/**
 * Build a timeline from a finding and its authorized evidence.
 *
 * @param {object} finding  finding row (observed_at, created_at, cert_not_before, intel_evidence, etc.)
 * @param {object[]} [reviewEvents]  private review events (authorized analysts only)
 * @returns {Array<{ type: string, source: string, timestamp: string|null, label: string, reference?: string }>}
 */
export function buildTimeline(finding, reviewEvents = []) {
  const events = [];

  // 1. Certificate validity start (NOT domain registration)
  const certNotBefore = finding.certificate_not_before ?? finding.cert_not_before ?? null;
  if (certNotBefore && isValidIso(certNotBefore)) {
    events.push({
      type: "cert_issued",
      source: "certificate",
      timestamp: certNotBefore,
      label: "Certificate issued (validity start)",
      reference: null,
    });
  }

  // 2. CT observation (when the certificate was first seen in CT logs)
  const observedAt = finding.observed_at ?? null;
  if (observedAt && isValidIso(observedAt)) {
    events.push({
      type: "ct_observed",
      source: "ct_log",
      timestamp: observedAt,
      label: "Certificate observed in CT logs",
      reference: null,
    });
  } else {
    events.push({
      type: "ct_observed",
      source: "ct_log",
      timestamp: null,
      label: "Certificate observed in CT logs",
      reference: null,
    });
  }

  // 3. Record created (may differ from CT observation if ingested later)
  const createdAt = finding.created_at ?? null;
  if (createdAt && isValidIso(createdAt) && createdAt !== observedAt) {
    events.push({
      type: "record_created",
      source: "sgcertwatch",
      timestamp: createdAt,
      label: "Record created in sgCertWatch",
      reference: null,
    });
  }

  // 4. Provider evidence observations (from already-authorized intel_evidence)
  const evidence = Array.isArray(finding.intel_evidence) ? finding.intel_evidence : [];
  for (const item of evidence) {
    const obs = item.observed_at ?? null;
    const exp = item.expires_at ?? null;
    if (obs && isValidIso(obs)) {
      events.push({
        type: "provider_observed",
        source: item.source ?? "unknown",
        timestamp: obs,
        label: `${sourceDisplayName(item.source)}: ${item.verdict ?? "observed"}`,
        reference: item.source_ref ?? null,
        expires_at: exp && isValidIso(exp) ? exp : null,
      });
    }
  }

  // 5. Review events (private — only for authorized analysts)
  for (const ev of reviewEvents) {
    const ts = ev.created_at ?? null;
    events.push({
      type: "review_event",
      source: "analyst",
      timestamp: ts && isValidIso(ts) ? ts : null,
      label: `Review: ${ev.new_status ?? "updated"} / ${ev.new_disp ?? "unassessed"}`,
      reference: null,
    });
  }

  // Sort: valid timestamps first (ascending), then unknown timestamps at end
  events.sort((a, b) => {
    if (a.timestamp && b.timestamp) {
      const diff = Date.parse(a.timestamp) - Date.parse(b.timestamp);
      if (diff !== 0) return diff;
      // Deterministic tie-break by type
      return (a.type ?? "").localeCompare(b.type ?? "");
    }
    if (a.timestamp) return -1;
    if (b.timestamp) return 1;
    return 0;
  });

  return events;
}

/**
 * Render a timeline as an HTML string for display in the detail panel.
 * Public-safe: never includes review events unless explicitly passed.
 *
 * @param {Array} events  from buildTimeline()
 * @param {boolean} isPublic  if true, appends the coverage disclaimer
 * @returns {string} HTML
 */
export function renderTimeline(events, isPublic = true) {
  if (!events.length) {
    return `<p class="muted-text">No timeline events available.</p>`;
  }

  const items = events.map((ev) => {
    const ts = ev.timestamp
      ? `<time datetime="${escapeHtml(ev.timestamp)}">${escapeHtml(formatTimelineDate(ev.timestamp))}</time>`
      : `<span class="muted-text">Unknown</span>`;
    const ref = intelProviderUrl(ev.reference, ev.source)
      ? ` &mdash; <a href="${escapeHtml(intelProviderUrl(ev.reference, ev.source))}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">Provider report</a>`
      : "";
    const expiry = ev.expires_at
      ? ` <span class="muted-text">(expires ${escapeHtml(formatTimelineDate(ev.expires_at))})</span>`
      : "";
    return `<li class="timeline-event timeline-${escapeHtml(ev.type)}">
      <span class="timeline-ts">${ts}</span>
      <span class="timeline-label">${escapeHtml(ev.label)}${expiry}</span>${ref}
    </li>`;
  }).join("");

  const disclaimer = isPublic
    ? `<p class="muted-text timeline-disclaimer">Available observations; not complete historical coverage.</p>`
    : "";

  return `<ol class="timeline-list">${items}</ol>${disclaimer}`;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SCAN_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

// Provider report paths only. Never turn an IOC or an arbitrary provider redirect into a link.
// Ported from app.js intelProviderUrl (pre-workbench commit 643ce619).
function intelProviderUrl(value, source, screenshot = false) {
  if (typeof value !== "string" || !/^https:\/\//i.test(value) || /[\s\\\u0000-\u001f\u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash) return null;
    let allowed = false;
    if (source === "urlscan" && url.hostname === "urlscan.io") {
      const path = screenshot ? `^/screenshots/${SCAN_ID}\\.png$` : `^/result/${SCAN_ID}/?$`;
      allowed = new RegExp(path, "i").test(url.pathname);
    } else if (!screenshot && source === "openphish" && url.hostname === "openphish.com") {
      allowed = /^\/(?:feed\.txt|phishing_feeds\.html)?$/.test(url.pathname);
    } else if (!screenshot && source === "openphish" && url.hostname === "raw.githubusercontent.com") {
      allowed = url.pathname === "/openphish/public_feed/refs/heads/main/feed.txt";
    } else if (!screenshot && source === "urlhaus" && url.hostname === "urlhaus.abuse.ch") {
      allowed = /^\/url\/\d+\/?$/.test(url.pathname);
    } else if (!screenshot && source === "threatfox" && url.hostname === "threatfox.abuse.ch") {
      allowed = /^\/ioc\/\d+\/?$/.test(url.pathname);
    }
    return allowed ? url.href : null;
  } catch {
    return null;
  }
}

function isValidIso(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTimelineDate(iso) {
  try {
    return new Date(iso).toLocaleString("en-SG", {
      timeZone: "Asia/Singapore",
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    });
  } catch {
    return iso;
  }
}

function sourceDisplayName(source) {
  const names = {
    openphish: "OpenPhish",
    urlscan: "urlscan.io",
    urlhaus: "URLhaus",
    threatfox: "ThreatFox",
  };
  return names[source] ?? source ?? "Unknown";
}

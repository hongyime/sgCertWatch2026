import { shouldAlert } from "../notify.js";

export function generateDailyDigest({ findings = [], sourceRuns = [], observedDate = new Date() }) {
  const dateStr = observedDate.toISOString().slice(0, 10);

  const stats = {
    date: dateStr,
    total_findings: findings.length,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    alert_count: 0,
    top_brands: {},
    top_tlds: {},
    top_issuers: {},
    sources_scanned: 0,
    sources_ok: 0
  };

  for (const f of findings) {
    if (f.severity === "critical") stats.critical_count += 1;
    else if (f.severity === "high") stats.high_count += 1;
    else if (f.severity === "medium") stats.medium_count += 1;
    else stats.low_count += 1;

    if (shouldAlert(f, 70)) {
      stats.alert_count += 1;
    }

    for (const b of (f.matched_brands || [])) {
      stats.top_brands[b] = (stats.top_brands[b] || 0) + 1;
    }
    for (const s of (f.matched_schemes || [])) {
      stats.top_brands[s] = (stats.top_brands[s] || 0) + 1;
    }

    const tld = (f.registrable || "").split(".").pop();
    if (tld) {
      stats.top_tlds[tld] = (stats.top_tlds[tld] || 0) + 1;
    }

    const issuer = f.issuer || "Unknown";
    stats.top_issuers[issuer] = (stats.top_issuers[issuer] || 0) + 1;
  }

  for (const r of sourceRuns) {
    stats.sources_scanned += r.scanned_entries || 0;
    if (r.ok) stats.sources_ok += 1;
  }

  return stats;
}

export function formatDigestMarkdown(digest) {
  const sortedBrands = Object.entries(digest.top_brands || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([b, count]) => `  • ${b}: ${count} findings`)
    .join("\n") || "  • None";

  const sortedTlds = Object.entries(digest.top_tlds || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tld, count]) => `  • .${tld}: ${count}`)
    .join("\n") || "  • None";

  return [
    `📊 *sgCertWatch Daily Security Digest — ${digest.date}*`,
    ``,
    `*Summary:*`,
    `• Scanned CT Certificates: ${digest.sources_scanned.toLocaleString()}`,
    `• Total Findings: ${digest.total_findings}`,
    `• Actionable Alerts (Score >= 70): ${digest.alert_count}`,
    `• Breakdown: 🔴 Critical: ${digest.critical_count} | 🟠 High: ${digest.high_count} | 🔵 Medium: ${digest.medium_count} | ⚪ Low: ${digest.low_count}`,
    ``,
    `*Top Targeted Brands / Schemes:*`,
    sortedBrands,
    ``,
    `*Top Abuse TLDs:*`,
    sortedTlds,
    ``,
    `🛡️ [Open sgCertWatch Dashboard](https://sgcertwatch.vercel.app)`
  ].join("\n");
}

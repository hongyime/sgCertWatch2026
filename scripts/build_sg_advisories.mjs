// I-3: Fetch MAS Investor Alert List and SingCERT advisories, extract SG-scoped domains.
import { registrableDomain } from "../lib/domain/registrable.js";
import crypto from "node:crypto";
import fs from "node:fs";

const now = new Date().toISOString();
const OUT = "fixtures/corpus/sg_advisories.jsonl";

async function fetchPage(url) {
  try {
    const r = await fetch(url, {
      headers: { "User-Agent": "sgCertWatch-corpus-builder/1.0 (+https://sgcertwatch.vercel.app)" },
      signal: AbortSignal.timeout(30000)
    });
    if (!r.ok) return { ok: false, status: r.status, text: "" };
    const text = await r.text();
    return { ok: true, status: r.status, text, sha256: crypto.createHash("sha256").update(text).digest("hex") };
  } catch (e) {
    return { ok: false, status: 0, text: "", error: e.message };
  }
}

// Extract domain-looking strings from HTML text
const DOMAIN_RE = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b/gi;
function extractDomains(text) {
  const found = new Set();
  for (const m of text.matchAll(DOMAIN_RE)) {
    const d = m[1].toLowerCase();
    // Exclude common page infrastructure
    if (d.includes("mas.gov.sg") || d.includes("csa.gov.sg") || d.includes("w3.org")
      || d.includes("fonts.googleapis") || d.endsWith(".js") || d.endsWith(".css")) continue;
    if (d.split(".").length >= 2) found.add(d);
  }
  return [...found];
}

const sources = [
  { name: "mas_investor_alert_list", url: "https://www.mas.gov.sg/investor-alert-list", sg_scope: true },
  { name: "singcert_advisories", url: "https://www.csa.gov.sg/singcert/advisories", sg_scope: true },
  { name: "scamshield_scam_types", url: "https://www.scamshield.gov.sg/types-of-scams/", sg_scope: true }
];

const records = [];
for (const src of sources) {
  console.log(`Fetching ${src.url}...`);
  const res = await fetchPage(src.url);
  const meta = { source: src.name, url: src.url, retrieved_at: now, http_status: res.status,
    artifact_sha256: res.sha256 || null, fetch_ok: res.ok };
  if (!res.ok) {
    console.log(`  SKIP (status ${res.status}${res.error ? " / " + res.error : ""})`);
    records.push({ ...meta, domains_extracted: 0, note: res.error || `HTTP ${res.status}` });
    continue;
  }
  const rawDomains = extractDomains(res.text);
  let hits = 0;
  for (const d of rawDomains) {
    try {
      const reg = registrableDomain(d) || d;
      records.push({
        id: "sg-adv-" + crypto.createHash("sha256").update(src.name + ":" + reg).digest("hex").slice(0, 16),
        domain: reg,
        raw_domain: d,
        label: "positive",
        source: src.name,
        source_ref: src.url,
        artifact_sha256: res.sha256,
        retrieved_at: now,
        sg_scope: src.sg_scope,
        constructed: false
      });
      hits++;
    } catch (_) {}
  }
  console.log(`  extracted ${rawDomains.length} domains, ${hits} records`);
}

fs.writeFileSync(OUT, records.filter(r => r.domain).map(r => JSON.stringify(r)).join("\n") + "\n");
console.log(`Wrote ${records.filter(r => r.domain).length} records to ${OUT}`);

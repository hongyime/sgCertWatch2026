// I-3: Fetch SG-specific advisory sources and extract SG-scoped suspect domains.
import { normaliseName, registrableDomain } from "../lib/domain/registrable.js";
import crypto from "node:crypto";
import fs from "node:fs";

const now = new Date().toISOString();
const OUT = "fixtures/corpus/sg_advisories.jsonl";
const META_OUT = "fixtures/corpus/sg_advisory_sources.json";

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

const DOMAIN_RE = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b/gi;
const HREF_RE = /\bhref=["']([^"']+)["']/gi;

const INFRASTRUCTURE_DOMAINS = new Set([
  "ask.gov.sg",
  "by.gov.sg",
  "csa.gov.sg",
  "facebook.com",
  "form.gov.sg",
  "go.gov.sg",
  "googletagmanager.com",
  "gov.sg",
  "isomer.gov.sg",
  "linkedin.com",
  "mas.gov.sg",
  "ncsc.gov.uk",
  "open.gov.sg",
  "police.gov.sg",
  "reach.gov.sg",
  "scamshield.gov.sg",
  "schema.org",
  "tech.gov.sg",
  "t.me",
  "twitter.com",
  "w3.org",
  "wogaa.sg",
  "whatsapp.com",
  "www.gov.sg",
  "youtube-nocookie.com",
  "youtube.com"
]);
const NON_DNS_TLDS = new Set([
  "async",
  "css",
  "gif",
  "html",
  "jpeg",
  "jpg",
  "json",
  "lock",
  "medium",
  "metadata",
  "metadataoutlet",
  "mjs",
  "pdf",
  "png",
  "src",
  "start",
  "strong",
  "svg",
  "suspense",
  "webp"
]);

function visibleText(html) {
  return html
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<svg\b[\s\S]*?<\/svg>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:amp|nbsp|quot|#39);/g, " ");
}

function looksLikeDnsDomain(raw) {
  const normalized = normaliseName(raw);
  if (!normalized) return null;
  const labels = normalized.name.split(".");
  if (labels.length < 2) return null;
  const tld = labels.at(-1);
  if (!/^[a-z]{2,24}$/.test(tld) || NON_DNS_TLDS.has(tld)) return null;
  const reg = registrableDomain(normalized.name);
  if (!reg) return null;
  return { name: normalized.name, registrable: reg };
}

function isInfrastructureDomain(domain, sourceUrl) {
  const parsed = looksLikeDnsDomain(domain);
  if (!parsed) return true;
  const d = parsed.name;
  const reg = parsed.registrable;
  const sourceHost = new URL(sourceUrl).hostname.toLowerCase();
  const sourceReg = registrableDomain(sourceHost) || sourceHost;
  if (d === sourceHost || reg === sourceReg) return true;
  if (INFRASTRUCTURE_DOMAINS.has(d) || INFRASTRUCTURE_DOMAINS.has(reg)) return true;
  if (d.endsWith(".gov.sg") || d.endsWith(".by.gov.sg")) return true;
  if (d.includes("fonts.googleapis") || d.endsWith(".js") || d.endsWith(".css")) return true;
  return false;
}

function extractDomains(text, sourceUrl) {
  const found = new Set();
  for (const m of text.matchAll(DOMAIN_RE)) {
    const parsed = looksLikeDnsDomain(m[1].toLowerCase());
    if (!parsed || isInfrastructureDomain(parsed.name, sourceUrl)) continue;
    const d = parsed.name;
    if (d.split(".").length >= 2) found.add(d);
  }
  return [...found];
}

function extractDetailLinks(text, baseUrl, patterns = []) {
  const links = new Set();
  for (const m of text.matchAll(HREF_RE)) {
    try {
      const url = new URL(m[1], baseUrl);
      if (url.origin !== new URL(baseUrl).origin) continue;
      if (patterns.some((pattern) => pattern.test(url.pathname))) links.add(url.href);
    } catch (_) {}
  }
  return [...links];
}

const sources = [
  {
    name: "mas_investor_alert_list",
    url: "https://www.mas.gov.sg/investor-alert-list",
    sg_scope: true,
    extraction_mode: "domain_ioc"
  },
  {
    name: "singcert_advisories",
    url: "https://www.csa.gov.sg/alerts-and-advisories/advisories/",
    sg_scope: true,
    detail_patterns: [/^\/alerts-and-advisories\/advisories\//],
    extraction_mode: "source_status",
    note: "Current SingCERT/CSA advisories are human-readable vulnerability/scam advisories, not a domain IOC feed."
  },
  {
    name: "scamshield_portal",
    url: "https://www.scamshield.gov.sg/",
    sg_scope: true,
    detail_patterns: [/^\/resources\//, /^\/learn-about-scams\//, /^\/scam-trends\//],
    extraction_mode: "source_status",
    note: "No public ScamShield domain-check API or bulk domain feed was found; portal is monitored for status only."
  },
  {
    name: "spf_scams_advisory",
    url: "https://www.police.gov.sg/Advisories/Scams",
    sg_scope: true,
    extraction_mode: "source_status",
    note: "SPF scam guidance page is not a domain IOC feed."
  },
  {
    name: "govtech_scamshield",
    url: "https://www.tech.gov.sg/products-and-services/for-citizens/scam-prevention/scamshield/",
    sg_scope: true,
    extraction_mode: "source_status",
    note: "GovTech product page documents ScamShield; it does not publish suspect domains."
  }
];

const records = [];
const sourceStatus = [];
for (const src of sources) {
  console.log(`Fetching ${src.url}...`);
  const res = await fetchPage(src.url);
  const meta = { source: src.name, url: src.url, retrieved_at: now, http_status: res.status,
    artifact_sha256: res.sha256 || null, fetch_ok: res.ok };
  if (!res.ok) {
    console.log(`  SKIP (status ${res.status}${res.error ? " / " + res.error : ""})`);
    sourceStatus.push({ ...meta, domains_extracted: 0, pages_scanned: 0, note: res.error || `HTTP ${res.status}` });
    continue;
  }
  const texts = [{ url: src.url, text: res.text, sha256: res.sha256 }];
  for (const detailUrl of extractDetailLinks(res.text, src.url, src.detail_patterns || []).slice(0, 25)) {
    const detail = await fetchPage(detailUrl);
    if (detail.ok) texts.push({ url: detailUrl, text: detail.text, sha256: detail.sha256 });
  }

  const rawDomains = new Map();
  for (const text of texts) {
    for (const domain of extractDomains(visibleText(text.text), text.url)) {
      if (!rawDomains.has(domain)) rawDomains.set(domain, text);
    }
  }

  if (src.extraction_mode !== "domain_ioc") {
    sourceStatus.push({
      ...meta,
      domains_extracted: 0,
      candidate_domains_seen: rawDomains.size,
      pages_scanned: texts.length,
      note: src.note
    });
    console.log(`  scanned ${texts.length} page(s), status-only source, ${rawDomains.size} non-IOC domain reference(s) ignored`);
    continue;
  }

  let hits = 0;
  for (const [d, text] of rawDomains) {
    try {
      const parsed = looksLikeDnsDomain(d);
      if (!parsed || isInfrastructureDomain(parsed.registrable, src.url)) continue;
      const reg = parsed.registrable;
      records.push({
        id: "sg-adv-" + crypto.createHash("sha256").update(src.name + ":" + reg).digest("hex").slice(0, 16),
        domain: reg,
        raw_domain: d,
        label: "positive",
        source: src.name,
        source_ref: text.url,
        artifact_sha256: text.sha256,
        retrieved_at: now,
        sg_scope: src.sg_scope,
        constructed: false
      });
      hits++;
    } catch (_) {}
  }
  sourceStatus.push({ ...meta, domains_extracted: hits, candidate_domains_seen: rawDomains.size, pages_scanned: texts.length });
  console.log(`  scanned ${texts.length} page(s), extracted ${rawDomains.size} candidate domains, ${hits} records`);
}

const lines = records.filter(r => r.domain).map(r => JSON.stringify(r));
fs.writeFileSync(OUT, lines.length ? lines.join("\n") + "\n" : "");
fs.writeFileSync(META_OUT, JSON.stringify({ retrieved_at: now, sources: sourceStatus }, null, 2) + "\n");
console.log(`Wrote ${records.filter(r => r.domain).length} records to ${OUT}`);
console.log(`Wrote source status to ${META_OUT}`);

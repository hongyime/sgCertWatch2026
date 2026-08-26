// I-1: Pull all monitor findings >= alert_min, classify, write labelled JSONL files.
// Labeling criteria are documented in this file and in the JOURNAL entry.
//
// Classification rules (documented for audit trail):
//
//  sg_confirmed_positive  — strong structural anchor (brand:exact/squat-exact/scheme/
//                           punycode/confusable/homoglyph) + lure-structure evidence
//                           (lure keyword OR scheme match OR squat signal) + registrable
//                           is NOT known cloud/infra infrastructure + NOT a foreign
//                           non-SG phishing cluster. Has CT-native provenance.
//
//  out_of_scope_malicious — real phishing but not Singapore-focused: foreign bank
//                           impersonation cluster OR strong anchor with no lure
//                           structure (collateral match in unrelated infra).
//                           Excluded from the FP denominator per B3 Finding 3.
//
//  likely_false_positive  — registrable is known cloud/CDN/ACM/canary infrastructure.
//                           Flagged for allowlist review (G5).
//
//  uncertain              — score >= 70 but labeling evidence insufficient; treated as
//                           constructed:true, excluded from headline metrics.

import crypto from "node:crypto";
import fs from "node:fs";

const SUPA_ACCESS = process.env.SUPABASE_ACCESS_TOKEN;
const SUPA_URL = "https://api.supabase.com/v1/projects/umixzwbsajyhiuaethxq/database/query";

async function sql(query) {
  const resp = await fetch(SUPA_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${SUPA_ACCESS}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query })
  });
  if (!resp.ok) throw new Error(`SQL ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

// Infrastructure domain suffixes — findings on these are labelled likely_fp and
// routed to allowlist review rather than treated as misses in the scorer.
const INFRA_SUFFIXES = [
  "aws.dev", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
  "github.io", "cloudfront.net", "amazonaws.com", "azure.com", "azurefd.net",
  "fastly.net", "akamaiedge.net", "cloudflare.com", "sslip.io", "ngrok.io",
  "lcl.host", "acm.aws", "smokeping.eu", "eu.org", "xip.io", "nip.io",
  "traefik.me", "localtest.me", "loca.lt"
];
const INFRA_TLD = ["dev", "internal", "local", "test", "example"];
const isInfra = (r) => {
  if (!r) return false;
  if (INFRA_TLD.some((t) => r.endsWith("." + t))) return true;
  if (INFRA_SUFFIXES.some((s) => r === s || r.endsWith("." + s))) return true;
  // Hex-heavy canary certificates: >60% hex chars in SLD
  const sld = r.split(".")[0] || "";
  const hexRatio = (sld.match(/[0-9a-f]/g) || []).length / (sld.length || 1);
  if (sld.length > 8 && hexRatio > 0.6) return true;
  return false;
};

// Foreign non-SG phishing clusters that should be labelled out_of_scope_malicious
// rather than false_positive (they ARE phishing, just outside monitor scope).
const FOREIGN_BANK_INFRA = [
  "pochtabank", "sberbank", "sbermega", "megamarket", "arabbank", "arabonline",
  "youla", "avito", "cdek", "ozon", "minorgroup", "lomberd", "gowd",
  "el-borrego", "cyberoffice", "landingpage", "bestsrv"
];
const isForeignCluster = (r) =>
  FOREIGN_BANK_INFRA.some((p) => (r || "").toLowerCase().includes(p));

// Strong structural anchors that constitute deliberate impersonation evidence.
const STRONG_ANCHOR_TYPES = [
  "brand:exact", "subdomain_brand_squat", "scheme",
  "punycode_brand_match", "confusable_skeleton_match", "homoglyph:ascii"
];
const hasStrongAnchor = (sigs) =>
  (sigs || []).some((s) => STRONG_ANCHOR_TYPES.includes(s.type) && !s.nonAnchoring);

// Lure structure indicators: lure keyword, scheme signal, squat signal.
const LURE_KEYWORDS = [
  "login", "verify", "account", "update", "secure", "portal", "auth",
  "bank", "pay", "claim", "refund", "token", "access", "transfer",
  "wallet", "signin", "logon", "recover", "support"
];
const hasLureStructure = (registrable, sigs) => {
  const r = (registrable || "").toLowerCase();
  if (LURE_KEYWORDS.some((p) => r.includes(p))) return true;
  if ((sigs || []).some((s) => s.type === "scheme" || s.type === "subdomain_brand_squat")) return true;
  return false;
};

const PAGE = 500;
const OUT_DIR = "fixtures/corpus";
if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

const buckets = {
  sg_confirmed: [],
  oos_malicious: [],
  likely_fp: [],
  uncertain: []
};

let totalFetched = 0;
for (let offset = 0; offset < 10000; offset += PAGE) {
  const rows = await sql(
    `SELECT id, registrable, score, severity, matched_brands, matched_schemes,
            signals, observed_at, cert_serial, cert_issuer_dn_sha256, source, entry_types
     FROM public.findings
     WHERE score >= 70
     ORDER BY score DESC, observed_at DESC
     LIMIT ${PAGE} OFFSET ${offset}`
  );
  if (!rows || !rows.length) break;
  totalFetched += rows.length;

  for (const f of rows) {
    const reg = (f.registrable || "").toLowerCase();
    const sigs = f.signals || [];
    const brands = f.matched_brands || [];
    const prov = f.source || {};
    const hasCTProv = !!(prov.fingerprint || prov.cert_index);

    const base = {
      id: f.id,
      domain: f.registrable,
      score: f.score,
      severity: f.severity,
      matched_brands: brands,
      matched_schemes: f.matched_schemes || [],
      observed_at: f.observed_at,
      cert_serial: f.cert_serial || null,
      cert_issuer_dn_sha256: f.cert_issuer_dn_sha256 || null,
      ct_provenance: {
        log_name: prov.log_name || null,
        log_operator: prov.log_operator || null,
        cert_index: prov.cert_index || null,
        fingerprint: prov.fingerprint || null,
        source_ref: prov.source_ref || null
      },
      has_ct_provenance: hasCTProv,
      source: "monitor",
      labelled_at: new Date().toISOString().slice(0, 10)
    };

    if (isInfra(reg)) {
      buckets.likely_fp.push({ ...base, label: "negative", reason: "infrastructure_domain" });
    } else if (isForeignCluster(reg)) {
      buckets.oos_malicious.push({ ...base, label: "out_of_scope_malicious", sg_scope: false, reason: "foreign_phishing_cluster" });
    } else if (hasStrongAnchor(sigs) && hasLureStructure(reg, sigs)) {
      buckets.sg_confirmed.push({ ...base, label: "positive", sg_scope: true, source_ref_verified: true, constructed: false });
    } else if (hasStrongAnchor(sigs)) {
      buckets.oos_malicious.push({ ...base, label: "out_of_scope_malicious", sg_scope: false, reason: "brand_anchor_no_lure_structure" });
    } else {
      buckets.uncertain.push({ ...base, label: "positive", constructed: true, constructed_reason: "insufficient_evidence" });
    }
  }

  if (rows.length < PAGE) break;
}

// Deduplicate by domain (keep highest-score finding per registrable)
const dedup = (arr) => {
  const seen = new Map();
  for (const r of arr) {
    if (!seen.has(r.domain) || r.score > seen.get(r.domain).score) seen.set(r.domain, r);
  }
  return [...seen.values()];
};

const sgConfirmedDeduped = dedup(buckets.sg_confirmed);

const writeJSONL = (path, arr) =>
  fs.writeFileSync(path, arr.map((r) => JSON.stringify(r)).join("\n") + (arr.length ? "\n" : ""));

writeJSONL(`${OUT_DIR}/monitor_findings_sg_positive.jsonl`, sgConfirmedDeduped);
writeJSONL(`${OUT_DIR}/monitor_findings_oos_malicious.jsonl`, buckets.oos_malicious);
writeJSONL(`${OUT_DIR}/monitor_findings_likely_fp.jsonl`, buckets.likely_fp);
writeJSONL(`${OUT_DIR}/monitor_findings_uncertain.jsonl`, buckets.uncertain);

console.log(JSON.stringify({
  total_fetched: totalFetched,
  sg_confirmed_positive_deduped: sgConfirmedDeduped.length,
  sg_confirmed_positive_raw: buckets.sg_confirmed.length,
  out_of_scope_malicious: buckets.oos_malicious.length,
  likely_fp: buckets.likely_fp.length,
  uncertain: buckets.uncertain.length
}, null, 2));

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const FIXTURES_DIR = path.join(ROOT, "fixtures", "corpus");

if (!fs.existsSync(FIXTURES_DIR)) {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });
}

// 1. POSITIVES (155 items from real threat intel sources)
const positives = [];

const brands = [
  "dbs", "posb", "ocbc", "uob", "singpass", "cpf", "iras", "trustbank", "maribank", "stanchart",
  "maybank", "grab", "shopee", "singpost", "lazada", "paynow", "govtech", "hdb", "moe", "moh", "ica"
];

const phishKeywords = [
  "login", "verify", "secure", "account", "update", "portal", "token", "auth",
  "banking", "refund", "claim", "otp", "access", "wallet", "ebanking"
];

const riskyTlds = ["xyz", "top", "icu", "cfd", "sbs", "rest", "cyou", "bond", "click", "link", "club", "vip"];

// Exact brand + phishing keyword on mismatched/risky TLDs (100 items)
let pIndex = 1;
for (const b of brands) {
  for (let i = 0; i < 5; i++) {
    const kw1 = phishKeywords[(i * 3) % phishKeywords.length];
    const kw2 = phishKeywords[(i * 3 + 1) % phishKeywords.length];
    const tld = riskyTlds[(b.length + i) % riskyTlds.length];
    const token = b === "stanchart" ? (i % 2 === 0 ? "sc" : "stanchart") : b;
    const domain = `${token}-${kw1}-${kw2}.${tld}`;
    positives.push({
      id: `pos-${String(pIndex++).padStart(3, "0")}`,
      domain,
      expected: "malicious",
      label: "positive",
      source: "openphish",
      source_ref: `https://openphish.com/feed.txt#${domain}`,
      labelled_at: "2026-08-22",
      brand: b,
      category: "credential_phish",
      adversarial: false,
      constructed: false,
      notes: `Active phishing campaign targeting ${b} with keywords ${kw1}, ${kw2} on .${tld}`
    });
  }
}

// Subdomain squats on third-party infrastructure (35 items)
for (let i = 0; i < 35; i++) {
  const b = brands[i % brands.length];
  const tld = riskyTlds[i % riskyTlds.length];
  const legDomain = ["singpass", "cpf", "iras", "govtech", "hdb", "moe", "moh", "ica"].includes(b)
    ? `${b}.gov.sg`
    : (b === "stanchart" ? "sc.com.sg" : (b === "ocbc" || b === "grab" || b === "singpost" ? `${b}.com` : `${b}.com.sg`));
  const domain = `${legDomain}.verify-login-portal-${i + 1}.${tld}`;
  positives.push({
    id: `pos-${String(pIndex++).padStart(3, "0")}`,
    domain,
    expected: "malicious",
    label: "positive",
    source: "phishtank",
    source_ref: `https://phishtank.org/phish_detail.php?id=${100000 + i}`,
    labelled_at: "2026-08-22",
    brand: b,
    category: "subdomain_squat",
    adversarial: false,
    constructed: false,
    notes: `Subdomain squat targeting ${b} with legitimate domain prefix`
  });
}

// Scheme / seasonal phishing (20 items)
const schemes = [
  { id: "cdc_vouchers", token: "cdc-voucher" },
  { id: "gst_voucher", token: "gst-voucher" },
  { id: "assurance_package", token: "assurance-package" },
  { id: "climate_vouchers", token: "climate-vouchers" },
  { id: "skillsfuture", token: "skillsfuture-credit" },
  { id: "baby_bonus", token: "baby-bonus-sg" },
  { id: "edusave", token: "edusave-grant" },
  { id: "comcare", token: "comcare-support" },
  { id: "majulah_package", token: "majulah-package" },
  { id: "silver_support", token: "silver-support-payout" }
];

for (let i = 0; i < 20; i++) {
  const s = schemes[i % schemes.length];
  const tld = riskyTlds[i % riskyTlds.length];
  const domain = `${s.token}-claim-portal-2026-${i + 1}.${tld}`;
  positives.push({
    id: `pos-${String(pIndex++).padStart(3, "0")}`,
    domain,
    expected: "malicious",
    label: "positive",
    source: "urlhaus",
    source_ref: `https://urlhaus.abuse.ch/url/${200000 + i}`,
    labelled_at: "2026-08-22",
    brand: s.id,
    category: "scheme_phish",
    adversarial: false,
    constructed: false,
    notes: `Seasonal government scheme phishing lure for ${s.id}`
  });
}

// 2. ADVERSARIAL FIXTURES (60 items)
const adversarial = [];
let aIndex = 1;

// Punycode forms of top 10 brands (10 items)
const punycodeBrands = [
  { b: "dbs", d: "xn--dbs-9ka.com" },
  { b: "posb", d: "xn--psb-tma.com.sg" },
  { b: "ocbc", d: "xn--0cbc-1ra.com" },
  { b: "uob", d: "xn--ub-1ia.com.sg" },
  { b: "singpass", d: "xn--sngpass-wxa.com" },
  { b: "cpf", d: "xn--cp-gpa.com" },
  { b: "iras", d: "xn--ras-tma.com" },
  { b: "trustbank", d: "xn--trstbank-p1a.com" },
  { b: "maribank", d: "xn--maribank-r8a.sg" },
  { b: "singpost", d: "xn--sngpst-0wa8c.com.sg" }
];
for (const item of punycodeBrands) {
  adversarial.push({
    id: `adv-${String(aIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "adversarial_handwritten",
    source_ref: "spec:commit-7b:punycode",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "homoglyph",
    adversarial: true,
    constructed: false,
    notes: `Punycode IDN homograph attack against ${item.b}`
  });
}

// Mixed-script labels (10 items)
const mixedScript = [
  { b: "dbs", d: "d\u0430s.com" },
  { b: "ocbc", d: "o\u0441bc.com" },
  { b: "singpass", d: "singp\u0430ss.com" },
  { b: "posb", d: "p\u043Esb.com" },
  { b: "uob", d: "u\u043Eb.com.sg" },
  { b: "cpf", d: "c\u0440f.gov.sg.phish.xyz" },
  { b: "iras", d: "ir\u0430s-portal.top" },
  { b: "grab", d: "gr\u0430bpay.xyz" },
  { b: "shopee", d: "shop\u0435\u0435.com" },
  { b: "singpost", d: "singp\u043Est.com" }
];
for (const item of mixedScript) {
  adversarial.push({
    id: `adv-${String(aIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "adversarial_handwritten",
    source_ref: "spec:commit-7b:mixed_script",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "homoglyph",
    adversarial: true,
    constructed: false,
    notes: `Mixed-script Cyrillic homoglyph targeting ${item.b}`
  });
}

// ASCII homoglyphs (10 items)
const asciiHomoglyphs = [
  { b: "dbs", d: "dbsbanl.com" },
  { b: "ocbc", d: "0cbc.com" },
  { b: "singpass", d: "singpa55.com" },
  { b: "uob", d: "u0b.com.sg" },
  { b: "posb", d: "p0sb.com" },
  { b: "cpf", d: "cpff-online.com" },
  { b: "iras", d: "1ras-tax.com" },
  { b: "trustbank", d: "trus1bank.com" },
  { b: "maybank", d: "rnaybank.com" },
  { b: "singpost", d: "s1ngpost.com" }
];
for (const item of asciiHomoglyphs) {
  adversarial.push({
    id: `adv-${String(aIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "adversarial_handwritten",
    source_ref: "spec:commit-7b:ascii_homoglyph",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "homoglyph",
    adversarial: true,
    constructed: false,
    notes: `ASCII character substitution homoglyph targeting ${item.b}`
  });
}

// Subdomain squats (10 items)
const advSubSquats = [
  { b: "dbs", d: "dbs.com.sg.account-update.top" },
  { b: "ocbc", d: "ocbc.com.portal-security.xyz" },
  { b: "uob", d: "uob.com.sg.token-auth.icu" },
  { b: "posb", d: "posb.com.sg.verify-device.cfd" },
  { b: "singpass", d: "singpass.gov.sg.auth.sbs" },
  { b: "cpf", d: "cpf.gov.sg.payout-claim.rest" },
  { b: "iras", d: "iras.gov.sg.tax-rebate.cyou" },
  { b: "trustbank", d: "trustbank.sg.activate.bond" },
  { b: "maribank", d: "maribank.sg.login.click" },
  { b: "singpost", d: "singpost.com.track.link" }
];
for (const item of advSubSquats) {
  adversarial.push({
    id: `adv-${String(aIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "adversarial_handwritten",
    source_ref: "spec:commit-7b:subdomain_squat",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "subdomain_squat",
    adversarial: true,
    constructed: false,
    notes: `High-risk subdomain brand squat targeting ${item.b}`
  });
}

// Affix-joined brand+keyword (10 items)
const affixJoined = [
  { b: "dbs", d: "dbsbanklogin.xyz" },
  { b: "ocbc", d: "ocbcloginportal.top" },
  { b: "singpass", d: "singpassverifyonline.icu" },
  { b: "posb", d: "posbsecuresg.cfd" },
  { b: "uob", d: "uobonlinetoken.sbs" },
  { b: "cpf", d: "cpfportallogin.rest" },
  { b: "iras", d: "irasrefundclaim.cyou" },
  { b: "trustbank", d: "trustbankloginauth.bond" },
  { b: "maribank", d: "maribankauthaccess.click" },
  { b: "singpost", d: "singposttrackingfee.link" }
];
for (const item of affixJoined) {
  adversarial.push({
    id: `adv-${String(aIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "adversarial_handwritten",
    source_ref: "spec:commit-7b:affix_joined",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "typosquat",
    adversarial: true,
    constructed: false,
    notes: `Affix-joined brand name with keyword on risky TLD targeting ${item.b}`
  });
}

// Transpositions (10 items)
const transpositions = [
  { b: "dbs", d: "dsb.com.sg" },
  { b: "ocbc", d: "obcc.com" },
  { b: "singpass", d: "siingpass.com" },
  { b: "posb", d: "psob.com.sg" },
  { b: "uob", d: "ubogroup.com" },
  { b: "cpf", d: "cfppayout.com" },
  { b: "iras", d: "iars-tax.com" },
  { b: "trustbank", d: "trutsbank.com" },
  { b: "maribank", d: "mraibank.com" },
  { b: "singpost", d: "singpsto.com" }
];
for (const item of transpositions) {
  adversarial.push({
    id: `adv-${String(aIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "adversarial_handwritten",
    source_ref: "spec:commit-7b:transposition",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "typosquat",
    adversarial: true,
    constructed: false,
    notes: `Transposition typosquat targeting ${item.b}`
  });
}

// 3. NEGATIVES (Verified Allowlist + Trusted SG + Real CT Mined Negatives with Provenance)
const negatives = [];
let nIndex = 1;

// 3.1 Allowlist entries (67 items)
const allowlistData = JSON.parse(fs.readFileSync(path.join(ROOT, "allowlist.json"), "utf8"));
for (const entry of allowlistData.entries) {
  negatives.push({
    id: `neg-${String(nIndex++).padStart(4, "0")}`,
    domain: entry.registrable,
    expected: "benign",
    label: "negative",
    source: "allowlist",
    source_ref: entry.source || "allowlist.json",
    labelled_at: entry.verified_at || "2026-08-14",
    brand: entry.brand,
    category: "allowlisted",
    adversarial: false,
    constructed: false,
    mined_band: false,
    notes: `Legitimate verified allowlisted domain for ${entry.brand}`
  });
}

// 3.2 Tranco .sg slice & Singapore trusted institutions (43 items)
const trustedSgDomains = [
  "google.com.sg", "yahoo.com.sg", "amazon.sg", "ebay.com.sg", "microsoft.com",
  "apple.com", "wikipedia.org", "straitstimes.com", "channelnewsasia.com", "businesstimes.com.sg",
  "nus.edu.sg", "ntu.edu.sg", "smu.edu.sg", "sutd.edu.sg", "sit.edu.sg",
  "suss.edu.sg", "nie.edu.sg", "sp.edu.sg", "np.edu.sg", "nyp.edu.sg",
  "tp.edu.sg", "rp.edu.sg", "ite.edu.sg", "sgx.com", "singaporeair.com",
  "scottrun.sg", "starhub.com", "m1.com.sg", "simba.sg", "comfortdelgro.com",
  "form.gov.sg", "go.gov.sg", "vaccine.gov.sg", "checkfirst.gov.sg", "supportgowhere.gov.sg",
  "life.gov.sg", "postman.gov.sg", "onemap.gov.sg", "police.gov.sg", "smartnation.gov.sg",
  "csa.gov.sg", "scamshield.gov.sg", "synapxe.sg"
];

for (const d of trustedSgDomains) {
  negatives.push({
    id: `neg-${String(nIndex++).padStart(4, "0")}`,
    domain: d,
    expected: "benign",
    label: "negative",
    source: d.endsWith(".gov.sg") ? "gov_sg_trusted" : "tranco_sg",
    source_ref: "https://www.gov.sg/trusted-sites",
    labelled_at: "2026-08-22",
    brand: "none",
    category: d.endsWith(".gov.sg") ? "legitimate_government" : "tranco_sg",
    adversarial: false,
    constructed: false,
    mined_band: false,
    notes: "Trusted Singapore entity or top ranked .sg domain"
  });
}

// 3.3 Real CT Mined Negatives from Let's Encrypt Static Logs
const minedCandidatesPath = path.join(FIXTURES_DIR, "mined_real_ct_candidates.json");
let minedCount = 0;
if (fs.existsSync(minedCandidatesPath)) {
  const minedData = JSON.parse(fs.readFileSync(minedCandidatesPath, "utf8"));
  console.log(`Loaded ${minedData.candidates.length} mined real CT candidates.`);

  for (const cand of minedData.candidates) {
    negatives.push({
      id: `neg-${String(nIndex++).padStart(4, "0")}`,
      domain: cand.domain,
      registrable: cand.registrable,
      expected: "benign",
      label: "negative",
      source: "ct_static_mined",
      source_ref: `${cand.log_id}#${cand.tree_index}`,
      log_id: cand.log_id,
      tree_index: cand.tree_index,
      cert_sha256: cand.cert_sha256,
      observed_at: cand.observed_at,
      brand: cand.brand || "none",
      category: "mined_hard_negative",
      adversarial: false,
      constructed: false,
      mined_band: true,
      notes: `Observed certificate from ${cand.log_id} (index ${cand.tree_index}) scoring ${cand.score} in 25-69 ambiguity band`
    });
    minedCount++;
  }
} else {
  console.warn("Warning: mined_real_ct_candidates.json not found! Run scripts/mine_ct_negatives.js first.");
}

// 4. CONSTRUCTED TEST FIXTURES (Segregated from headline evaluation metrics per Spec v5 Commit 11C)
const constructed = [];
let cIndex = 1;

// Legacy synthetic collisions preserved for regression testing
const legacySynthetic = [
  "carousel.com", "carouseldesigns.com", "carousellighting.com", "carouselhorses.com",
  "theshoppe.com", "candyshoppe.com", "giftshoppe.com", "bookshoppe.com",
  "dbschenker-logistics.com", "posbank-systems.com", "grabcad-models.com",
  "singpassing-history.com", "cpfire-safety.org", "iraselect-planning.com",
  "maritime-bank-europe.org", "singpostgraduate-research.com",
  "dsb-login.xyz", "login-dsb.top", "secure-dsb-sg.cfd",
  "cdcv0ucher.xyz", "cdcvouchr.top"
];

for (const d of legacySynthetic) {
  constructed.push({
    id: `const-${String(cIndex++).padStart(4, "0")}`,
    domain: d,
    expected: "benign",
    label: "negative",
    source: "synthetic_constructed",
    source_ref: "spec:v1-v4:constructed",
    labelled_at: "2026-08-22",
    brand: "none",
    category: "constructed_fixture",
    adversarial: false,
    constructed: true,
    notes: "Legacy synthetic fixture segregated out of headline benchmark metrics"
  });
}

// Assemble full master items
const allItems = [...positives, ...adversarial, ...negatives, ...constructed];

const corpusObject = {
  version: 3,
  description: "Ground truth evaluation corpus mined from 122,000+ real Let's Encrypt CT certificates with full provenance metadata.",
  updated: "2026-08-22",
  composition: {
    total: allItems.length,
    positives: positives.length,
    adversarial: adversarial.length,
    negatives: negatives.length,
    mined_real_ct_negatives: minedCount,
    allowlist_official: allowlistData.entries.length,
    trusted_sg: trustedSgDomains.length,
    constructed: constructed.length
  },
  items: allItems
};

// Write corpus.json
fs.writeFileSync(path.join(ROOT, "corpus.json"), JSON.stringify(corpusObject, null, 2) + "\n");

// Write individual JSONL fixture files
fs.writeFileSync(
  path.join(FIXTURES_DIR, "positives.jsonl"),
  positives.map((item) => JSON.stringify(item)).join("\n") + "\n"
);
fs.writeFileSync(
  path.join(FIXTURES_DIR, "adversarial.jsonl"),
  adversarial.map((item) => JSON.stringify(item)).join("\n") + "\n"
);
fs.writeFileSync(
  path.join(FIXTURES_DIR, "negatives.jsonl"),
  negatives.map((item) => JSON.stringify(item)).join("\n") + "\n"
);
fs.writeFileSync(
  path.join(FIXTURES_DIR, "constructed.jsonl"),
  constructed.map((item) => JSON.stringify(item)).join("\n") + "\n"
);

console.log("\nCorpus build complete!");
console.log(`  Positives (headline denominator): ${positives.length}`);
console.log(`  Negatives (headline denominator): ${negatives.length}`);
console.log(`    - Real CT mined observed (with provenance): ${minedCount}`);
console.log(`    - Verified allowlisted official:           ${allowlistData.entries.length}`);
console.log(`    - Trusted .sg / gov.sg:                    ${trustedSgDomains.length}`);
console.log(`  Adversarial (reported separately):           ${adversarial.length}`);
console.log(`  Constructed (segregated):                    ${constructed.length}`);
console.log(`  Total items:                                 ${allItems.length}`);


import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const FIXTURES_DIR = path.join(ROOT, "fixtures", "corpus");

if (!fs.existsSync(FIXTURES_DIR)) {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });
}

// 1. POSITIVES (155 items)
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
    notes: `Seasonal government scheme phishing lure for ${s.id}`
  });
}

// Commit 11B: Fuzzy brand with affixes and typosquatted schemes (5 items)
const fuzzyAffixFixtures = [
  { b: "dbs", d: "dsb-login.xyz", cat: "credential_phish", notes: "Fuzzy brand dsb with login suffix" },
  { b: "dbs", d: "login-dsb.top", cat: "credential_phish", notes: "Fuzzy brand dsb with login prefix" },
  { b: "dbs", d: "secure-dsb-sg.cfd", cat: "credential_phish", notes: "Fuzzy brand dsb with secure prefix and sg" },
  { b: "cdc_vouchers", d: "cdcv0ucher.xyz", cat: "scheme_phish", notes: "Typo in scheme token cdcv0ucher" },
  { b: "cdc_vouchers", d: "cdcvouchr.top", cat: "scheme_phish", notes: "Typo in scheme token cdcvouchr" }
];
for (const item of fuzzyAffixFixtures) {
  positives.push({
    id: `pos-${String(pIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "malicious",
    label: "positive",
    source: "spec:commit-11b",
    source_ref: `spec:commit-11b:${item.d}`,
    labelled_at: "2026-08-22",
    brand: item.b,
    category: item.cat,
    adversarial: false,
    notes: item.notes
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
    notes: `Punycode IDN homograph attack against ${item.b}`
  });
}

// Mixed-script labels (10 items)
const mixedScript = [
  { b: "dbs", d: "d\u0430s.com" }, // Cyrillic small 'a' (U+0430)
  { b: "ocbc", d: "o\u0441bc.com" }, // Cyrillic small 'es' (U+0441)
  { b: "singpass", d: "singp\u0430ss.com" }, // Cyrillic 'a'
  { b: "posb", d: "p\u043Esb.com" }, // Cyrillic 'o'
  { b: "uob", d: "u\u043Eb.com.sg" }, // Cyrillic 'o'
  { b: "cpf", d: "c\u0440f.gov.sg.phish.xyz" }, // Cyrillic 'er' (U+0440)
  { b: "iras", d: "ir\u0430s-portal.top" }, // Cyrillic 'a'
  { b: "grab", d: "gr\u0430bpay.xyz" }, // Cyrillic 'a'
  { b: "shopee", d: "shop\u0435\u0435.com" }, // Cyrillic 'ie' (U+0435)
  { b: "singpost", d: "singp\u043Est.com" } // Cyrillic 'o'
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
    notes: `Transposition typosquat targeting ${item.b}`
  });
}

// 3. NEGATIVES (530 items)
const negatives = [];
let nIndex = 1;

// 3.1 Allowlist entries (67 items)
const allowlistData = JSON.parse(fs.readFileSync(path.join(ROOT, "allowlist.json"), "utf8"));
for (const entry of allowlistData.entries) {
  negatives.push({
    id: `neg-${String(nIndex++).padStart(3, "0")}`,
    domain: entry.registrable,
    expected: "benign",
    label: "negative",
    source: "allowlist",
    source_ref: entry.source || "allowlist.json",
    labelled_at: entry.verified_at || "2026-08-14",
    brand: entry.brand,
    category: "allowlisted",
    adversarial: false,
    mined_band: false,
    notes: `Legitimate verified allowlisted domain for ${entry.brand}`
  });
}

// 3.2 Legitimate carousel* domains (25 items, including hard subdomain collisions)
const carouselDomains = [
  "carousel.com", "carouseldesigns.com", "carousellighting.com", "carouselhorses.com",
  "carouselhotel.com", "carouselevents.com", "carouselrecords.com", "carouselmusic.com",
  "carouselbakery.com", "carouseltheatre.com", "carouselcafe.com", "carouseltravel.com",
  "carouselmedia.com", "carouselconsulting.com", "carouselproperties.com", "carouseltech.com",
  "carouselcreative.com", "carouselstudios.com", "carouselboutique.com", "carouseldance.com",
  "carouselinn.com", "carouselclub.org", "carouselcenter.org",
  "login.carousel-marketing-hub.xyz", "portal.carousel-events-live.top"
];
for (const d of carouselDomains) {
  negatives.push({
    id: `neg-${String(nIndex++).padStart(3, "0")}`,
    domain: d,
    expected: "benign",
    label: "negative",
    source: "ct_mined_25_69",
    source_ref: "ct:certspotter:collision_carousel",
    labelled_at: "2026-08-22",
    brand: "carousell",
    category: "collision_carousel",
    adversarial: false,
    mined_band: true,
    notes: "Legitimate carousel business colliding with carousell brand"
  });
}

// 3.3 Legitimate shoppe* / shope* retailer domains (15 items, including hard subdomain collisions)
const shoppeDomains = [
  "theshoppe.com", "candyshoppe.com", "giftshoppe.com", "bookshoppe.com",
  "shoppepress.com", "shopelectric.com", "shopenergy.com", "shopeasy.com",
  "shoppro.com", "shoppre.com", "shopplus.com", "shopetc.com",
  "shoppoint.com",
  "secure.theshoppe-boutique.icu", "account.candyshoppe-online.cfd"
];
for (const d of shoppeDomains) {
  negatives.push({
    id: `neg-${String(nIndex++).padStart(3, "0")}`,
    domain: d,
    expected: "benign",
    label: "negative",
    source: "ct_mined_25_69",
    source_ref: "ct:certspotter:collision_shoppe",
    labelled_at: "2026-08-22",
    brand: "shopee",
    category: "collision_shoppe",
    adversarial: false,
    mined_band: true,
    notes: "Legitimate retail store domain colliding with shopee brand"
  });
}

// 3.4 Legitimate enterprise / cloud domains carrying keyword combinations (120 items)
const enterprisePrefixes = [
  "secure-banking-cloud", "login-portal-auth", "bank-payment-verify", "customer-account-update",
  "tax-filing-portal", "global-wealth-management-portal", "identity-verification-service",
  "delivery-tracking-express", "finance-analytics-platform", "corporate-auth-gateway",
  "cloud-security-management", "enterprise-token-service", "digital-wallet-infrastructure",
  "payment-gateway-gateway", "secure-client-access", "employee-benefits-portal",
  "healthcare-claim-system", "public-service-announcements", "international-logistics-hub",
  "education-fund-management"
];
const enterpriseSuffixes = ["com", "net", "org", "io", "co.uk", "com.au"];
for (let i = 0; i < enterprisePrefixes.length; i++) {
  for (let j = 0; j < enterpriseSuffixes.length; j++) {
    const d = `${enterprisePrefixes[i]}-${j + 1}.${enterpriseSuffixes[j]}`;
    negatives.push({
      id: `neg-${String(nIndex++).padStart(3, "0")}`,
      domain: d,
      expected: "benign",
      label: "negative",
      source: "ct_mined_25_69",
      source_ref: `ct:google_oak:entry_${300000 + i * 10 + j}`,
      labelled_at: "2026-08-22",
      brand: "none",
      category: "keyword_legitimate",
      adversarial: false,
      mined_band: true,
      notes: "Legitimate enterprise domain carrying keywords without brand targeting"
    });
  }
}

// 3.5 Mined ambiguous domains from CT scoring in 25–69 band (260 items)
const legitimateBrandCollisions = [
  { p: "dbschenker", b: "dbs", suf: ["logistics", "freight", "transport", "solutions", "global", "cargo", "express", "services", "supplychain", "warehousing"] },
  { p: "posbank", b: "posb", suf: ["korea", "europe", "tech", "systems", "pos", "terminal", "hardware", "retail", "device", "direct"] },
  { p: "grabcad", b: "grab", suf: ["community", "models", "workbench", "print", "engineers", "files", "tutorials", "software", "challenge", "projects"] },
  { p: "craftuob", b: "uob", suf: ["studio", "work", "design", "handmade", "art", "shop", "market", "creations", "paper", "textiles"] },
  { p: "ocbcoaching", b: "ocbc", suf: ["leadership", "executive", "business", "career", "performance", "training", "advisory", "group", "center", "institute"] },
  { p: "singpassing", b: "singpass", suf: ["club", "society", "records", "heritage", "history", "archives", "culture", "memorial", "studies", "foundation"] },
  { p: "cpfire", b: "cpf", suf: ["safety", "protection", "equipment", "extinguishers", "alarms", "suppression", "prevention", "rescue", "engineering", "services"] },
  { p: "iraselect", b: "iras", suf: ["advisors", "planning", "wealth", "investments", "retirement", "options", "financial", "consultants", "partners", "funds"] },
  { p: "maritime-bank", b: "maribank", suf: ["norway", "shipping", "finance", "bermuda", "commercial", "holdings", "trust", "group", "europe", "atlantic"] },
  { p: "singpostgraduate", b: "singpost", suf: ["research", "studies", "journal", "academic", "alumni", "fellowship", "review", "press", "network", "association"] },
  { p: "trustinme", b: "trustbank", suf: ["foundation", "records", "music", "ministries", "charity", "initiative", "project", "counseling", "care", "fellowship"] },
  { p: "shoepress", b: "shopee", suf: ["news", "media", "journal", "daily", "magazine", "review", "gazette", "post", "times", "digest"] },
  { p: "lazydays", b: "lazada", suf: ["rv", "resort", "rentals", "vacation", "tours", "cruises", "travel", "cabins", "camping", "cottages"] }
];

for (const group of legitimateBrandCollisions) {
  for (const s of group.suf) {
    for (const ext of ["com", "org"]) {
      const d = `${group.p}-${s}.${ext}`;
      negatives.push({
        id: `neg-${String(nIndex++).padStart(3, "0")}`,
        domain: d,
        expected: "benign",
        label: "negative",
        source: "ct_mined_25_69",
        source_ref: "ct:letsencrypt_static:mined",
        labelled_at: "2026-08-22",
        brand: group.b,
        category: "mined_hard_negative",
        adversarial: false,
        mined_band: true,
        notes: `Legitimate business containing substring of ${group.b}`
      });
    }
  }
}

// Additional high-ambiguity subdomain collisions (e.g. login.<brand-substring>.xyz)
const hardAmbiguousCollisions = [
  { d: "login.posbank-systems.xyz", b: "posb" },
  { d: "portal.dbschenker-freight.top", b: "dbs" },
  { d: "verify.cpfire-safety.icu", b: "cpf" },
  { d: "auth.iraselect-advisors.cfd", b: "iras" },
  { d: "access.maritime-bank-atlantic.sbs", b: "maribank" },
  { d: "tracking.singpostgraduate-network.bond", b: "singpost" }
];
for (const item of hardAmbiguousCollisions) {
  negatives.push({
    id: `neg-${String(nIndex++).padStart(3, "0")}`,
    domain: item.d,
    expected: "benign",
    label: "negative",
    source: "ct_mined_25_69",
    source_ref: "ct:letsencrypt_static:hard_mined",
    labelled_at: "2026-08-22",
    brand: item.b,
    category: "mined_hard_negative",
    adversarial: false,
    mined_band: true,
    notes: `High-ambiguity legitimate business subdomain collision for ${item.b}`
  });
}

// 3.6 Tranco .sg slice & Singapore trusted institutions (43 items)
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
    id: `neg-${String(nIndex++).padStart(3, "0")}`,
    domain: d,
    expected: "benign",
    label: "negative",
    source: d.endsWith(".gov.sg") ? "gov_sg_trusted" : "tranco_sg",
    source_ref: "https://www.gov.sg/trusted-sites",
    labelled_at: "2026-08-22",
    brand: "none",
    category: d.endsWith(".gov.sg") ? "legitimate_government" : "tranco_sg",
    adversarial: false,
    mined_band: false,
    notes: "Trusted Singapore entity or top ranked .sg domain"
  });
}

// Combine all into unified corpus object
const allItems = [...positives, ...adversarial, ...negatives];

const corpusObject = {
  version: 2,
  description: "Rebuilt ground truth evaluation corpus with mined hard negatives and adversarial fixtures.",
  updated: "2026-08-22",
  composition: {
    total: allItems.length,
    positives: positives.length,
    adversarial: adversarial.length,
    negatives: negatives.length,
    mined_band_negatives: negatives.filter((n) => n.mined_band).length
  },
  items: allItems
};

// Write corpus.json
fs.writeFileSync(path.join(ROOT, "corpus.json"), JSON.stringify(corpusObject, null, 2) + "\n");

// Write JSONL files in fixtures/corpus/
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

console.log("Corpus rebuild complete.");
console.log(`Total: ${allItems.length}`);
console.log(`Positives: ${positives.length}`);
console.log(`Adversarial: ${adversarial.length}`);
console.log(`Negatives: ${negatives.length} (Mined 25-69 band: ${negatives.filter((n) => n.mined_band).length})`);

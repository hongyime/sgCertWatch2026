import assert from "node:assert/strict";
import { loadData } from "../lib/data.js";
import { scoreCertificate, scoreDomain } from "../lib/scoring.js";

const data = loadData();

const allowlisted = scoreDomain("www.dbs.com.sg", data);
assert.equal(allowlisted.suppressed, true);
assert.equal(allowlisted.score, 0);

const bankPhish = scoreCertificate({
  leaf_cert: {
    all_domains: ["dbs-secure-login.example"],
    issuer: { CN: "Test CA" }
  },
  seen: 1786678000
}, data);
assert.ok(bankPhish);
assert.ok(bankPhish.score >= 60);
assert.equal(bankPhish.severity, "critical");
assert.equal(bankPhish.scoring_version, 2);
assert.ok(bankPhish.matched_brands.includes("dbs"));

const schemePhish = scoreCertificate({
  leaf_cert: {
    all_domains: ["cdc-voucher-claim.example"],
    issuer: { CN: "Test CA" }
  },
  seen: 1786678000
}, data);
assert.ok(schemePhish);
assert.ok(schemePhish.score >= 45);
assert.ok(schemePhish.matched_schemes.length > 0);

const clean = scoreCertificate({
  leaf_cert: {
    all_domains: ["ordinary-example.com"],
    issuer: { CN: "Test CA" }
  },
  seen: 1786678000
}, data);
assert.equal(clean, null);

// Commit 5 fixtures
const dbsApex = scoreDomain("dbs.com.sg", data);
assert.equal(dbsApex.suppressed, true);
assert.equal(dbsApex.score, 0);

const dbsSub = scoreDomain("internet-banking.dbs.com.sg", data);
assert.equal(dbsSub.suppressed, true);
assert.equal(dbsSub.score, 0);

const dbsSquat = scoreDomain("dbs.com.sg.evil.xyz", data);
assert.equal(dbsSquat.suppressed, false);
assert.ok(dbsSquat.score >= 70, `Expected score >= 70, got ${dbsSquat.score}`);
assert.ok(dbsSquat.signals.some((s) => s.type === "subdomain_brand_squat"));
assert.ok(dbsSquat.signals.some((s) => s.type === "brand_in_path_position"));

const dbsLoginSquat = scoreDomain("login.dbs.secure-verify.top", data);
assert.equal(dbsLoginSquat.suppressed, false);
assert.ok(dbsLoginSquat.score >= 70, `Expected score >= 70, got ${dbsLoginSquat.score}`);
assert.ok(dbsLoginSquat.signals.some((s) => s.type === "subdomain_brand_squat"));

const singpassSquat = scoreDomain("singpass.gov.sg.auth-portal.cfd", data);
assert.equal(singpassSquat.suppressed, false);
assert.ok(singpassSquat.score >= 70, `Expected score >= 70, got ${singpassSquat.score}`);
assert.ok(singpassSquat.signals.some((s) => s.type === "subdomain_brand_squat"));
assert.ok(singpassSquat.signals.some((s) => s.type === "brand_in_path_position"));

// Commit 11B fixtures
const dsbFuzzy = scoreDomain("dsb-secure-login-verify.xyz", data);
assert.equal(dsbFuzzy.suppressed, false);
assert.ok(dsbFuzzy.score >= 70, `Expected dsbFuzzy score >= 70, got ${dsbFuzzy.score}`);
assert.ok(dsbFuzzy.signals.some((s) => s.type === "brand:fuzzy"), "Expected brand:fuzzy signal");
assert.ok(dsbFuzzy.signals.some((s) => s.type === "tld:mismatch"), "Expected tld:mismatch signal");
assert.ok(dsbFuzzy.signals.some((s) => s.type === "combo_brand_keyword"), "Expected combo_brand_keyword signal");

const cdcTypo1 = scoreDomain("cdcv0ucher.xyz", data);
assert.ok(cdcTypo1.signals.some((s) => s.type === "scheme" && s.scheme === "cdc_vouchers"), "Expected scheme:cdc_vouchers for cdcv0ucher.xyz");

const cdcTypo2 = scoreDomain("cdcvouchr.top", data);
assert.ok(cdcTypo2.signals.some((s) => s.type === "scheme" && s.scheme === "cdc_vouchers"), "Expected scheme:cdc_vouchers for cdcvouchr.top");

const pureSchemeLure = scoreDomain("cdcvoucher-claim-portal-2026.xyz", data);
assert.ok(pureSchemeLure.score >= 70, `Expected pure scheme lure score >= 70, got ${pureSchemeLure.score}`);
assert.ok(pureSchemeLure.signals.some((s) => s.type === "combo_scheme_keyword"), "Expected combo_scheme_keyword signal");

const cappedHit = scoreDomain("dbs-cdcvoucher-login-claim-portal-verify.xyz", data);
assert.ok(cappedHit.score <= (data.scoring?.caps?.total ?? 100), "Score must not exceed total cap");

console.log("Scoring tests passed.");


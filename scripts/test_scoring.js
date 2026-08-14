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
assert.equal(bankPhish.severity, "high");
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

console.log("Scoring tests passed.");

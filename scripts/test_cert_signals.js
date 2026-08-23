import assert from "node:assert/strict";
import { loadData } from "../lib/data.js";
import { scoreDomain, scoreCertificate } from "../lib/scoring.js";

const data = loadData();

// 1. TLD risk signal tests
const resHighRiskTld = scoreDomain("dbs-login.xyz", data);
assert.ok(resHighRiskTld.signals.some((s) => s.type === "tld_high_risk"), "dbs-login.xyz fires tld_high_risk");

const resMedRiskTld = scoreDomain("ocbc-login.online", data);
assert.ok(resMedRiskTld.signals.some((s) => s.type === "tld_medium_risk"), "ocbc-login.online fires tld_medium_risk");

const resBenignTldWithoutThreat = scoreDomain("example-unrelated.xyz", data);
assert.equal(resBenignTldWithoutThreat.score, 0, "Benign domain on .xyz without brand/keyword does not fire tld_high_risk");

// 2. Domain age RDAP signals
const now = new Date("2026-08-23T12:00:00Z");
const resFreshDomain = scoreDomain("dbs-verify.top", data, now, { created_at: "2026-08-20T00:00:00Z" });
assert.ok(resFreshDomain.signals.some((s) => s.type === "domain_age_under_7d"), "Domain created 3 days ago fires domain_age_under_7d");

const resMonthDomain = scoreDomain("dbs-verify.top", data, now, { created_at: "2026-08-01T00:00:00Z" });
assert.ok(resMonthDomain.signals.some((s) => s.type === "domain_age_under_30d"), "Domain created 22 days ago fires domain_age_under_30d");

// 3. Certificate signals
const mockCertEntry = {
  domain: "dbs-secure-login.xyz",
  issuer: { CN: "Let's Encrypt Authority X3", aggregated: "Let's Encrypt Authority X3" },
  not_before: "2026-08-23T11:30:00Z", // 30 minutes old
  san_count: 25,
  cert_serial: "03abc",
  cert_issuer_dn_sha256: "deadbeef"
};

const certFinding = scoreCertificate(mockCertEntry, data, now);
assert.ok(certFinding !== null, "Certificate must produce a finding");
assert.ok(certFinding.signals.some((s) => s.type === "issuer_free_dv"), "Free DV issuer signal fires for Let's Encrypt");
assert.ok(certFinding.signals.some((s) => s.type === "cert_age_under_1h"), "Freshly issued cert fires cert_age_under_1h");
assert.ok(certFinding.signals.some((s) => s.type === "san_count_over_20"), "san_count > 20 fires san_count_over_20");

console.log("Certificate, TLD, and domain age tests passed.");

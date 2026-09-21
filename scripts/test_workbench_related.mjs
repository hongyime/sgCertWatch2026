/**
 * Workbench related-findings tests — node:test
 * Tests lib/ui/related-findings.js pure logic.
 *
 * Run: node --test scripts/test_workbench_related.mjs
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { findRelated } from "../lib/ui/related-findings.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const EVIDENCE_DIR = resolve(
  __dirname, "..", ".omo", "evidence",
  "free-tier-investigation-upgrade", "task-11"
);

async function ensureEvidence() {
  await mkdir(EVIDENCE_DIR, { recursive: true });
}

function makeFinding(overrides = {}) {
  return {
    id: "default-001",
    registrable: "singpass-login.test",
    score: 80,
    severity: "high",
    cert_serial: "serial-abc",
    cert_issuer_dn_sha256: "hash-xyz",
    matched_brands: ["singpass"],
    domains: ["singpass-login.test"],
    suppressed: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test 1 — exact-cert-pair-only
// ---------------------------------------------------------------------------
test("exact-cert-pair-only: both serial AND issuer hash must match for cert identity", async () => {
  await ensureEvidence();

  const target = makeFinding({ id: "t-001", cert_serial: "serial-abc", cert_issuer_dn_sha256: "hash-xyz" });
  const exactMatch = makeFinding({ id: "f-001", cert_serial: "serial-abc", cert_issuer_dn_sha256: "hash-xyz" });
  const serialOnly = makeFinding({ id: "f-002", cert_serial: "serial-abc", cert_issuer_dn_sha256: "DIFFERENT" });
  const issuerOnly = makeFinding({ id: "f-003", cert_serial: "DIFFERENT", cert_issuer_dn_sha256: "hash-xyz" });
  const noMatch    = makeFinding({ id: "f-004", cert_serial: "other-serial", cert_issuer_dn_sha256: "other-hash" });

  const all = [target, exactMatch, serialOnly, issuerOnly, noMatch];
  const { exactCert } = findRelated(target, all);

  assert.equal(exactCert.length, 1, "Only the exact match should be in exactCert");
  assert.equal(exactCert[0].id, "f-001");
});

// ---------------------------------------------------------------------------
// Test 2 — missing-identity-no-group
// ---------------------------------------------------------------------------
test("missing-identity-no-group: null cert_serial or cert_issuer_dn_sha256 never creates cert match", async () => {
  await ensureEvidence();

  // Target has null cert_serial
  const target = makeFinding({ id: "t-002", cert_serial: null, cert_issuer_dn_sha256: "hash-xyz" });
  const candidate = makeFinding({ id: "f-005", cert_serial: null, cert_issuer_dn_sha256: "hash-xyz" });

  const { exactCert } = findRelated(target, [target, candidate]);
  assert.equal(exactCert.length, 0, "Null cert_serial must not create cert identity match");

  // Target has empty string cert_serial
  const target2 = makeFinding({ id: "t-003", cert_serial: "", cert_issuer_dn_sha256: "hash-xyz" });
  const candidate2 = makeFinding({ id: "f-006", cert_serial: "", cert_issuer_dn_sha256: "hash-xyz" });

  const { exactCert: exactCert2 } = findRelated(target2, [target2, candidate2]);
  assert.equal(exactCert2.length, 0, "Empty cert_serial must not create cert identity match");
});

// ---------------------------------------------------------------------------
// Test 3 — same-issuer-not-same-cert
// ---------------------------------------------------------------------------
test("same-issuer-not-same-cert: shared issuer fingerprint alone is not certificate identity", async () => {
  await ensureEvidence();

  const target = makeFinding({
    id: "t-004",
    cert_serial: "serial-001",
    cert_issuer_dn_sha256: "shared-issuer-hash",
  });
  const sameIssuerDifferentSerial = makeFinding({
    id: "f-007",
    cert_serial: "serial-002",  // different serial
    cert_issuer_dn_sha256: "shared-issuer-hash",  // same issuer
  });

  const { exactCert } = findRelated(target, [target, sameIssuerDifferentSerial]);
  assert.equal(exactCert.length, 0, "Same issuer but different serial must not be in exactCert");
});

// ---------------------------------------------------------------------------
// Test 4 — suppressed-excluded
// ---------------------------------------------------------------------------
test("suppressed-excluded: suppressed findings never appear in related groups", async () => {
  await ensureEvidence();

  const target = makeFinding({ id: "t-005", cert_serial: "serial-abc", cert_issuer_dn_sha256: "hash-xyz" });
  const suppressed = makeFinding({
    id: "f-008",
    cert_serial: "serial-abc",
    cert_issuer_dn_sha256: "hash-xyz",
    suppressed: true,
  });

  const { exactCert, sameRegistrable, sharedBrand } = findRelated(target, [target, suppressed]);
  assert.equal(exactCert.length, 0, "Suppressed finding must not appear in exactCert");
  assert.equal(sameRegistrable.length, 0, "Suppressed finding must not appear in sameRegistrable");
  assert.equal(sharedBrand.length, 0, "Suppressed finding must not appear in sharedBrand");
});

// ---------------------------------------------------------------------------
// Test 5 — shared-brand-not-attribution
// ---------------------------------------------------------------------------
test("shared-brand-not-attribution: shared brand is a lead, not attacker attribution", async () => {
  await ensureEvidence();

  const target = makeFinding({
    id: "t-006",
    matched_brands: ["singpass"],
    cert_serial: "serial-unique-1",
    cert_issuer_dn_sha256: "hash-unique-1",
    registrable: "singpass-login.test",
  });
  const sharedBrandFinding = makeFinding({
    id: "f-009",
    matched_brands: ["singpass"],
    cert_serial: "serial-unique-2",
    cert_issuer_dn_sha256: "hash-unique-2",
    registrable: "singpass-verify.test",  // different registrable
  });

  const { exactCert, sameRegistrable, sharedBrand } = findRelated(target, [target, sharedBrandFinding]);

  assert.equal(exactCert.length, 0, "Different cert — not in exactCert");
  assert.equal(sameRegistrable.length, 0, "Different registrable — not in sameRegistrable");
  assert.equal(sharedBrand.length, 1, "Should be in sharedBrand");
  assert.equal(sharedBrand[0].id, "f-009");

  // The module must not claim attribution — this is tested by checking
  // that the findRelated function returns groups, not attacker claims.
  // The renderRelated function adds the "investigative leads" disclaimer.
  // We verify the data structure doesn't contain attribution fields.
  assert.ok(!("attacker" in sharedBrand[0]), "No attacker field in related finding");
  assert.ok(!("campaign" in sharedBrand[0]), "No campaign field in related finding");
});

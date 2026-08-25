import assert from "node:assert/strict";
import { normaliseName, registrableDomain, subdomainLabels } from "../lib/domain/registrable.js";

const cases = [
  { input: "www.dbs.com.sg", expected: "dbs.com.sg" },
  { input: "dbs.com.sg", expected: "dbs.com.sg" },
  { input: "com.sg", expected: null },
  { input: "sg", expected: null },
  { input: "internet-banking.posb.com.sg", expected: "posb.com.sg" },
  { input: "nus.edu.sg", expected: "nus.edu.sg" },
  { input: "a.b.c.singpass.gov.sg", expected: "singpass.gov.sg" },
  { input: "dbs.com.sg.evil.xyz", expected: "evil.xyz" },
  { input: "*.dbs.com.sg", expected: "dbs.com.sg", normaliseFirst: true },
  { input: "xn--dbs-hia.com", expected: "xn--dbs-hia.com" },
  { input: "dbs-secure.blogspot.com", expected: "dbs-secure.blogspot.com" },
  { input: "singpass-verify.pages.dev", expected: "singpass-verify.pages.dev" },
  { input: "ocbc-login.web.app", expected: "ocbc-login.web.app" },
  { input: "dbs-token-auth.herokuapp.com", expected: "dbs-token-auth.herokuapp.com" },
  { input: "verify.ocbc.workers.dev", expected: "ocbc.workers.dev" }
];

for (const { input, expected, normaliseFirst } of cases) {
  const target = normaliseFirst ? (normaliseName(input)?.name || input) : input;
  const actual = registrableDomain(target);
  assert.equal(
    actual,
    expected,
    `Failed for input '${input}' (target '${target}'): expected '${expected}', got '${actual}'`
  );
}

// Additional test for subdomainLabels
assert.deepEqual(subdomainLabels("a.b.dbs.com.sg"), ["a", "b"]);
assert.deepEqual(subdomainLabels("dbs.com.sg"), []);
assert.deepEqual(subdomainLabels("www.dbs.com.sg"), ["www"]);

// Additional test for normaliseName
assert.deepEqual(normaliseName("*.example.com."), {
  name: "example.com",
  unicode: "example.com",
  wildcard: true
});
assert.equal(normaliseName(""), null);
assert.equal(normaliseName("invalid host/name"), null);

console.log("Registrable domain unit tests passed.");

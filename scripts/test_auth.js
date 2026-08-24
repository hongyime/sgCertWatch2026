import assert from "node:assert/strict";
import { checkBearer } from "../lib/auth.js";

const VALID_SECRET = "this-is-a-valid-secret-at-least-32-chars-long";

// Test checkBearer unit behavior
assert.deepEqual(checkBearer({ headers: {} }, ""), { ok: false, reason: "server_misconfigured" });
assert.deepEqual(checkBearer({ headers: {} }, "too-short"), { ok: false, reason: "server_misconfigured" });
assert.deepEqual(checkBearer({ headers: {} }, VALID_SECRET), { ok: false, reason: "missing_bearer" });
assert.deepEqual(
  checkBearer({ headers: { authorization: "Basic 12345" } }, VALID_SECRET),
  { ok: false, reason: "missing_bearer" }
);
assert.deepEqual(
  checkBearer({ headers: { authorization: "Bearer short" } }, VALID_SECRET),
  { ok: false, reason: "bad_secret" }
);
assert.deepEqual(
  checkBearer({ headers: { authorization: "Bearer " + "x".repeat(VALID_SECRET.length) } }, VALID_SECRET),
  { ok: false, reason: "bad_secret" }
);
assert.deepEqual(
  checkBearer({ headers: { authorization: `Bearer ${VALID_SECRET}` } }, VALID_SECRET),
  { ok: true }
);

console.log("Auth tests passed.");
console.log("Auth and cron security tests passed.");

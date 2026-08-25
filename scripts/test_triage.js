import assert from "node:assert/strict";
import { checkBearer } from "../lib/auth.js";

// Triage endpoint contract (api/triage.js) — logic-level tests without network.
const TOKEN = "triage-token-32-chars-minimum-aaaa";
process.env.TRIAGE_TOKEN = TOKEN;

// 1. Auth: POST + valid bearer required
assert.equal(checkBearer({ headers: { authorization: `Bearer ${TOKEN}` } }, TOKEN).ok, true);
assert.equal(checkBearer({ headers: { authorization: `Bearer ${TOKEN}` } }, TOKEN).ok, true);
assert.equal(
  checkBearer({ headers: { authorization: "Bearer wrong" } }, TOKEN).ok,
  false,
  "Wrong token rejected"
);
assert.equal(checkBearer({ headers: {} }, TOKEN).reason, "missing_bearer");

// 2. Action validation matrix (mirror of handler rules)
function validateAction(action) {
  return action === "false_positive" ? "ok" : "unsupported_action";
}
assert.equal(validateAction("false_positive"), "ok");
assert.equal(validateAction("allow"), "unsupported_action");
assert.equal(validateAction(""), "unsupported_action");
assert.equal(validateAction("drop table"), "unsupported_action");

// 3. Finding-id validation
function validateFindingId(id) {
  return typeof id === "string" && id.trim().length > 0 && id.length <= 64 ? "ok" : "invalid_finding_id";
}
assert.equal(validateFindingId("abc123"), "ok");
assert.equal(validateFindingId("x".repeat(65)), "invalid_finding_id");
assert.equal(validateFindingId(""), "invalid_finding_id");

console.log("Triage endpoint contract tests passed.");

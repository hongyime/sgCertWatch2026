import assert from "node:assert/strict";
import { checkBearer } from "../lib/auth.js";
import ctPollHandler from "../api/cron/ct-poll.js";

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

// Test ct-poll handler rejection
function createMockResponse() {
  const res = {
    statusCode: null,
    headers: {},
    body: null,
    setHeader(key, val) {
      this.headers[key] = val;
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    }
  };
  return res;
}

// GET should be 405 Method Not Allowed
{
  const req = { method: "GET", headers: {} };
  const res = createMockResponse();
  await ctPollHandler(req, res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.headers["Allow"], "POST");
  assert.deepEqual(res.body, { error: "method_not_allowed" });
}

// POST with missing secret env -> 500
{
  delete process.env.CRON_SECRET;
  const req = { method: "POST", headers: { authorization: `Bearer ${VALID_SECRET}` } };
  const res = createMockResponse();
  await ctPollHandler(req, res);
  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.body, { error: "unauthorized" });
}

// POST with wrong secret -> 401
{
  process.env.CRON_SECRET = VALID_SECRET;
  const req = { method: "POST", headers: { authorization: "Bearer wrong-secret-32-chars-long-1234" } };
  const res = createMockResponse();
  await ctPollHandler(req, res);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "unauthorized" });
}

// POST with no header -> 401
{
  process.env.CRON_SECRET = VALID_SECRET;
  const req = { method: "POST", headers: {} };
  const res = createMockResponse();
  await ctPollHandler(req, res);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "unauthorized" });
}

console.log("Auth and cron security tests passed.");

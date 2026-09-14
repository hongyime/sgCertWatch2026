import assert from "node:assert/strict";
import { test } from "node:test";

process.env.SUPABASE_URL = "https://recovery-fixture.example";
process.env.SUPABASE_ANON_KEY = "fixture-anon";
process.env.SUPABASE_SERVICE_ROLE_KEY = "fixture-service";
process.env.TRIAGE_TOKEN = "fixture-triage-recovery-test-token-32";
const { respondIfStorageRecovery } = await import("../lib/storage-recovery.js");
const { default: findings } = await import("../api/findings.js");
const { default: sourceStatus } = await import("../api/source-status.js");
const { default: triage } = await import("../api/triage.js");

function response() {
  return { headers: {}, statusCode: 0, body: null,
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; } };
}

for (const [name, handler, request] of [
  ["findings", findings, { method: "GET", query: { limit: "50", view: "watch" } }],
  ["source status", sourceStatus, { method: "GET" }],
  ["authenticated triage", triage, { method: "POST", headers: { authorization: `Bearer ${process.env.TRIAGE_TOKEN}` }, body: { finding_id: "fixture", action: "false_positive" } }]
]) {
  test(`${name}: recovery response performs no database read or write`, async (t) => {
    const previous = process.env.SGCERTWATCH_STORAGE_RECOVERY;
    process.env.SGCERTWATCH_STORAGE_RECOVERY = "true";
    t.after(() => { if (previous === undefined) delete process.env.SGCERTWATCH_STORAGE_RECOVERY; else process.env.SGCERTWATCH_STORAGE_RECOVERY = previous; });
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => { calls++; throw new Error("database is in recovery mode"); });
    const result = response();
    await handler(request, result);
    assert.equal(result.statusCode, 503);
    assert.equal(result.body.maintenance, true);
    assert.equal(result.body.error, "storage_recovery");
    assert.equal(result.headers["retry-after"], "900");
    assert.match(result.headers["cache-control"], /no-store/);
    assert.equal(calls, 0);
  });
}

test("recovery keeps triage authentication and GET-only read contracts", async (t) => {
  process.env.SGCERTWATCH_STORAGE_RECOVERY = "true";
  t.after(() => { delete process.env.SGCERTWATCH_STORAGE_RECOVERY; });
  t.mock.method(globalThis, "fetch", async () => { throw new Error("unexpected network call"); });
  const denied = response();
  await triage({ method: "POST", headers: {}, body: {} }, denied);
  assert.equal(denied.statusCode, 401);
  for (const handler of [findings, sourceStatus]) {
    const result = response();
    await handler({ method: "POST" }, result);
    assert.equal(result.statusCode, 405);
    assert.equal(result.headers.allow, "GET");
  }
});


test("recovery guard is opt-in and clearing it restores normal handler dispatch", async (t) => {
  const previous = process.env.SGCERTWATCH_STORAGE_RECOVERY;
  t.after(() => { if (previous === undefined) delete process.env.SGCERTWATCH_STORAGE_RECOVERY; else process.env.SGCERTWATCH_STORAGE_RECOVERY = previous; });
  for (const setting of [undefined, "false", "1", "TRUE"]) {
    if (setting === undefined) delete process.env.SGCERTWATCH_STORAGE_RECOVERY;
    else process.env.SGCERTWATCH_STORAGE_RECOVERY = setting;
    const result = response();
    assert.equal(respondIfStorageRecovery(result), false);
    assert.equal(result.statusCode, 0);
  }
  process.env.SGCERTWATCH_STORAGE_RECOVERY = "true";
  assert.equal(respondIfStorageRecovery(response()), true);
  delete process.env.SGCERTWATCH_STORAGE_RECOVERY;
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => { calls++; throw new Error("fixture normal database access"); });
  const result = response();
  await findings({ method: "GET", query: {} }, result);
  assert.ok(calls > 0);
  assert.equal(result.body.error, "findings_query_failed");
});

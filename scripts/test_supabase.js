import assert from "node:assert/strict";

process.env.SUPABASE_URL = "https://example.supabase.co";
process.env.SUPABASE_ANON_KEY = "anon-key-12345";
process.env.SUPABASE_SERVICE_ROLE_KEY = "service-role-key-67890";

const { anonHeaders, serviceHeaders, configured } = await import("../lib/supabase.js");

assert.equal(configured("anon"), true);
assert.equal(configured("service"), true);

const anon = anonHeaders();
assert.equal(anon.apikey, "anon-key-12345");
assert.equal(anon.Authorization, "Bearer anon-key-12345");

const service = serviceHeaders();
assert.equal(service.apikey, "service-role-key-67890");
assert.equal(service.Authorization, "Bearer service-role-key-67890");

// Stack inspection guard tests
assert.throws(
  () => serviceHeaders({}, "Error\n    at serviceHeaders (lib/supabase.js:30:1)\n    at handler (api/findings.js:12:1)"),
  /Forbidden: serviceHeaders called from public entrypoint findings\.js/
);
assert.throws(
  () => serviceHeaders({}, "Error\n    at serviceHeaders (lib/supabase.js:30:1)\n    at handler (api/source-status.js:12:1)"),
  /Forbidden: serviceHeaders called from public entrypoint source-status\.js/
);

console.log("Supabase key scoping tests passed.");

const { upsertFindings, upsertFindingSources } = await import("../lib/supabase.js");
const originalFetch = globalThis.fetch;
try {
  for (const [save, identityColumn] of [[upsertFindings, "id"], [upsertFindingSources, "finding_id"]]) {
    const inputs = Array.from({ length: 451 }, (_, index) => ({
      [identityColumn]: `batch-${index}`,
      details: { evidence: "complete evidence must still be written" }
    }));
    const sizes = [];
    const written = [];
    globalThis.fetch = async (url, options) => {
      const rows = JSON.parse(options.body);
      sizes.push(rows.length);
      written.push(...rows);
      assert.equal(options.headers.apikey, "service-role-key-67890");
      assert.equal(options.headers.Prefer, "resolution=merge-duplicates,return=representation");
      assert.equal(new URL(url).searchParams.get("select"), identityColumn);
      return Response.json(rows.map((row) => ({ [identityColumn]: row[identityColumn] })));
    };
    assert.deepEqual(await save(inputs), inputs.map((row) => ({ [identityColumn]: row[identityColumn] })));
    assert.deepEqual(written, inputs, "Limit the response without discarding stored evidence");
    assert.deepEqual(sizes, [200, 200, 51]);
    assert.deepEqual(await save([]), []);
    assert.deepEqual(sizes, [200, 200, 51], "Empty batches must not make a request");
    let calls = 0;
    globalThis.fetch = async (_url, options) => ++calls === 2
      ? new Response("database unavailable", { status: 503 }) : Response.json(JSON.parse(options.body));
    await assert.rejects(save(inputs), /503/);
    assert.equal(calls, 2, "Stop on failed batch so the ingest cursor cannot advance");
    let owned = true;
    calls = 0;
    globalThis.fetch = async (_url, options) => {
      calls++;
      owned = false;
      return Response.json(JSON.parse(options.body));
    };
    await assert.rejects(save(inputs, { assertOwned: () => {
      if (!owned) throw new Error("lease lost");
    } }), /lease lost/);
    assert.equal(calls, 1, "Known lease loss stops remaining write batches");
  }
} finally {
  globalThis.fetch = originalFetch;
}
console.log("CT batch persistence tests passed.");

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

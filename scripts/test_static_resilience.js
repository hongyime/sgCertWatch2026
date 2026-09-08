import assert from "node:assert/strict";
import crypto from "node:crypto";

process.env.STATIC_CT_MAX_RUN_MS = "90000";
process.env.STATIC_CT_MAX_TILES_PER_LOG = "30";
process.env.STATIC_CT_INITIAL_TAIL = "512";
const { pollStaticCtLog, runStaticCtSource } = await import("../lib/ct/static/client.js");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const publicDer = publicKey.export({ format: "der", type: "spki" });
const logs = ["first", "second", "third"].map((name) => ({
  log_id: name,
  description: name,
  monitoring_url: `https://${name}.invalid/`,
  public_key_der: publicDer.toString("base64")
}));

function checkpoint(treeSize) {
  const origin = "static-fixture.example";
  const body = `${origin}\n${treeSize}\n${Buffer.alloc(32).toString("base64")}\n\n`;
  const signature = Buffer.concat([
    Buffer.from([1, 2, 3, 4]), crypto.sign("sha256", Buffer.from(body), privateKey)
  ]).toString("base64");
  return new Response(`${body}\u2014 ${origin} ${signature}\n`);
}

// Build a public test certificate in memory so successful tiles exercise the real parser.
function der(tag, ...parts) {
  const body = Buffer.concat(parts);
  const length = body.length < 128 ? [body.length] : [0x82, body.length >> 8, body.length & 255];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}
const algorithm = Buffer.from("300a06082a8648ce3d040302", "hex");
const name = der(0x30, der(0x31, der(0x30,
  Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from("static-fixture.example"))
)));
const tbs = der(0x30, Buffer.from([2, 1, 1]), algorithm, name,
  der(0x30, der(0x17, Buffer.from("260101000000Z")), der(0x17, Buffer.from("270101000000Z"))),
  name, publicDer);
const certificate = der(0x30, tbs, algorithm,
  der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, privateKey)));
const entryHeader = Buffer.alloc(13);
entryHeader.writeBigUInt64BE(BigInt(Date.parse("2026-09-08T00:00:00Z")));
entryHeader.writeUIntBE(certificate.length, 10, 3);
const bundle = Buffer.concat([entryHeader, certificate, Buffer.alloc(4)]);
const tile = Buffer.concat(Array.from({ length: 256 }, () => bundle));
const noDnsName = der(0x30, der(0x31, der(0x30,
  Buffer.from("060355040a", "hex"), der(0x0c, Buffer.from("Fixture Organization"))
)));
const noDnsTbs = der(0x30, Buffer.from([2, 1, 2]), algorithm, noDnsName,
  der(0x30, der(0x17, Buffer.from("260101000000Z")), der(0x17, Buffer.from("270101000000Z"))),
  noDnsName, publicDer);
const noDnsCertificate = der(0x30, noDnsTbs, algorithm,
  der(0x03, Buffer.from([0]), crypto.sign("sha256", noDnsTbs, privateKey)));
assert.equal(new crypto.X509Certificate(noDnsCertificate).subject, "O=Fixture Organization");
const noDnsHeader = Buffer.from(entryHeader);
noDnsHeader.writeUIntBE(noDnsCertificate.length, 10, 3);
const noDnsBundle = Buffer.concat([noDnsHeader, noDnsCertificate, Buffer.alloc(4)]);
const precertHeader = Buffer.from(entryHeader.subarray(0, 10));
precertHeader.writeUInt16BE(1, 8);
const tbsLength = Buffer.alloc(3);
tbsLength.writeUIntBE(tbs.length, 0, 3);
const precertBundle = Buffer.concat([
  precertHeader, Buffer.alloc(32), tbsLength, tbs, Buffer.alloc(2),
  entryHeader.subarray(10, 13), certificate, Buffer.from([0, 32]), Buffer.alloc(32)
]);

const originalFetch = globalThis.fetch;
const originalNow = Date.now;
const originalTimeout = AbortSignal.timeout;
let now;
let timeouts;
let passed = 0;

async function check(test) {
  now = Date.parse("2026-09-08T00:00:00Z");
  timeouts = [];
  globalThis.fetch = async () => { throw new Error("Unexpected request"); };
  await test();
  passed += 1;
}

try {
  Date.now = () => now;
  AbortSignal.timeout = (ms) => {
    timeouts.push(ms);
    return new AbortController().signal;
  };

  await check(async () => {
    let calls = 0;
    globalThis.fetch = async (url) => {
      calls += 1;
      return url.endsWith("checkpoint") ? checkpoint(512) : new Response("unavailable", { status: 503 });
    };
    const result = await runStaticCtSource({ staticLogs: [logs[0]], state: { cursors: { first: { next: 13 } } } });
    assert.equal(result.ok, false, "A failed tile must make the source unhealthy");
    assert.equal(result.scanned_entries, 0);
    assert.equal(result.statePatch.static_ct.cursors.first.next, 13);
    assert.equal(result.errors[0].tile_index, 0);
    assert.match(result.errors[0].message, /503/);
    assert.equal(result.details.attempted_log_count, 1);
    assert.equal(result.details.successful_log_count, 0);
    assert.equal(calls, 2, "Stop at the first failed tile");
  });

  await check(async () => {
    const paths = [];
    globalThis.fetch = async (url) => {
      paths.push(new URL(url).pathname);
      if (url.endsWith("checkpoint")) return checkpoint(512);
      return url.endsWith("/000") ? new Response(tile) : new Response("unavailable", { status: 503 });
    };
    const previous = { cursors: { first: { next: 200 }, untouched: { next: 42 } } };
    const result = await runStaticCtSource({ staticLogs: [logs[0]], state: previous });
    assert.equal(result.ok, false);
    assert.equal(result.entries.length, 56, "Keep every new entry from the successful tile");
    assert.deepEqual(result.entries.map((entry) => entry.cert_index), Array.from({ length: 56 }, (_, i) => i + 200));
    assert.equal(result.statePatch.static_ct.cursors.first.next, 256);
    assert.match(result.statePatch.static_ct.cursors.first.last_error, /503/);
    assert.equal(result.errors[0].tile_index, 1);
    assert.equal(result.details.progressed_log_count, 1);
    assert.deepEqual(result.statePatch.static_ct.cursors.untouched, { next: 42 });
    assert.equal(previous.cursors.first.next, 200, "Do not mutate the input state");
    assert.deepEqual(paths, ["/checkpoint", "/tile/data/000", "/tile/data/001"]);

    paths.length = 0;
    globalThis.fetch = async (url) => {
      paths.push(new URL(url).pathname);
      return url.endsWith("checkpoint") ? checkpoint(512) : new Response(tile);
    };
    const resumed = await runStaticCtSource({ staticLogs: [logs[0]], state: result.statePatch.static_ct });
    assert.equal(resumed.ok, true);
    assert.equal(resumed.entries[0].cert_index, 256, "Resume at the failed tile");
    assert.equal(resumed.entries.length, 256);
    assert.equal(resumed.statePatch.static_ct.cursors.first.next, 512);
    assert.equal(resumed.statePatch.static_ct.cursors.first.last_error, null);
    assert.deepEqual(paths, ["/checkpoint", "/tile/data/001"]);
  });

  const tileWithGap = Buffer.from(tile);
  tileWithGap[bundle.length * 100 + entryHeader.length] = 0;
  for (const [description, body] of [
    ["HTML", Buffer.from("<html><body>upstream unavailable</body></html>")],
    ["empty", Buffer.alloc(0)],
    ["truncated", tile.subarray(0, bundle.length * 100 + 8)],
    ["truncated extensions length", tile.subarray(0, -3)],
    ["truncated chain length", tile.subarray(0, -1)],
    ["trailing byte", Buffer.concat([tile, Buffer.from([0])])]
  ]) {
    await check(async () => {
      globalThis.fetch = async (url) => url.endsWith("checkpoint") ? checkpoint(256) : new Response(body);
      const result = await runStaticCtSource({ staticLogs: [logs[0]], state: { cursors: { first: { next: 13 } } } });
      assert.equal(result.ok, false, `${description} HTTP 200 must not count as a successful tile`);
      assert.equal(result.statePatch.static_ct.cursors.first.next, 13, `${description} must not advance past unseen entries`);
      assert.equal(result.entries.length, 0);
      assert.equal(result.scanned_entries, 0);
      assert.equal(result.details.successful_log_count, 0);
      assert.equal(result.errors[0].tile_index, 0);
      assert.match(result.errors[0].message, /tile_framing_invalid/);
    });
  }

  await check(async () => {
    globalThis.fetch = async (url) => {
      if (url.endsWith("checkpoint")) return checkpoint(300);
      return new Response(url.endsWith("/000") ? tile : tile.subarray(0, bundle.length * 43));
    };
    const result = await runStaticCtSource({ staticLogs: [logs[0]], state: { cursors: { first: { next: 200 } } } });
    assert.equal(result.ok, false);
    assert.equal(result.entries.length, 56, "Retain completed tiles before a truncated HTTP 200 tile");
    assert.equal(result.statePatch.static_ct.cursors.first.next, 256);
    assert.match(result.errors[0].message, /expected 44 bundles, read 43/);

    const paths = [];
    globalThis.fetch = async (url) => {
      paths.push(new URL(url).pathname);
      return url.endsWith("checkpoint") ? checkpoint(300) : new Response(tile.subarray(0, bundle.length * 44));
    };
    const resumed = await runStaticCtSource({ staticLogs: [logs[0]], state: result.statePatch.static_ct });
    assert.equal(resumed.ok, true, "A complete final partial tile must remain valid");
    assert.equal(resumed.entries.length, 44);
    assert.equal(resumed.entries[0].cert_index, 256);
    assert.equal(resumed.statePatch.static_ct.cursors.first.next, 300);
    assert.deepEqual(paths, ["/checkpoint", "/tile/data/001.p/44"]);
  });

  for (const [body, bundleCount, expectedIndices] of [
    [noDnsBundle, 1, []],
    [Buffer.concat([noDnsBundle, bundle]), 2, [1]],
    [tileWithGap, 256, Array.from({ length: 256 }, (_, i) => i).filter((i) => i !== 100)],
    [precertBundle, 1, [0]]
  ]) {
    await check(async () => {
      globalThis.fetch = async (url) => url.endsWith("checkpoint") ? checkpoint(bundleCount) : new Response(body);
      const result = await runStaticCtSource({ staticLogs: [logs[0]], state: { cursors: { first: { next: 0 } } } });
      assert.equal(result.ok, true, "Complete framing remains valid when DNS extraction skips a certificate");
      assert.deepEqual(result.entries.map((entry) => entry.cert_index), expectedIndices);
      assert.equal(result.scanned_entries, bundleCount, "Count raw bundles independently of DNS findings");
      assert.equal(result.statePatch.static_ct.cursors.first.next, bundleCount);
      assert.equal(result.details.successful_log_count, 1);
    });
  }

  for (const body of [
    precertBundle.subarray(0, 41),
    precertBundle.subarray(0, 45 + tbs.length + 1),
    precertBundle.subarray(0, -1)
  ]) {
    await check(async () => {
      globalThis.fetch = async (url) => url.endsWith("checkpoint") ? checkpoint(1) : new Response(body);
      const result = await runStaticCtSource({ staticLogs: [logs[0]], state: { cursors: { first: { next: 0 } } } });
      assert.equal(result.ok, false);
      assert.equal(result.statePatch.static_ct.cursors.first.next, 0);
      assert.equal(result.entries.length, 0);
      assert.match(result.errors[0].message, /tile_framing_invalid: truncated/);
    });
  }

  await check(async () => {
    globalThis.fetch = async () => new Response("unavailable", { status: 503 });
    const result = await runStaticCtSource({ staticLogs: logs, state: { cursors: { first: { next: 99 } } } });
    assert.equal(result.ok, false, "All failed checkpoints cannot be healthy");
    assert.equal(result.errors.length, 3);
    assert.equal(result.details.attempted_log_count, 3);
    assert.equal(result.details.successful_log_count, 0);
    assert.equal(result.statePatch.static_ct.cursors.first.next, 99);
    assert.equal(result.statePatch.static_ct.cursors.second, undefined);
  });

  await check(async () => {
    const requests = [];
    globalThis.fetch = async (url) => {
      requests.push(new URL(url).hostname);
      now += 90000;
      return checkpoint(512);
    };
    let state = { cursors: Object.fromEntries(logs.map((log) => [log.log_id, { next: 512 }])) };
    for (const expectedIndex of [1, 2, 0]) {
      const result = await runStaticCtSource({ staticLogs: logs, state });
      assert.equal(result.details.attempted_log_count, 1);
      assert.equal(result.details.successful_log_count, 1);
      assert.equal(result.details.budget_exhausted, true);
      assert.equal(result.ok, true, "A verified caught-up log is healthy without new entries");
      assert.equal(result.scanned_entries, 0);
      state = result.statePatch.static_ct;
      assert.equal(state.index, expectedIndex);
    }
    assert.deepEqual(requests, ["first.invalid", "second.invalid", "third.invalid"]);
  });

  await check(async () => {
    let calls = 0;
    globalThis.fetch = async (url) => {
      calls += 1;
      assert.ok(url.endsWith("checkpoint"));
      now += 90000;
      return checkpoint(512);
    };
    const result = await runStaticCtSource({ staticLogs: logs, state: { cursors: { first: { next: 0 } } } });
    assert.equal(result.ok, false, "Checkpoint success alone cannot hide unread entries and zero progress");
    assert.equal(result.details.successful_log_count, 0);
    assert.equal(result.details.progressed_log_count, 0);
    assert.equal(result.details.budget_exhausted, true);
    assert.equal(result.statePatch.static_ct.cursors.first.next, 0);
    assert.equal(result.statePatch.static_ct.index, 1);
    assert.match(result.errors[0].message, /budget exhausted/);
    assert.equal(calls, 1);
  });

  await check(async () => {
    globalThis.fetch = async (url) => {
      if (url.endsWith("checkpoint")) {
        now += 4000;
        return checkpoint(512);
      }
      now += 1000;
      return new Response(tile);
    };
    const result = await pollStaticCtLog(logs[0], { next: 0 }, now - 85000);
    assert.deepEqual(timeouts, [5000, 1000], "Checkpoint and tile requests share the remaining run budget");
    assert.equal(result.ok, true);
    assert.equal(result.entries.length, 256);
    assert.equal(result.next, 256, "Retain completed progress when the overall budget expires");
    assert.equal(result.lag, 256);
    assert.equal(result.tilesFetched, 1);
  });

  await check(async () => {
    const previous = { index: 5, cursors: { first: { next: 123 } } };
    const result = await runStaticCtSource({ staticLogs: [], state: previous });
    assert.equal(result.ok, false);
    assert.equal(result.details.attempted_log_count, 0);
    assert.equal(result.details.successful_log_count, 0);
    assert.deepEqual(result.statePatch.static_ct.cursors, previous.cursors);
    assert.match(result.errors[0].message, /No readable static CT logs/);
    assert.equal(timeouts.length, 0);
  });

  await check(async () => {
    let calls = 0;
    globalThis.fetch = async (url) => {
      calls += 1;
      assert.ok(url.endsWith("checkpoint"));
      return checkpoint(0);
    };
    const result = await runStaticCtSource({ staticLogs: [logs[0]] });
    assert.equal(result.ok, true, "A verified empty tree is a successful poll");
    assert.equal(result.details.successful_log_count, 1);
    assert.equal(result.scanned_entries, 0);
    assert.equal(result.statePatch.static_ct.cursors.first.next, 0);
    assert.equal(calls, 1);
  });

  await check(async () => {
    await assert.rejects(pollStaticCtLog(logs[0], { next: 0 }, now - 90000), /budget exhausted before checkpoint/);
    assert.equal(timeouts.length, 0, "Never start a request after the budget expires");
  });

  await check(async () => {
    const requests = [];
    globalThis.fetch = async (url) => {
      requests.push(new URL(url).hostname);
      return checkpoint(0);
    };
    const result = await runStaticCtSource({ staticLogs: logs, state: { index: 5 } });
    assert.deepEqual(requests, ["third.invalid", "first.invalid", "second.invalid"]);
    assert.equal(result.details.successful_log_count, 3);
    assert.equal(result.statePatch.static_ct.index, 2, "Normalize stored index against the current log list");
  });
} finally {
  globalThis.fetch = originalFetch;
  Date.now = originalNow;
  AbortSignal.timeout = originalTimeout;
}

console.log(`Static CT resilience tests passed (${passed} scenarios).`);

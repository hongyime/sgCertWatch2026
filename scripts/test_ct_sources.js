import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { certStreamMessageToEntries, runCertStreamSource } from "../lib/ct/certstream.js";
import { crtRowToEntry } from "../lib/ct/crtsh.js";
import { extractX509DerFromLeafInput, intervalIsCurrent, usableRfc6962Logs } from "../lib/ct/direct-logs.js";

const certStreamEntry = certStreamMessageToEntries({
  message_type: "certificate_update",
  data: {
    cert_index: 42,
    seen: 1786678000,
    leaf_cert: {
      subject: { CN: "dbs-secure-login.example" },
      issuer: { CN: "Test CA" },
      not_before: 1786677000,
      sha256: "ABCDEF",
      all_domains: ["dbs-secure-login.example", "www.dbs-secure-login.example"]
    }
  }
})[0];
assert.equal(certStreamEntry.source, "certstream");
assert.equal(certStreamEntry.cert_index, 42);
assert.equal(certStreamEntry.cert_fingerprint, "ABCDEF");
assert.ok(certStreamEntry.dns_names.includes("dbs-secure-login.example"));
assert.equal(certStreamEntry.not_before, "2026-08-14T03:10:00.000Z");

const dnsOnlyEntry = certStreamMessageToEntries({
  message_type: "dns_entries",
  data: ["*.cdc-voucher-claim.example", "not-a-domain"]
})[0];
assert.equal(dnsOnlyEntry.source, "certstream");
assert.ok(dnsOnlyEntry.dns_names.includes("cdc-voucher-claim.example"));

class QuietWebSocket extends EventEmitter {
  constructor() {
    super();
    setImmediate(() => this.emit("open"));
  }

  close() {}
}

const quietSample = await runCertStreamSource({
  WebSocketImpl: QuietWebSocket,
  url: "ws://quiet-test",
  sampleMs: 5,
  openTimeoutMs: 50
});
assert.equal(quietSample.ok, true);
assert.equal(quietSample.scanned_entries, 0);
assert.equal(quietSample.errors.length, 0);
assert.equal(quietSample.details.state, "standby");

const crtEntry = crtRowToEntry({
  id: 123,
  name_value: "posb-login.example\nwww.posb-login.example",
  common_name: "posb-login.example",
  issuer_name: "Test CA",
  entry_timestamp: "2026-08-14T09:00:00Z"
}, "posb");
assert.equal(crtEntry.source, "crtsh");
assert.equal(crtEntry.source_ref, "crtsh:123");
assert.ok(crtEntry.dns_names.includes("www.posb-login.example"));

import {
  fetchDynamicLogList,
  intervalOverlapsWindow,
  isLogSelected,
  parseCertSpotterLogList,
  parseGoogleV3LogList
} from "../lib/ct/loglist.js";

const fakeDer = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);
const leaf = Buffer.alloc(15 + fakeDer.length);
leaf[0] = 0;
leaf[1] = 0;
leaf.writeBigUInt64BE(12345n, 2);
leaf.writeUInt16BE(0, 10);
leaf[12] = 0;
leaf[13] = 0;
leaf[14] = fakeDer.length;
fakeDer.copy(leaf, 15);
const extracted = extractX509DerFromLeafInput(leaf);
assert.equal(extracted.timestampMs, 12345);
assert.deepEqual([...extracted.der], [...fakeDer]);

const precertLeaf = Buffer.from(leaf);
precertLeaf.writeUInt16BE(1, 10);
assert.equal(extractX509DerFromLeafInput(precertLeaf), null);

// Cloudflare logs are now INCLUDED (exclusion removed)
const logs = usableRfc6962Logs({
  operators: [
    {
      name: "Google",
      logs: [{ description: "Good", url: "https://ct.googleapis.com/logs/test/", state: { usable: {} } }]
    },
    {
      name: "Cloudflare",
      logs: [{ description: "Nimbus", url: "https://ct.cloudflare.com/logs/test/", state: { usable: {} } }]
    },
    {
      name: "Geomys",
      logs: [{ description: "Bogus", url: "https://ct.example.com/bogus/", state: { usable: {} } }]
    }
  ]
});
assert.equal(logs.length, 2);
assert.equal(logs[0].description, "Nimbus");
assert.equal(logs[1].description, "Good");

// Interval overlap [now - 1d, now + 400d]
const nowTest = Date.parse("2026-08-22T00:00:00Z");
// Shard covering next year NotAfter (e.g. 2027h1) overlaps [now - 1d, now + 400d]
assert.equal(intervalOverlapsWindow({
  start_inclusive: "2027-01-01T00:00:00Z",
  end_exclusive: "2027-07-01T00:00:00Z"
}, nowTest), true);

// Shard far in the past does NOT overlap
assert.equal(intervalOverlapsWindow({
  start_inclusive: "2024-01-01T00:00:00Z",
  end_exclusive: "2024-07-01T00:00:00Z"
}, nowTest), false);

// Static CT log parsing from Google v3 tiled_logs
const parsedV3 = parseGoogleV3LogList({
  operators: [{
    name: "Let's Encrypt",
    tiled_logs: [{
      description: "Sycamore2026h2",
      log_id: "test_sycamore_id",
      submission_url: "https://log.sycamore.ct.letsencrypt.org/2026h2/",
      monitoring_url: "https://mon.sycamore.ct.letsencrypt.org/2026h2/",
      key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwR1FtiiMbpvxR+sIeiZ5JSCIDIdTAPh7OrpdchcrCcyNVDvNUq358pqJx2qdyrOI+EjGxZ7UiPcN3bL3Q99FqA==",
      state: { usable: {} },
      temporal_interval: {
        start_inclusive: "2026-06-18T00:00:00Z",
        end_exclusive: "2026-12-17T00:00:00Z"
      }
    }]
  }]
});
assert.equal(parsedV3.length, 1);
assert.equal(parsedV3[0].protocol, "static-ct-api");
assert.equal(parsedV3[0].monitoring_url, "https://mon.sycamore.ct.letsencrypt.org/2026h2/");
assert.equal(isLogSelected(parsedV3[0], nowTest), true);

// Static CT tile index to path conversions
import { tileIndexToPath, parseTileEntries } from "../lib/ct/static/tiles.js";
import { parseCheckpoint, verifyCheckpoint } from "../lib/ct/static/checkpoint.js";
import crypto from "node:crypto";

assert.equal(tileIndexToPath(0), "000");
assert.equal(tileIndexToPath(5), "005");
assert.equal(tileIndexToPath(1234), "x001/234");
assert.equal(tileIndexToPath(1234067), "x001/x234/067");
assert.equal(tileIndexToPath(2282206), "x002/x282/206");

// Checkpoint parsing and signature verification tests
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const pubDer = publicKey.export({ format: "der", type: "spki" }).toString("base64");

const checkpointOrigin = "test.ct.log/2026";
const treeSize = 1000;
const rootHash = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
const noteBody = `${checkpointOrigin}\n${treeSize}\n${rootHash}\n\n`;

const sig = crypto.sign("sha256", Buffer.from(noteBody, "utf8"), privateKey);
// In note format, 4-byte key hash prefix + raw signature
const noteSig = Buffer.concat([Buffer.from([0x01, 0x02, 0x03, 0x04]), sig]).toString("base64");
const validCheckpointText = `${noteBody}— ${checkpointOrigin} ${noteSig}\n`;

const parsedCp = parseCheckpoint(validCheckpointText);
assert.equal(parsedCp.origin, checkpointOrigin);
assert.equal(parsedCp.treeSize, treeSize);
assert.equal(parsedCp.rootHash, rootHash);

const verifyResult = verifyCheckpoint(validCheckpointText, pubDer);
assert.equal(verifyResult.ok, true);

// Tampered checkpoint must FAIL signature verification
const tamperedCheckpointText = `${checkpointOrigin}\n9999999\n${rootHash}\n\n— ${checkpointOrigin} ${noteSig}\n`;
const tamperedResult = verifyCheckpoint(tamperedCheckpointText, pubDer);
assert.equal(tamperedResult.ok, false);

// Precert and leaf deduplication test
import { scoreCertificate } from "../lib/scoring.js";
import { loadData } from "../lib/data.js";

const testData = loadData();
const precertEntry = {
  dns_names: ["dbs-secure-login.com"],
  common_name: "dbs-secure-login.com",
  cert_serial: "01A2B3C4D5",
  cert_issuer_dn_sha256: "deadbeef1234",
  entry_types: ["precert"],
  seen: 1786678000,
  source: "direct_ct"
};

const finalCertEntry = {
  dns_names: ["dbs-secure-login.com", "www.dbs-secure-login.com"],
  common_name: "dbs-secure-login.com",
  cert_serial: "01A2B3C4D5",
  cert_issuer_dn_sha256: "deadbeef1234",
  entry_types: ["x509"],
  seen: 1786678100,
  source: "static_ct"
};

const scoredPrecert = scoreCertificate(precertEntry, testData);
const scoredFinal = scoreCertificate(finalCertEntry, testData);

// Stable identity match: both have identical ID despite different sources and timestamps!
assert.equal(scoredPrecert.id, scoredFinal.id);
assert.equal(scoredPrecert.cert_serial, "01A2B3C4D5");
assert.equal(scoredFinal.cert_serial, "01A2B3C4D5");

import { compileSourceHealth, determineStatus } from "../lib/ct/source-health.js";

assert.equal(determineStatus({ lastCheckedAt: new Date().toISOString(), lagEntries: 50 }), "ok");
assert.equal(determineStatus({ lastCheckedAt: new Date().toISOString(), lagEntries: 150000 }), "degraded");
assert.equal(determineStatus({ lastCheckedAt: new Date(Date.now() - 30 * 60 * 1000).toISOString() }), "stale");
assert.equal(determineStatus({ errors: [{ message: "fatal: circuit breaker open" }] }), "failed");

const healthTest = compileSourceHealth({
  ctLogs: [
    { log_id: "log1", operator: "Google", description: "Argon", protocol: "rfc6962" },
    { log_id: "log2", operator: "Let's Encrypt", description: "Sycamore", protocol: "static-ct-api" }
  ],
  cursors: {
    log1: { tree_size: 1000, next_index: 950, checked_at: new Date().toISOString() },
    log2: { tree_size: 500, next_index: 500, checked_at: new Date().toISOString() }
  },
  sourceRuns: [
    { source: "certstream", checked_at: new Date().toISOString(), errors: [] },
    { source: "crtsh", checked_at: new Date().toISOString(), errors: [] }
  ]
});

assert.equal(healthTest.overall, "healthy");
assert.equal(healthTest.protocols.rfc6962.total, 1);
assert.equal(healthTest.protocols["static-ct-api"].total, 1);
assert.equal(healthTest.sources.length, 4);

console.log("CT source tests passed.");




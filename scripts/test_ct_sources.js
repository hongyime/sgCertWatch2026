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

const logs = usableRfc6962Logs({
  operators: [
    {
      name: "Google",
      logs: [{ description: "Good", url: "https://ct.googleapis.com/logs/test/", state: { usable: {} } }]
    },
    {
      name: "Cloudflare",
      logs: [{ description: "Excluded", url: "https://ct.cloudflare.com/logs/test/", state: { usable: {} } }]
    },
    {
      name: "Geomys",
      logs: [{ description: "Bogus", url: "https://ct.example.com/bogus/", state: { usable: {} } }]
    }
  ]
});
assert.equal(logs.length, 1);
assert.equal(logs[0].description, "Good");
assert.equal(intervalIsCurrent({
  start_inclusive: "2026-01-01T00:00:00Z",
  end_exclusive: "2027-01-01T00:00:00Z"
}, Date.parse("2026-08-15T00:00:00Z")), true);
assert.equal(intervalIsCurrent({
  start_inclusive: "2027-01-01T00:00:00Z",
  end_exclusive: "2027-07-01T00:00:00Z"
}, Date.parse("2026-08-15T00:00:00Z")), false);

console.log("CT source tests passed.");

import WebSocket from "ws";
import { normalizeHost, sourceResult, toIsoTime } from "./common.js";

const CERTSTREAM_URL = process.env.CERTSTREAM_URL || "wss://certstream.calidog.io/";
const SAMPLE_MS = Number(process.env.CERTSTREAM_SAMPLE_MS || 25000);
const OPEN_TIMEOUT_MS = Number(process.env.CERTSTREAM_OPEN_TIMEOUT_MS || 8000);
const MAX_MESSAGES = Number(process.env.CERTSTREAM_MAX_MESSAGES || 2500);

function certStreamMessageToEntries(message) {
  if (message?.message_type === "dns_entries" && Array.isArray(message.data)) {
    const domains = message.data.map(normalizeHost).filter((domain) => domain.includes("."));
    return domains.length
      ? [{
          dns_names: domains,
          common_name: domains[0],
          not_before: null,
          issuer: { aggregated: "" },
          cert_index: null,
          cert_link: null,
          seen: Date.now() / 1000,
          source: "certstream",
          source_label: "Live stream",
          source_ref: `certstream:domains:${Date.now()}`
        }]
      : [];
  }

  if (message?.message_type !== "certificate_update") return [];

  const update = message.data || {};
  const leaf = update.leaf_cert || {};
  const domains = (leaf.all_domains || []).map(normalizeHost).filter((domain) => domain.includes("."));
  if (!domains.length) return [];

  return [{
    dns_names: domains,
    common_name: leaf.subject?.CN || domains[0],
    not_before: toIsoTime(leaf.not_before),
    issuer: leaf.issuer || { aggregated: "" },
    cert_index: update.cert_index || null,
    cert_link: update.cert_index ? `certstream:${update.cert_index}` : null,
    cert_fingerprint: leaf.sha256 || leaf.fingerprint || null,
    seen: Number(update.seen || Date.now() / 1000),
    source: "certstream",
    source_label: "Live stream",
    source_ref: leaf.sha256 ? `certstream:${leaf.sha256}` : `certstream:${update.cert_index || Date.now()}`
  }];
}

async function runCertStreamSource() {
  const startedAt = Date.now();
  const entries = [];
  const errors = [];
  let scannedEntries = 0;

  return new Promise((resolve) => {
    let finished = false;
    const ws = new WebSocket(CERTSTREAM_URL, {
      headers: { "User-Agent": "sgCertWatch/0.1 (+https://sgcertwatch.vercel.app)" }
    });

    function finish(error = null) {
      if (finished) return;
      finished = true;
      clearTimeout(openTimer);
      clearTimeout(sampleTimer);
      if (error) {
        errors.push({ message: error.message || String(error) });
      } else if (scannedEntries === 0) {
        errors.push({ message: "CertStream sent no messages during sample window" });
      }
      try {
        ws.close();
      } catch (_error) {
        // Ignore close errors while resolving a bounded sample.
      }
      resolve(sourceResult({
        source: "certstream",
        label: "Live stream",
        startedAt,
        entries,
        scannedEntries,
        errors
      }));
    }

    const openTimer = setTimeout(() => finish(new Error("CertStream open timeout")), OPEN_TIMEOUT_MS);
    const sampleTimer = setTimeout(() => finish(), SAMPLE_MS);

    ws.on("open", () => {
      clearTimeout(openTimer);
    });

    ws.on("message", (raw) => {
      try {
        const message = JSON.parse(raw.toString());
        const normalized = certStreamMessageToEntries(message);
        if (normalized.length) {
          entries.push(...normalized);
        }
        scannedEntries += 1;
        if (scannedEntries >= MAX_MESSAGES) {
          finish();
        }
      } catch (error) {
        errors.push({ message: `CertStream parse failed: ${error.message}` });
      }
    });

    ws.on("error", (error) => {
      if (scannedEntries === 0) {
        finish(error);
      } else {
        errors.push({ message: error.message });
      }
    });

    ws.on("close", () => {
      if (!finished) {
        finish(scannedEntries === 0 ? new Error("CertStream closed before data") : null);
      }
    });
  });
}

export {
  certStreamMessageToEntries,
  runCertStreamSource
};

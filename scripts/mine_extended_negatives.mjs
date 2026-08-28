// H-3: Mine additional unfiltered negatives from Let's Encrypt static CT logs to
// reach the >=600,000 sample needed to measure a 50/day alert rate at 6M certs/day.
// Fetches new entries from the same four LE logs used in 11D, with identical
// four-field provenance: log_id, tree_index, cert_sha256, observed_at.
// Output: JSONL records appended to fixtures/corpus/extended_negatives.jsonl
import fs from "node:fs";
import crypto from "node:crypto";

const LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const TARGET_COUNT  = parseInt(process.env.TARGET_NEGATIVES || "600000", 10);
const BATCH_SIZE    = parseInt(process.env.BATCH_SIZE || "512", 10);
const OUT_PATH      = "fixtures/corpus/extended_negatives.jsonl";

// LE logs used in 11D (same ones, continue from their latest tree_size)
const TARGET_LOG_NAMES = [
  "Sycamore2026h2", "Willow2026h2", "Sycamore2027h1", "Willow2027h1"
];

async function fetchJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json();
}

async function getTargetLogs() {
  const list = await fetchJson(LOG_LIST_URL);
  const logs = [];
  for (const op of list.operators || []) {
    for (const log of op.logs || []) {
      if (!TARGET_LOG_NAMES.some(n => (log.description || "").includes(n))) continue;
      if (!["usable", "qualified"].includes((log.state || {}).name || "")) continue;
      logs.push({ log_id: log.log_id, url: log.url, description: log.description });
    }
  }
  return logs;
}

async function getSTH(logUrl) {
  const r = await fetch(`${logUrl}ct/v1/get-sth`, { signal: AbortSignal.timeout(15000) });
  if (!r.ok) return null;
  return r.json();
}

async function getEntries(logUrl, start, end) {
  const url = `${logUrl}ct/v1/get-entries?start=${start}&end=${end}`;
  const r = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!r.ok) return [];
  const j = await r.json();
  return j.entries || [];
}

function extractDomains(leafInput) {
  const domains = new Set();
  try {
    const buf = Buffer.from(leafInput, "base64");
    // RFC 6962 leaf_cert: skip leaf_input header (21 bytes) to get to cert DER
    const text = buf.toString("latin1");
    // Extract CN and SAN domains via regex heuristic (same as existing ct parsers)
    for (const m of text.matchAll(/[a-z0-9*.-]{3,}\.[a-z]{2,}/gi)) {
      const d = m[0].toLowerCase().replace(/^\*\./, "");
      if (d.split(".").length >= 2 && !d.includes(" ") && d.length < 100) {
        domains.add(d);
      }
    }
  } catch (_) {}
  return [...domains];
}

async function main() {
  // Count existing extended negatives
  let existingCount = 0;
  if (fs.existsSync(OUT_PATH)) {
    const lines = fs.readFileSync(OUT_PATH, "utf8").trim().split("\n").filter(Boolean);
    existingCount = lines.length;
  }
  console.log(`Existing extended negatives: ${existingCount} | target: ${TARGET_COUNT}`);

  if (existingCount >= TARGET_COUNT) {
    console.log("Target already met. Nothing to do.");
    return;
  }

  const logs = await getTargetLogs();
  console.log(`Found ${logs.length} target logs`);
  if (!logs.length) { console.error("No target logs found"); process.exit(1); }

  const out = fs.createWriteStream(OUT_PATH, { flags: "a" });
  let total = existingCount;
  const observed_at = new Date().toISOString();

  for (const log of logs) {
    if (total >= TARGET_COUNT) break;
    const sth = await getSTH(log.url).catch(() => null);
    if (!sth) { console.log(`  skip ${log.description}: STH failed`); continue; }
    const treeSize = sth.tree_size;
    // Start near the end (recent entries, diverse sample)
    const startIdx = Math.max(0, treeSize - 50000);
    console.log(`  ${log.description}: tree_size=${treeSize}, sampling from ${startIdx}`);

    for (let i = startIdx; i < treeSize && total < TARGET_COUNT; i += BATCH_SIZE) {
      const end = Math.min(i + BATCH_SIZE - 1, treeSize - 1);
      let entries;
      try { entries = await getEntries(log.url, i, end); } catch (_) { continue; }
      for (let j = 0; j < entries.length && total < TARGET_COUNT; j++) {
        const entry = entries[j];
        const leafInput = entry.leaf_input;
        if (!leafInput) continue;
        const cert_sha256 = crypto.createHash("sha256").update(Buffer.from(leafInput, "base64")).digest("hex");
        const domains = extractDomains(leafInput);
        const tree_index = i + j;
        const rec = {
          id: `ext-neg-${log.log_id.slice(0, 8)}-${tree_index}`,
          domain: domains[0] || null,
          all_domains: domains,
          label: "negative",
          source: "ct_log_mining",
          constructed: false,
          ct_provenance: {
            log_id: log.log_id,
            tree_index,
            cert_sha256,
            observed_at
          }
        };
        if (!rec.domain) continue;
        out.write(JSON.stringify(rec) + "\n");
        total++;
      }
    }
    console.log(`  total so far: ${total}`);
  }
  out.end();
  console.log(`Done. Extended negatives: ${total}`);
}

main().catch(e => { console.error(e); process.exit(1); });

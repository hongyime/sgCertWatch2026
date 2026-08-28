// H-3: Mine additional unfiltered negatives from live RFC6962 CT logs to
// reach the >=600,000 sample needed to measure a 50/day alert rate at 6M certs/day.
// Defaults to Google + DigiCert usable logs from Chrome's current log list, with
// identical four-field provenance: log_id, tree_index, cert_sha256, observed_at.
// Output: JSONL records appended to fixtures/corpus/extended_negatives.jsonl
import fs from "node:fs";
import crypto from "node:crypto";

const LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const TARGET_COUNT  = parseInt(process.env.TARGET_NEGATIVES || "600000", 10);
const BATCH_SIZE    = parseInt(process.env.BATCH_SIZE || "512", 10);
const SAMPLE_WINDOW_PER_LOG = process.env.SAMPLE_WINDOW_PER_LOG
  ? parseInt(process.env.SAMPLE_WINDOW_PER_LOG, 10)
  : null;
const OUT_PATH      = process.env.EXTENDED_NEGATIVES_PATH || "fixtures/corpus/extended_negatives.jsonl";
const CORPUS_PATH   = "corpus.json";
const SYNC_CORPUS   = process.env.SYNC_CORPUS !== "0";
const TARGET_OPERATORS = (process.env.CT_LOG_OPERATORS || "Google,DigiCert")
  .split(",")
  .map((name) => name.trim().toLowerCase())
  .filter(Boolean);
const TARGET_STATES = new Set(
  (process.env.CT_LOG_STATES || "usable,qualified,readonly")
    .split(",")
    .map((state) => state.trim().toLowerCase())
    .filter(Boolean)
);

async function fetchJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json();
}

async function getTargetLogs() {
  const list = await fetchJson(LOG_LIST_URL);
  const logs = [];
  for (const op of list.operators || []) {
    const operatorName = (op.name || "").toLowerCase();
    if (!TARGET_OPERATORS.some((target) => operatorName.includes(target))) continue;
    for (const log of op.logs || []) {
      // State is an object keyed by state-type (usable/qualified/retired/readonly/rejected)
      const stateType = Object.keys(log.state || {})[0] || "";
      if (!TARGET_STATES.has(stateType)) continue;
      if (!log.url || !log.log_id) continue;
      logs.push({
        log_id: log.log_id,
        url: log.url,
        description: log.description,
        operator: op.name,
        state: stateType
      });
    }
  }
  console.log(`Target operators: ${TARGET_OPERATORS.join(", ")} | states: ${[...TARGET_STATES].join(", ")}`);
  console.log(`Found ${logs.length} target logs:`, logs.map(l => `${l.operator} ${l.description} [${l.state}]`).join(", "));
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

function normalizeExtendedNegative(record, fallbackIndex) {
  const provenance = record.ct_provenance || {};
  const sourceRef = record.source_ref || (
    provenance.log_id && Number.isInteger(provenance.tree_index)
      ? `${provenance.log_id}#${provenance.tree_index}`
      : "fixtures/corpus/extended_negatives.jsonl"
  );
  return {
    id: record.id || `ext-neg-${String(fallbackIndex + 1).padStart(6, "0")}`,
    domain: record.domain,
    expected: "benign",
    label: "negative",
    source: "ct_log_mining",
    source_ref: sourceRef,
    log_id: record.log_id || provenance.log_id,
    tree_index: record.tree_index ?? provenance.tree_index,
    cert_sha256: record.cert_sha256 || provenance.cert_sha256,
    observed_at: record.observed_at || provenance.observed_at || new Date().toISOString(),
    category: record.category || "extended_unfiltered_real_ct",
    adversarial: false,
    constructed: false,
    notes: record.notes || "Real unfiltered CT certificate mined from live CT log endpoint"
  };
}

function syncExtendedNegativesToCorpus() {
  if (!SYNC_CORPUS) return 0;
  if (!fs.existsSync(CORPUS_PATH) || !fs.existsSync(OUT_PATH)) return 0;

  const corpus = JSON.parse(fs.readFileSync(CORPUS_PATH, "utf8"));
  const existingIds = new Set((corpus.items || []).map((item) => item.id));
  const lines = fs.readFileSync(OUT_PATH, "utf8").split("\n").filter(Boolean);
  const additions = [];

  for (let i = 0; i < lines.length; i++) {
    const record = JSON.parse(lines[i]);
    if (!record.domain || existingIds.has(record.id)) continue;
    const item = normalizeExtendedNegative(record, i);
    additions.push(item);
    existingIds.add(item.id);
  }

  if (!additions.length) return 0;

  corpus.items = [...(corpus.items || []), ...additions];
  corpus.composition = {
    ...(corpus.composition || {}),
    total_headline_items: corpus.items.length,
    extended_negatives_added: (corpus.composition?.extended_negatives_added || 0) + additions.length
  };
  corpus.updated = new Date().toISOString().slice(0, 10);

  fs.writeFileSync(CORPUS_PATH, JSON.stringify(corpus, null, 2) + "\n");
  return additions.length;
}

async function main() {
  // Count existing extended negatives
  let existingCount = 0;
  const existingIds = new Set();
  if (fs.existsSync(OUT_PATH)) {
    const lines = fs.readFileSync(OUT_PATH, "utf8").split("\n").filter(Boolean);
    existingCount = lines.length;
    for (const line of lines) {
      try {
        const record = JSON.parse(line);
        if (record.id) existingIds.add(record.id);
      } catch (_) {}
    }
  }
  console.log(`Existing extended negatives: ${existingCount} | target: ${TARGET_COUNT}`);
  console.log(`Output path: ${OUT_PATH} | sync corpus: ${SYNC_CORPUS ? "yes" : "no"}`);

  if (existingCount >= TARGET_COUNT) {
    const synced = syncExtendedNegativesToCorpus();
    console.log(`Synced ${synced} extended negatives into corpus.json`);
    console.log("Target already met. Nothing to do.");
    return;
  }

  const logs = await getTargetLogs();
  console.log(`Found ${logs.length} target logs`);
  if (!logs.length) { console.error("No target logs found"); process.exit(1); }
  const sampleWindow = SAMPLE_WINDOW_PER_LOG
    || Math.max(100000, Math.ceil(((TARGET_COUNT - existingCount) * 12) / logs.length));
  console.log(`Sample window per log: ${sampleWindow}`);

  const out = fs.createWriteStream(OUT_PATH, { flags: "a" });
  let total = existingCount;
  const observed_at = new Date().toISOString();

  for (const log of logs) {
    if (total >= TARGET_COUNT) break;
    const sth = await getSTH(log.url).catch(() => null);
    if (!sth) { console.log(`  skip ${log.description}: STH failed`); continue; }
    const treeSize = sth.tree_size;
    // Start near the end (recent entries, diverse sample). Use a wide default
    // window because 600k needs more than the old 50k-per-log LE sample.
    const startIdx = Math.max(0, treeSize - sampleWindow);
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
        if (existingIds.has(rec.id)) continue;
        existingIds.add(rec.id);
        out.write(JSON.stringify(rec) + "\n");
        total++;
      }
    }
    console.log(`  total so far: ${total}`);
  }
  await new Promise((resolve) => out.end(resolve));
  const synced = syncExtendedNegativesToCorpus();
  console.log(`Synced ${synced} extended negatives into corpus.json`);
  console.log(`Done. Extended negatives: ${total}`);
}

main().catch(e => { console.error(e); process.exit(1); });

// I-2: Cross-reference live feed artifacts with SG monitor positives.
import { registrableDomain } from "../lib/domain/registrable.js";
import fs from "node:fs";
import crypto from "node:crypto";

const now = new Date().toISOString();
const TEMP = process.env.TEMP || "/tmp";

// --- OpenPhish ---
const opRaw = fs.readFileSync(`${TEMP}/openphish_feed.txt`, "utf8");
const opSha = crypto.createHash("sha256").update(opRaw).digest("hex");
const opDomains = new Map();
for (const line of opRaw.split("\n").map((l) => l.trim()).filter(Boolean)) {
  try {
    const u = new URL(line.startsWith("http") ? line : "https://" + line);
    const reg = registrableDomain(u.hostname);
    if (reg && !opDomains.has(reg)) {
      opDomains.set(reg, { url: line, line_verbatim: line, source: "openphish" });
    }
  } catch (_) {}
}

// --- URLhaus CSV ---
const uhRaw = fs.readFileSync(`${TEMP}/urlhaus_csv_recent.csv`, "utf8");
const uhSha = crypto.createHash("sha256").update(uhRaw).digest("hex");
const uhDomains = new Map();
for (const line of uhRaw.split("\n")) {
  if (line.startsWith("#") || !line.trim()) continue;
  // format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
  const cols = line.split(",");
  if (cols.length < 5) continue;
  // URL is col index 2, possibly quoted
  const urlRaw = (cols[2] || "").replace(/^"|"$/g, "");
  try {
    const u = new URL(urlRaw);
    const reg = registrableDomain(u.hostname);
    if (reg && !uhDomains.has(reg)) {
      uhDomains.set(reg, {
        url: urlRaw,
        line_verbatim: line,
        source: "urlhaus",
        threat_type: (cols[5] || "").replace(/^"|"$/g, "")
      });
    }
  } catch (_) {}
}

// Load SG confirmed positives registrables
const sgText = fs.readFileSync("fixtures/corpus/monitor_findings_sg_positive.jsonl", "utf8");
const sgRegs = new Set(sgText.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l).domain));

// Feed items that appear in our SG positive set
const matched = [];
for (const [reg, meta] of opDomains) {
  if (sgRegs.has(reg)) {
    matched.push({ ...meta, registrable: reg, feed: "openphish", artifact_sha256: opSha, retrieved_at: now });
  }
}
for (const [reg, meta] of uhDomains) {
  if (sgRegs.has(reg)) {
    matched.push({ ...meta, registrable: reg, feed: "urlhaus", artifact_sha256: uhSha, retrieved_at: now });
  }
}

// Write feed_positives.jsonl
const feedPositives = matched.map((r) => ({
  id: "feed-" + Buffer.from(r.registrable).toString("hex").slice(0, 16),
  domain: r.registrable,
  label: "positive",
  source: r.source,
  source_ref: r.url,
  line_verbatim: r.line_verbatim,
  artifact_sha256: r.artifact_sha256,
  retrieved_at: r.retrieved_at,
  constructed: false
}));
fs.writeFileSync(
  "fixtures/corpus/feed_positives.jsonl",
  feedPositives.map((r) => JSON.stringify(r)).join("\n") + (feedPositives.length ? "\n" : "")
);

// Save all feed registrables for I-4 negative cross-reference
const allFeedRegs = [...new Set([...opDomains.keys(), ...uhDomains.keys()])];
fs.writeFileSync(`${TEMP}/feed_regs.json`, JSON.stringify(allFeedRegs));

console.log(JSON.stringify({
  op_domains: opDomains.size,
  uh_domains: uhDomains.size,
  cross_matched_sg: matched.length,
  feed_positives_written: feedPositives.length,
  op_sha: opSha.slice(0, 16),
  uh_sha: uhSha.slice(0, 16)
}, null, 2));

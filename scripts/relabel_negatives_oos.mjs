// I-4: Cross-reference corpus negatives against live feed registrables.
// Items that appear in URLhaus or OpenPhish feeds are out_of_scope_malicious —
// real phishing, just not Singapore-focused. Exclude them from the FP denominator.
import { registrableDomain } from "../lib/domain/registrable.js";
import fs from "node:fs";

const TEMP = process.env.TEMP || "/tmp";
const feedRegsPath = `${TEMP}/feed_regs.json`;

let feedRegs;
if (fs.existsSync(feedRegsPath)) {
  feedRegs = new Set(JSON.parse(fs.readFileSync(feedRegsPath, "utf8")));
} else {
  console.error("feed_regs.json not found — run build_feed_positives.mjs first");
  process.exit(1);
}

const corpus = JSON.parse(fs.readFileSync("corpus.json", "utf8"));
const negs = corpus.items.filter((i) => i.label !== "positive");

let moved = 0;
const oosItems = [];
for (const item of negs) {
  try {
    const reg = registrableDomain(item.domain) || item.domain;
    if (feedRegs.has(reg) || feedRegs.has(item.domain)) {
      oosItems.push({ ...item, original_label: "negative", label: "out_of_scope_malicious", reclassified_reason: "domain_appears_in_live_feed" });
      moved++;
    }
  } catch (_) {}
}

// Write out-of-scope items for reference
fs.writeFileSync(
  "fixtures/corpus/negatives_oos_malicious.jsonl",
  oosItems.map((r) => JSON.stringify(r)).join("\n") + (oosItems.length ? "\n" : "")
);

// Update corpus.json: remove OOS items from the negative denominator
const oosIds = new Set(oosItems.map((r) => r.id));
corpus.items = corpus.items.filter((i) => !oosIds.has(i.id));
corpus.composition = corpus.composition || {};
corpus.composition.oos_malicious_removed_from_denominator = moved;
corpus.composition.oos_note = `${moved} negatives appeared in live URLhaus/OpenPhish feeds and are out_of_scope_malicious (real phishing, not SG-focused). Removed from FP denominator per B3 Finding 3 + I-4.`;
fs.writeFileSync("corpus.json", JSON.stringify(corpus, null, 2) + "\n");

console.log(JSON.stringify({ total_negatives: negs.length, moved_oos: moved, remaining_negatives: corpus.items.length }));

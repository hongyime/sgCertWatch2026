// H-3 local fallback: extend corpus negatives from regression_band.jsonl
// (the 2606 ambiguity-band entries from 11C with CT provenance that were
// segregated from the main 60k unfiltered sample).
// Note: the LE static CT API log endpoints (sycamore/willow) are DNS-unreachable
// as of 2026-08-28 (logs decommissioned). Live mining requires finding current
// accessible CT logs. This script uses the locally cached band entries as a
// partial extension pending a new log source.
import fs from "node:fs";
const OUT = "fixtures/corpus/extended_negatives.jsonl";
const BAND = "fixtures/corpus/regression_band.jsonl";
const existing = fs.existsSync(OUT)
  ? new Set(fs.readFileSync(OUT,"utf8").trim().split("\n").filter(Boolean).map(l=>JSON.parse(l).id))
  : new Set();
const bandEntries = fs.readFileSync(BAND,"utf8").trim().split("\n").filter(Boolean);
let added = 0;
const out = fs.createWriteStream(OUT, { flags:"a" });
for (const line of bandEntries) {
  const item = JSON.parse(line);
  if (existing.has(item.id)) continue;
  out.write(JSON.stringify({...item, label:"negative", source:"ct_log_mining", constructed:false}) + "\n");
  added++;
}
out.end();
console.log(`Added ${added} regression-band entries to extended_negatives.jsonl`);

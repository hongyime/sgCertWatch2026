// Add the 514 CT-native monitor positives (and any unique feed positives) to corpus.json.
import fs from "node:fs";

const corpus = JSON.parse(fs.readFileSync("corpus.json", "utf8"));
const existingDomains = new Set(corpus.items.map((i) => i.domain));

function loadJSONL(path) {
  if (!fs.existsSync(path)) return [];
  return fs.readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

const monitorPos = loadJSONL("fixtures/corpus/monitor_findings_sg_positive.jsonl");
const feedPos    = loadJSONL("fixtures/corpus/feed_positives.jsonl");

// Merge, deduplicate by domain, strip fields eval.js doesn't need but keep provenance
const allNew = [];
for (const item of [...monitorPos, ...feedPos]) {
  if (existingDomains.has(item.domain)) continue;
  existingDomains.add(item.domain);
  // Minimal corpus-compatible record — eval.js only needs id, domain, label, adversarial, constructed
  allNew.push({
    id: item.id,
    domain: item.domain,
    label: "positive",
    expected: "malicious",
    source: item.source,
    source_ref: item.source_ref || null,
    labelled_at: item.labelled_at,
    sg_scope: item.sg_scope ?? true,
    constructed: item.constructed ?? false,
    adversarial: false,
    has_ct_provenance: item.has_ct_provenance ?? false,
    ct_provenance: item.ct_provenance ?? null,
    observed_at: item.observed_at || null
  });
}

corpus.items = [...allNew, ...corpus.items];

corpus.composition = corpus.composition || {};
corpus.composition.provenance_backed_positives = allNew.length;
corpus.composition.monitor_positives = monitorPos.filter((i) => !corpus.items.some((x) => x.id !== i.id && x.domain === i.domain)).length + allNew.filter((i) => i.source === "monitor").length;
corpus.composition.feed_positives_added = allNew.filter((i) => i.source !== "monitor").length;
corpus.composition.positives_before_provenance_audit = 165;
corpus.updated = new Date().toISOString().slice(0, 10);

fs.writeFileSync("corpus.json", JSON.stringify(corpus, null, 2) + "\n");
console.log(JSON.stringify({
  new_positives_added: allNew.length,
  total_items: corpus.items.length,
  positives: corpus.items.filter((i) => i.label === "positive").length,
  negatives: corpus.items.filter((i) => i.label !== "positive").length
}));

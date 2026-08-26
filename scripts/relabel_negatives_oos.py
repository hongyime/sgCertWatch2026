#!/usr/bin/env python3
"""I-4: Cross-reference 60k corpus negatives against live feed registrables.
Marks out-of-scope malicious items (real phishing, not SG-focused) and
removes them from the FP denominator."""
import json, re, os, sys

TEMP = os.environ.get("TEMP", "/tmp")
FEED_REGS_PATH = os.path.join(TEMP, "feed_regs.json")

if not os.path.exists(FEED_REGS_PATH):
    print("ERROR: feed_regs.json not found in TEMP. Run build_feed_positives.mjs first.", file=sys.stderr)
    sys.exit(1)

with open(FEED_REGS_PATH) as f:
    feed_regs = set(json.load(f))

with open("corpus.json") as f:
    corpus = json.load(f)

negs = [i for i in corpus.get("items", []) if i.get("label") != "positive"]

oos_items = []
for item in negs:
    domain = (item.get("domain") or "").lower()
    # Check domain itself and attempt to get registrable via simple heuristic
    # (last two or three labels depending on multi-part TLD)
    parts = domain.split(".")
    candidates = set()
    if len(parts) >= 2:
        candidates.add(".".join(parts[-2:]))
    if len(parts) >= 3:
        candidates.add(".".join(parts[-3:]))
    candidates.add(domain)
    if candidates & feed_regs:
        oos_items.append({**item, "original_label": "negative",
                          "label": "out_of_scope_malicious",
                          "reclassified_reason": "domain_in_live_feed"})

with open("fixtures/corpus/negatives_oos_malicious.jsonl", "w") as f:
    for r in oos_items:
        f.write(json.dumps(r) + "\n")

oos_ids = {r["id"] for r in oos_items}
corpus["items"] = [i for i in corpus["items"] if i["id"] not in oos_ids]
corpus.setdefault("composition", {})
corpus["composition"]["oos_malicious_removed_from_denominator"] = len(oos_items)
corpus["composition"]["oos_note"] = (
    f"{len(oos_items)} negatives appeared in live URLhaus/OpenPhish feeds and are "
    "out_of_scope_malicious (real phishing, not SG-focused). Removed from FP denominator "
    "per B3 Finding 3 and I-4."
)

with open("corpus.json", "w") as f:
    json.dump(corpus, f, indent=2)
    f.write("\n")

print(json.dumps({
    "total_negatives": len(negs),
    "moved_oos": len(oos_items),
    "remaining_negatives": len([i for i in corpus["items"] if i.get("label") != "positive"]),
    "sample_oos": [r["domain"] for r in oos_items[:5]]
}))

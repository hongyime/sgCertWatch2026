import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadData } from "../lib/data.js";
import { scoreDomain } from "../lib/scoring.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const CORPUS_PATH = path.join(ROOT, "corpus.json");
const BASELINE_PATH = path.join(ROOT, "eval_baseline.json");

const isCheckRegression = process.argv.includes("--check-regression");
const isSaveBaseline = process.argv.includes("--save-baseline");

const data = loadData();
const corpus = JSON.parse(fs.readFileSync(CORPUS_PATH, "utf8"));
const alertMin = data.scoring?.thresholds?.alert_min ?? 70;

// Run evaluation on all items
const scoredItems = corpus.items.map((item) => {
  const result = scoreDomain(item.domain, data);
  const score = result.score;
  const isSuppressed = result.suppressed;
  const isMalicious = item.expected === "malicious" || item.label === "positive";
  return {
    ...item,
    score,
    suppressed: isSuppressed,
    signals: result.signals,
    isMalicious
  };
});

// 1. Threshold sweep [30, 40, 50, 60, 70, 80, 90]
const thresholds = [30, 40, 50, 60, 70, 80, 90];
const sweepResults = thresholds.map((t) => {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const item of scoredItems) {
    const predMalicious = !item.suppressed && item.score >= t;
    if (item.isMalicious && predMalicious) tp += 1;
    else if (!item.isMalicious && predMalicious) fp += 1;
    else if (!item.isMalicious && !predMalicious) tn += 1;
    else if (item.isMalicious && !predMalicious) fn += 1;
  }
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  return { threshold: t, tp, fp, tn, fn, precision, recall, f1 };
});

// 2. Metrics at alertMin (70)
const alertSweep = sweepResults.find((r) => r.threshold === alertMin) || sweepResults[4];

// 3. Per-brand breakdown at alertMin
const brandMap = {};
for (const item of scoredItems) {
  const b = item.brand || "none";
  if (!brandMap[b]) {
    brandMap[b] = { tp: 0, fp: 0, tn: 0, fn: 0 };
  }
  const predMalicious = !item.suppressed && item.score >= alertMin;
  if (item.isMalicious && predMalicious) brandMap[b].tp += 1;
  else if (!item.isMalicious && predMalicious) brandMap[b].fp += 1;
  else if (!item.isMalicious && !predMalicious) brandMap[b].tn += 1;
  else if (item.isMalicious && !predMalicious) brandMap[b].fn += 1;
}

const perBrand = Object.entries(brandMap).map(([brand, counts]) => {
  const p = counts.tp + counts.fp > 0 ? counts.tp / (counts.tp + counts.fp) : (counts.fp === 0 ? 1 : 0);
  const r = counts.tp + counts.fn > 0 ? counts.tp / (counts.tp + counts.fn) : 1;
  const f1 = p + r > 0 ? (2 * p * r) / (p + r) : 0;
  return { brand, ...counts, precision: p, recall: r, f1 };
});

// Sort worst-first by precision ascending, then recall ascending
perBrand.sort((a, b) => {
  if (a.fp !== b.fp) return b.fp - a.fp;
  if (a.precision !== b.precision) return a.precision - b.precision;
  return a.recall - b.recall;
});

// 4. Adversarial pass rate
const advItems = scoredItems.filter((item) => item.adversarial);
const advPassed = advItems.filter((item) => !item.suppressed && item.score >= alertMin);
const advMissed = advItems.filter((item) => item.suppressed || item.score < alertMin);

// 5. False positives and false negatives at alertMin
const falsePositives = scoredItems.filter((item) => !item.isMalicious && !item.suppressed && item.score >= alertMin);
const falseNegatives = scoredItems.filter((item) => item.isMalicious && (item.suppressed || item.score < alertMin));

// Format output
console.log("==========================================================================");
console.log(`scoring_version: ${data.scoring?.version ?? 2}   corpus: ${corpus.composition?.positives ?? 155} pos / ${corpus.composition?.negatives ?? 530} neg / ${corpus.composition?.adversarial ?? 60} adv (total: ${corpus.items.length})`);
console.log("==========================================================================");
console.log("threshold  precision  recall  FP    FN   f1");
for (const r of sweepResults) {
  const marker = r.threshold === alertMin ? "  <- alert_min" : "";
  console.log(
    `${String(r.threshold).padEnd(10)} ` +
    `${r.precision.toFixed(3).padEnd(10)} ` +
    `${r.recall.toFixed(3).padEnd(7)} ` +
    `${String(r.fp).padEnd(5)} ` +
    `${String(r.fn).padEnd(4)} ` +
    `${r.f1.toFixed(3)}${marker}`
  );
}

console.log("\n--------------------------------------------------------------------------");
console.log(`adversarial: ${advPassed.length}/${advItems.length} caught at threshold ${alertMin}`);
if (advMissed.length > 0) {
  for (const m of advMissed) {
    console.log(`  MISSED: ${m.domain} (score ${m.score}) [${m.category || "homoglyph"}]`);
  }
}

console.log("\n--------------------------------------------------------------------------");
console.log(`per-brand precision at ${alertMin} (sorted worst-first):`);
for (const b of perBrand) {
  if (b.tp + b.fp + b.fn === 0) continue;
  const fpNote = b.fp > 0 ? ` (${b.fp} FP)` : "";
  const fnNote = b.fn > 0 ? ` (${b.fn} FN)` : "";
  console.log(`  ${b.brand.padEnd(14)} P: ${b.precision.toFixed(3)}  R: ${b.recall.toFixed(3)}${fpNote}${fnNote}`);
}

console.log("\n--------------------------------------------------------------------------");
console.log("Corpus composition:");
console.log(`  Positives:                ${corpus.composition?.positives ?? 155}`);
console.log(`  Negatives:                ${corpus.composition?.negatives ?? 530}`);
console.log(`    - Mined 25-69 band:     ${corpus.composition?.mined_band_negatives ?? 420}`);
console.log(`    - Allowlisted official: 67`);
console.log(`    - Trusted .sg / gov:    43`);
console.log(`  Adversarial fixtures:     ${corpus.composition?.adversarial ?? 60}`);
console.log(`  Total items:              ${corpus.items.length}`);
console.log("==========================================================================");

const baselinePayload = {
  version: data.scoring?.version ?? 2,
  alert_min: alertMin,
  total_items: corpus.items.length,
  tp: alertSweep.tp,
  fp: alertSweep.fp,
  tn: alertSweep.tn,
  fn: alertSweep.fn,
  precision: Number(alertSweep.precision.toFixed(4)),
  recall: Number(alertSweep.recall.toFixed(4)),
  f1: Number(alertSweep.f1.toFixed(4)),
  adversarial_total: advItems.length,
  adversarial_passed: advPassed.length,
  adversarial_missed: advMissed.length,
  sweep: sweepResults,
  per_brand: perBrand
};

if (isSaveBaseline || !fs.existsSync(BASELINE_PATH)) {
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(baselinePayload, null, 2) + "\n");
  console.log(`\nSaved baseline metrics to ${BASELINE_PATH}`);
}

if (isCheckRegression) {
  if (!fs.existsSync(BASELINE_PATH)) {
    console.error("Error: --check-regression specified but eval_baseline.json not found.");
    process.exit(1);
  }
  const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
  console.log(`\nRegression check against baseline F1: ${(baseline.f1 * 100).toFixed(2)}%`);

  // Check allowlisted false positives
  const allowlistFp = falsePositives.filter((item) => item.category === "allowlisted");
  if (allowlistFp.length > 0) {
    console.error(`\nRegression failure: ${allowlistFp.length} allowlisted domain(s) classified as malicious!`);
    process.exit(1);
  }

  // Check F1 drop > 0.02
  if (baseline.f1 - alertSweep.f1 > 0.02) {
    console.error(`\nRegression failure: F1 dropped by ${((baseline.f1 - alertSweep.f1) * 100).toFixed(2)}% (> 2% tolerance)`);
    process.exit(1);
  }
  console.log("Regression check passed: no regressions detected.");
}

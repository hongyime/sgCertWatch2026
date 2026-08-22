import fs from "node:fs";
import path from "node:path";
import assert from "node:assert";
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

// Segregate items for headline metrics vs adversarial vs constructed fixtures
const headlinePositives = scoredItems.filter((i) => !i.adversarial && !i.constructed && i.isMalicious);
const headlineNegatives = scoredItems.filter((i) => !i.adversarial && !i.constructed && !i.isMalicious);
const headlineItems = [...headlinePositives, ...headlineNegatives];
const totalPositivesCount = headlinePositives.length;
const totalNegativesCount = headlineNegatives.length;
const totalHeadlineDenominator = headlineItems.length;

const adversarialItems = scoredItems.filter((i) => i.adversarial);
const constructedItems = scoredItems.filter((i) => i.constructed);

// 1. Threshold sweep [30, 40, 50, 60, 70, 80, 90] on headline benchmark set
const thresholds = [30, 40, 50, 60, 70, 80, 90];
const sweepResults = thresholds.map((t) => {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const item of headlineItems) {
    const predMalicious = !item.suppressed && item.score >= t;
    if (item.isMalicious && predMalicious) tp += 1;
    else if (!item.isMalicious && predMalicious) fp += 1;
    else if (!item.isMalicious && !predMalicious) tn += 1;
    else if (item.isMalicious && !predMalicious) fn += 1;
  }

  // Self-consistency mathematical assertions
  assert.strictEqual(
    tp + fn,
    totalPositivesCount,
    `Consistency Error: TP (${tp}) + FN (${fn}) !== total positives (${totalPositivesCount}) at threshold ${t}`
  );
  assert.strictEqual(
    tn + fp,
    totalNegativesCount,
    `Consistency Error: TN (${tn}) + FP (${fp}) !== total negatives (${totalNegativesCount}) at threshold ${t}`
  );
  assert.strictEqual(
    tp + fp + tn + fn,
    totalHeadlineDenominator,
    `Consistency Error: Total sum (${tp + fp + tn + fn}) !== headline denominator (${totalHeadlineDenominator})`
  );

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return { threshold: t, tp, fp, tn, fn, precision, recall, f1 };
});

// 2. Headline metrics at alertMin (70)
const alertSweep = sweepResults.find((r) => r.threshold === alertMin) || sweepResults[4];

// 3. Per-brand breakdown at alertMin on headline benchmark items
const brandMap = {};
for (const item of headlineItems) {
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

// 4. Adversarial evaluation (tracked and reported separately)
const advPassed = adversarialItems.filter((item) => !item.suppressed && item.score >= alertMin);
const advMissed = adversarialItems.filter((item) => item.suppressed || item.score < alertMin);

// 5. Constructed evaluation (segregated legacy synthetic fixtures)
const constPassed = constructedItems.filter((item) => !item.isMalicious && (item.suppressed || item.score < alertMin));
const constFp = constructedItems.filter((item) => !item.isMalicious && !item.suppressed && item.score >= alertMin);

// 6. False positives and false negatives at alertMin on headline benchmark
const falsePositives = headlineItems.filter((item) => !item.isMalicious && !item.suppressed && item.score >= alertMin);
const falseNegatives = headlineItems.filter((item) => item.isMalicious && (item.suppressed || item.score < alertMin));

// Format output
console.log("=========================================================================================");
console.log(`sgCertWatch Evaluation Benchmark — Scorer Version: ${data.scoring?.version ?? 2}`);
console.log(`Headline Denominator: N = ${totalHeadlineDenominator} (${totalPositivesCount} positives, ${totalNegativesCount} observed negatives)`);
console.log("=========================================================================================");
console.log("Threshold  Precision  Recall   TP     FP     TN       FN    F1-Score");
console.log("---------  ---------  -------  -----  -----  -------  ----  --------");
for (const r of sweepResults) {
  const marker = r.threshold === alertMin ? "  <- alert_min" : "";
  console.log(
    `${String(r.threshold).padEnd(9)}  ` +
    `${r.precision.toFixed(4).padEnd(9)}  ` +
    `${r.recall.toFixed(4).padEnd(7)}  ` +
    `${String(r.tp).padEnd(5)}  ` +
    `${String(r.fp).padEnd(5)}  ` +
    `${String(r.tn).padEnd(7)}  ` +
    `${String(r.fn).padEnd(4)}  ` +
    `${r.f1.toFixed(4)}${marker}`
  );
}

console.log("\n-----------------------------------------------------------------------------------------");
console.log(`Adversarial Suite (Reported Separately): ${advPassed.length}/${adversarialItems.length} caught at alert_min (${alertMin}) [${((advPassed.length / adversarialItems.length) * 100).toFixed(1)}%]`);
if (advMissed.length > 0) {
  for (const m of advMissed) {
    console.log(`  MISSED: ${m.domain} (score ${m.score}) [${m.category || "homoglyph"}]`);
  }
}

console.log("\n-----------------------------------------------------------------------------------------");
console.log(`Constructed Fixtures (Segregated): ${constPassed.length}/${constructedItems.length} correctly benign at alert_min (${alertMin})`);
if (constFp.length > 0) {
  for (const cf of constFp) {
    console.log(`  FP (constructed): ${cf.domain} (score ${cf.score})`);
  }
}

console.log("\n-----------------------------------------------------------------------------------------");
console.log(`Per-Brand Headline Performance at ${alertMin} (Worst-first):`);
for (const b of perBrand) {
  if (b.tp + b.fp + b.fn === 0) continue;
  const fpNote = b.fp > 0 ? ` (${b.fp} FP)` : "";
  const fnNote = b.fn > 0 ? ` (${b.fn} FN)` : "";
  console.log(`  ${b.brand.padEnd(14)} P: ${b.precision.toFixed(4)}  R: ${b.recall.toFixed(4)}  [TP:${b.tp} FP:${b.fp} TN:${b.tn} FN:${b.fn}]${fpNote}${fnNote}`);
}

console.log("\n-----------------------------------------------------------------------------------------");
console.log("Corpus Provenance & Composition Breakdown:");
console.log(`  Headline Benchmark (Positives):      ${totalPositivesCount}`);
console.log(`  Headline Benchmark (Observed Negs):  ${totalNegativesCount}`);
console.log(`    - Real CT static mined (provenance):  ${corpus.composition?.mined_real_ct_negatives ?? 0}`);
console.log(`    - Verified allowlisted official:     ${corpus.composition?.allowlist_official ?? 67}`);
console.log(`    - Trusted .sg / gov.sg:              ${corpus.composition?.trusted_sg ?? 43}`);
console.log(`  Adversarial Fixtures (Separate):     ${adversarialItems.length}`);
console.log(`  Constructed Fixtures (Segregated):   ${constructedItems.length}`);
console.log(`  Total Evaluated Corpus Entities:     ${corpus.items.length}`);
console.log("=========================================================================================");

const baselinePayload = {
  version: data.scoring?.version ?? 2,
  alert_min: alertMin,
  total_items: corpus.items.length,
  headline_denominator: totalHeadlineDenominator,
  tp: alertSweep.tp,
  fp: alertSweep.fp,
  tn: alertSweep.tn,
  fn: alertSweep.fn,
  precision: Number(alertSweep.precision.toFixed(4)),
  recall: Number(alertSweep.recall.toFixed(4)),
  f1: Number(alertSweep.f1.toFixed(4)),
  adversarial_total: adversarialItems.length,
  adversarial_passed: advPassed.length,
  adversarial_missed: advMissed.length,
  constructed_total: constructedItems.length,
  constructed_passed: constPassed.length,
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


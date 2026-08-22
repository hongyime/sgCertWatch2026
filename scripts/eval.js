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

let tp = 0;
let fp = 0;
let tn = 0;
let fn = 0;

const falsePositives = [];
const falseNegatives = [];
const perBrand = {};

for (const item of corpus.items) {
  const result = scoreDomain(item.domain, data);
  const score = result.score;
  const isSuppressed = result.suppressed;
  const predicted = !isSuppressed && score >= alertMin ? "malicious" : "benign";
  const actual = item.expected;
  const brand = item.brand || "unknown";

  if (!perBrand[brand]) {
    perBrand[brand] = { tp: 0, fp: 0, tn: 0, fn: 0 };
  }

  if (actual === "malicious" && predicted === "malicious") {
    tp += 1;
    perBrand[brand].tp += 1;
  } else if (actual === "benign" && predicted === "malicious") {
    fp += 1;
    perBrand[brand].fp += 1;
    falsePositives.push({ ...item, score, signals: result.signals });
  } else if (actual === "benign" && predicted === "benign") {
    tn += 1;
    perBrand[brand].tn += 1;
  } else if (actual === "malicious" && predicted === "benign") {
    fn += 1;
    perBrand[brand].fn += 1;
    falseNegatives.push({ ...item, score, signals: result.signals });
  }
}

const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

console.log("==================================================");
console.log(" sgCertWatch2026 Evaluation Report");
console.log("==================================================");
console.log(`Corpus items:      ${corpus.items.length}`);
console.log(`Alert threshold:   ${alertMin}`);
console.log(`Scoring version:   ${data.scoring?.version ?? 2}`);
console.log("--------------------------------------------------");
console.log(`Confusion Matrix:  TP: ${tp.toString().padStart(3)} | FP: ${fp.toString().padStart(3)}`);
console.log(`                   FN: ${fn.toString().padStart(3)} | TN: ${tn.toString().padStart(3)}`);
console.log("--------------------------------------------------");
console.log(`Precision:         ${(precision * 100).toFixed(2)}%`);
console.log(`Recall:            ${(recall * 100).toFixed(2)}%`);
console.log(`F1 Score:          ${(f1 * 100).toFixed(2)}%`);
console.log("==================================================");

if (falsePositives.length > 0) {
  console.log("\nFalse Positives (Benign classified as Malicious):");
  for (const item of falsePositives) {
    console.log(`  - [${item.id}] ${item.domain} (score: ${item.score}, brand: ${item.brand}, category: ${item.category})`);
  }
}

if (falseNegatives.length > 0) {
  console.log("\nFalse Negatives (Malicious classified as Benign):");
  for (const item of falseNegatives) {
    console.log(`  - [${item.id}] ${item.domain} (score: ${item.score}, brand: ${item.brand}, category: ${item.category})`);
  }
}

const currentMetrics = {
  version: data.scoring?.version ?? 2,
  alert_min: alertMin,
  total_items: corpus.items.length,
  tp,
  fp,
  tn,
  fn,
  precision: Number(precision.toFixed(4)),
  recall: Number(recall.toFixed(4)),
  f1: Number(f1.toFixed(4)),
  per_brand: perBrand
};

if (isSaveBaseline || !fs.existsSync(BASELINE_PATH)) {
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(currentMetrics, null, 2) + "\n");
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
  if (baseline.f1 - f1 > 0.02) {
    console.error(`\nRegression failure: F1 dropped by ${((baseline.f1 - f1) * 100).toFixed(2)}% (> 2% tolerance)`);
    process.exit(1);
  }
  console.log("Regression check passed: no regressions detected.");
}

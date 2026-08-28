import fs from "node:fs";
import readline from "node:readline";
import { loadData } from "../lib/data.js";
import { scoreDomain } from "../lib/scoring.js";

const EXTENDED_NEGATIVES_PATH = process.env.EXTENDED_NEGATIVES_PATH || "fixtures/corpus/extended_negatives.jsonl";
const EVAL_LIMIT = process.env.EVAL_LIMIT ? parseInt(process.env.EVAL_LIMIT, 10) : null;
const PROGRESS_EVERY = process.env.PROGRESS_EVERY ? parseInt(process.env.PROGRESS_EVERY, 10) : 10000;
const DAILY_CT_VOLUME = 6000000;
const thresholds = [30, 40, 50, 60, 70, 80, 90];
const data = loadData();
const alertMin = data.scoring?.thresholds?.alert_min ?? 70;
const counts = new Map(thresholds.map((threshold) => [threshold, { fp: 0, tn: 0 }]));
const topSignals = new Map();

let total = 0;
let malformed = 0;
let missingDomain = 0;
let suppressed = 0;

function addSignals(signals) {
  for (const signal of signals || []) {
    const key = signal.type || "unknown";
    topSignals.set(key, (topSignals.get(key) || 0) + 1);
  }
}

const stream = fs.createReadStream(EXTENDED_NEGATIVES_PATH, "utf8");
const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
const startedAt = Date.now();

for await (const line of rl) {
  if (EVAL_LIMIT !== null && total >= EVAL_LIMIT) break;
  if (!line.trim()) continue;
  let record;
  try {
    record = JSON.parse(line);
  } catch (_) {
    malformed++;
    continue;
  }
  if (!record.domain) {
    missingDomain++;
    continue;
  }

  const result = scoreDomain(record.domain, data);
  total++;
  if (result.suppressed) suppressed++;
  if (!result.suppressed && result.score >= alertMin) addSignals(result.signals);

  for (const threshold of thresholds) {
    const bucket = counts.get(threshold);
    if (!result.suppressed && result.score >= threshold) bucket.fp++;
    else bucket.tn++;
  }

  if (PROGRESS_EVERY > 0 && total % PROGRESS_EVERY === 0) {
    const seconds = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
    console.error(`scored ${total.toLocaleString()} extended negatives (${Math.round(total / seconds).toLocaleString()}/s)...`);
  }
}

console.log("=========================================================================================================");
console.log("sgCertWatch Extended Negative Evaluation");
console.log(`Input: ${EXTENDED_NEGATIVES_PATH}`);
console.log(`Negatives scored: ${total.toLocaleString()} | malformed: ${malformed} | missing domain: ${missingDomain} | suppressed: ${suppressed}`);
if (EVAL_LIMIT !== null) console.log(`Limit: ${EVAL_LIMIT.toLocaleString()}`);
console.log(`Daily CT Volume Baseline: ~${DAILY_CT_VOLUME.toLocaleString()} certs/day`);
console.log("=========================================================================================================");
console.log("Threshold  FP       TN        FP Rate     Alerts/Day (Extrapolated)");
console.log("---------  -------  --------  ----------  -------------------------");
for (const threshold of thresholds) {
  const bucket = counts.get(threshold);
  const fpRate = total > 0 ? bucket.fp / total : 0;
  const alertsPerDay = Math.round(fpRate * DAILY_CT_VOLUME);
  const marker = threshold === alertMin ? "  <- alert_min" : "";
  console.log(
    `${String(threshold).padEnd(9)}  ` +
    `${String(bucket.fp).padEnd(7)}  ` +
    `${String(bucket.tn).padEnd(8)}  ` +
    `${fpRate.toFixed(8).padEnd(10)}  ` +
    `${String(alertsPerDay.toLocaleString() + " / day").padEnd(25)}${marker}`
  );
}

const signalSummary = [...topSignals.entries()]
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .map(([type, count]) => `${type}:${count}`)
  .join("  ");
console.log("---------------------------------------------------------------------------------------------------------");
console.log(`Alert-min signal types: ${signalSummary || "none"}`);
console.log("=========================================================================================================");

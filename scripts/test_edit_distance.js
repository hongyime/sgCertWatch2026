import assert from "node:assert/strict";
import { loadData } from "../lib/data.js";
import {
  damerauLevenshteinDistance,
  minSubstringEditDistance,
  maxEditDistanceForLength,
  scoreDomain
} from "../lib/scoring.js";

// 1. Damerau-Levenshtein transposition and distance tests
assert.equal(damerauLevenshteinDistance("dbs", "dsb"), 1, "Adjacent transposition is distance 1");
assert.equal(damerauLevenshteinDistance("posb", "psob"), 1, "Adjacent transposition is distance 1");
assert.equal(damerauLevenshteinDistance("ocbc", "obcc"), 1, "Adjacent transposition is distance 1");
assert.equal(damerauLevenshteinDistance("singpass", "siingpass"), 1, "Single insertion is distance 1");
assert.equal(damerauLevenshteinDistance("carousell", "carousel"), 1, "Single deletion is distance 1");

// 2. Length-banding rules
assert.equal(maxEditDistanceForLength(2), 0, "Length <= 2 allows 0 edit distance");
assert.equal(maxEditDistanceForLength(3, 1, false), 0, "Length 3 without context requirement allows 0 edit distance");
assert.equal(maxEditDistanceForLength(3, 1, true), 1, "Length 3 with context requirement allows 1 edit distance");
assert.equal(maxEditDistanceForLength(4, 2), 1, "Length 4 is capped at 1 edit distance");
assert.equal(maxEditDistanceForLength(6, 2), 1, "Length 6 is capped at 1 edit distance");
assert.equal(maxEditDistanceForLength(7, 2), 2, "Length 7 allows 2 edit distance");
assert.equal(maxEditDistanceForLength(8, 2), 2, "Length 8 allows 2 edit distance");

// 3. Substring window edit distance
assert.equal(minSubstringEditDistance("dhjfhoers", "shopee", 1), -1, "shoer vs shopee distance 2 is rejected under length 6 cap (maxDist 1)");
assert.equal(minSubstringEditDistance("singpstoportal", "singpost", 2), 1, "singpsto vs singpost is distance 1 (transposition)");

// 4. Dictionary word suppression for carousell
const data = loadData();

const resBenignCarousel = scoreDomain("vintage-carousel.org", data);
assert.equal(resBenignCarousel.score, 0, "Benign carousel domain without market context is suppressed");

const resMaliciousCarousellPhish = scoreDomain("carousell-login-verify.top", data);
assert.ok(resMaliciousCarousellPhish.score >= 70, "Carousell phish with keywords scores >= alert_min");

// 5. Length-banding prevents false positives on dhjfhoers.shop
const resDhjfhoers = scoreDomain("www.dhjfhoers.shop", data);
assert.equal(resDhjfhoers.score, 0, "dhjfhoers.shop does not trigger fuzzy match for shopee");

console.log("Length-banded edit distance and dictionary suppression tests passed.");

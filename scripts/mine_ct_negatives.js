import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadData } from "../lib/data.js";
import { scoreDomain } from "../lib/scoring.js";
import { fetchDynamicLogList } from "../lib/ct/loglist.js";
import { verifyCheckpoint } from "../lib/ct/static/checkpoint.js";
import { fetchTile, parseTileEntries } from "../lib/ct/static/tiles.js";
import { registrableDomain } from "../lib/domain/registrable.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const data = loadData();

async function mineFromLog(log, targetTilesCount = 120) {
  const normUrl = String(log.monitoring_url || log.submission_url).replace(/\/?$/, "/");
  console.log(`\nConnecting to log: ${log.description} (${normUrl})`);

  const cpRes = await fetch(`${normUrl}checkpoint`, {
    headers: { "User-Agent": "sgCertWatch-Miner/1.0" },
    signal: AbortSignal.timeout(10000)
  });
  if (!cpRes.ok) {
    throw new Error(`Failed to fetch checkpoint: ${cpRes.status}`);
  }
  const cpText = await cpRes.text();
  const verified = verifyCheckpoint(cpText, log.public_key_der);
  if (!verified.ok) {
    throw new Error(`Checkpoint signature verification failed: ${verified.reason}`);
  }

  const treeSize = verified.parsed.treeSize;
  const latestTileIndex = Math.floor((treeSize - 1) / 256);
  const startTileIndex = Math.max(0, latestTileIndex - targetTilesCount);

  console.log(`Tree size: ${treeSize.toLocaleString()} entries.`);
  console.log(`Reading tile range: [${startTileIndex} .. ${latestTileIndex - 1}] (${latestTileIndex - startTileIndex} tiles, ~${(latestTileIndex - startTileIndex) * 256} certs)...`);

  const cacheDir = path.join(ROOT, ".cache", "tiles", log.description.replace(/[^a-zA-Z0-9]/g, "_"));
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }

  const certEntries = [];
  const CONCURRENCY = 15;
  const tileIndices = [];
  for (let t = startTileIndex; t < latestTileIndex; t++) {
    tileIndices.push(t);
  }

  for (let i = 0; i < tileIndices.length; i += CONCURRENCY) {
    const chunk = tileIndices.slice(i, i + CONCURRENCY);
    const results = await Promise.all(chunk.map(async (tileIdx) => {
      const cacheFile = path.join(cacheDir, `tile_${tileIdx}.bin`);
      try {
        let buf;
        if (fs.existsSync(cacheFile)) {
          buf = fs.readFileSync(cacheFile);
        } else {
          buf = await fetchTile(normUrl, tileIdx, null, 15000);
          fs.writeFileSync(cacheFile, buf);
        }
        return parseTileEntries(buf, log, tileIdx * 256);
      } catch (err) {
        console.warn(`Warning: failed tile ${tileIdx} on ${log.description}: ${err.message}`);
        return [];
      }
    }));
    for (const res of results) {
      certEntries.push(...res);
    }
    process.stdout.write(`\r  Progress: ${certEntries.length} certificates parsed...`);
  }
  console.log(`\nCompleted ${log.description}: ${certEntries.length} certificates read.`);
  return {
    log,
    treeSize,
    startTileIndex,
    endTileIndex: latestTileIndex - 1,
    certCount: certEntries.length,
    entries: certEntries
  };
}

async function main() {
  console.log("=== sgCertWatch: Real CT Certificate Negative Miner (Commit 11C) ===");
  const { allLogs } = await fetchDynamicLogList();

  const targetLogDescriptions = [
    "Sycamore2026h2",
    "Willow2026h2",
    "Sycamore2027h1",
    "Willow2027h1"
  ];

  const targetLogs = targetLogDescriptions.map((desc) => {
    const found = allLogs.find((l) => l.description.includes(desc) && l.protocol === "static-ct-api");
    if (!found) throw new Error(`Could not find static log for ${desc}`);
    return found;
  });

  const totalResults = [];
  let totalCertsRead = 0;

  for (const log of targetLogs) {
    const res = await mineFromLog(log, 120);
    totalResults.push(res);
    totalCertsRead += res.certCount;
  }

  console.log(`\n======================================================`);
  console.log(`Total real certificates scanned: ${totalCertsRead.toLocaleString()}`);
  for (const r of totalResults) {
    console.log(`  - ${r.log.description}: ${r.certCount.toLocaleString()} certs (tiles ${r.startTileIndex}..${r.endTileIndex}, tree size ${r.treeSize.toLocaleString()})`);
  }
  console.log(`======================================================\n`);

  console.log("Extracting SANs and scoring with current scorer (25..69 band)...");

  const seenRegistrables = new Set();
  const minedCandidates = [];
  let certIndex = 0;

  for (const r of totalResults) {
    for (const entry of r.entries) {
      certIndex++;
      if (certIndex % 10000 === 0) {
        process.stdout.write(`\r  Scored ${certIndex.toLocaleString()} / ${totalCertsRead.toLocaleString()} certs (found ${minedCandidates.length} in 25..69 band)...`);
      }
      for (const d of entry.dns_names || []) {
        const reg = registrableDomain(d);
        if (!reg || seenRegistrables.has(reg)) continue;
        seenRegistrables.add(reg);

        const scoreRes = scoreDomain(d, data);
        if (scoreRes.suppressed) continue;

        // Band 25 to 69 (or legitimate collisions scoring >= 25)
        if (scoreRes.score >= 25 && scoreRes.score < 70) {
          const matchedBrand = scoreRes.signals.find((s) => s.type.startsWith("brand:"))?.brand || "none";
          minedCandidates.push({
            domain: d,
            registrable: reg,
            score: scoreRes.score,
            signals: scoreRes.signals,
            log_id: r.log.description,
            tree_index: entry.cert_index,
            cert_sha256: entry.cert_fingerprint || "unknown",
            observed_at: new Date(entry.seen * 1000).toISOString(),
            brand: matchedBrand
          });
        }
      }
    }
  }

  console.log(`\nTotal unique registrables evaluated: ${seenRegistrables.size.toLocaleString()}`);
  console.log(`Unique domains scoring in 25..69 ambiguity band: ${minedCandidates.length}`);

  // Write mined candidates to scratch / json for corpus assembly
  const outPath = path.join(ROOT, "fixtures", "corpus", "mined_real_ct_candidates.json");
  fs.writeFileSync(outPath, JSON.stringify({
    mined_at: new Date().toISOString(),
    total_certs_scanned: totalCertsRead,
    logs: totalResults.map(r => ({
      log: r.log.description,
      tree_size: r.treeSize,
      tiles: [r.startTileIndex, r.endTileIndex],
      certs: r.certCount
    })),
    count: minedCandidates.length,
    candidates: minedCandidates
  }, null, 2));

  console.log(`Saved candidates to ${outPath}`);
}

main().catch((err) => {
  console.error("Fatal error during mining:", err);
  process.exit(1);
});

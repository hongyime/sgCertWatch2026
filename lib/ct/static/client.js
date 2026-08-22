import { fetchJson, sourceResult } from "../common.js";
import { parseCheckpoint, verifyCheckpoint } from "./checkpoint.js";
import { fetchTile, parseTileEntries } from "./tiles.js";

const MAX_TILES_PER_LOG_PER_RUN = Number(process.env.STATIC_CT_MAX_TILES_PER_LOG || 20);
const INITIAL_TAIL = Number(process.env.STATIC_CT_INITIAL_TAIL || 512);
const MAX_RUN_DURATION_MS = 50000; // 50s headroom for 60s Vercel timeout

/**
 * Polls a single static CT API log from its current cursor position up to the verified checkpoint tree size.
 */
export async function pollStaticCtLog(log, cursorState = {}, startTime = Date.now()) {
  const normMonitoringUrl = String(log.monitoring_url || log.submission_url || "").replace(/\/?$/, "/");
  const checkpointUrl = `${normMonitoringUrl}checkpoint`;

  // 1. Fetch checkpoint
  const res = await fetch(checkpointUrl, {
    headers: { "User-Agent": "sgCertWatch/1.0" },
    signal: AbortSignal.timeout(8000)
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch checkpoint: ${res.status} ${res.statusText} at ${checkpointUrl}`);
  }

  const checkpointText = await res.text();

  // 2. Verify signature
  const verifyResult = verifyCheckpoint(checkpointText, log.public_key_der);
  if (!verifyResult.ok) {
    throw new Error(`checkpoint_signature_invalid: ${verifyResult.reason}`);
  }

  const checkpoint = verifyResult.parsed;
  const treeSize = checkpoint.treeSize;

  // 3. Determine start cursor
  let cursor = Number.isFinite(Number(cursorState?.next_index ?? cursorState?.next))
    ? Math.min(Number(cursorState.next_index ?? cursorState.next), treeSize)
    : Math.max(0, treeSize - INITIAL_TAIL);

  const entries = [];
  let scannedCount = 0;
  let tilesFetched = 0;

  // 4. Reading loop with budget enforcement
  while (cursor < treeSize && tilesFetched < MAX_TILES_PER_LOG_PER_RUN) {
    if (Date.now() - startTime >= MAX_RUN_DURATION_MS) {
      break; // Time budget reached, exit cleanly
    }

    const tileIndex = Math.floor(cursor / 256);
    const tileBaseIndex = tileIndex * 256;
    const isLastTile = Math.floor((treeSize - 1) / 256) === tileIndex;
    const rem = treeSize % 256;
    const partialWidth = isLastTile && rem !== 0 ? rem : null;

    try {
      const tileBuffer = await fetchTile(normMonitoringUrl, tileIndex, partialWidth);
      tilesFetched += 1;

      const tileEntries = parseTileEntries(tileBuffer, log, tileBaseIndex);
      scannedCount += tileEntries.length;

      // Filter entries at or beyond cursor
      for (const entry of tileEntries) {
        if (entry.cert_index >= cursor) {
          entries.push(entry);
        }
      }

      // Advance cursor to end of this tile or tree size
      cursor = Math.min(treeSize, (tileIndex + 1) * 256);
    } catch (tileErr) {
      // Record tile fetch error and stop advancing for this log
      break;
    }
  }

  const lag = Math.max(0, treeSize - cursor);

  return {
    scanned: scannedCount,
    entries,
    next: cursor,
    treeSize,
    lag,
    tilesFetched
  };
}

/**
 * Runs static CT source across configured static logs.
 */
export async function runStaticCtSource({ staticLogs = [], state = {} }) {
  const startedAt = Date.now();
  const errors = [];
  const entries = [];
  let totalScanned = 0;
  const cursors = { ...(state.cursors || {}) };

  for (const log of staticLogs) {
    if (Date.now() - startedAt >= MAX_RUN_DURATION_MS) {
      break;
    }

    const logKey = log.log_id || log.description;
    try {
      const result = await pollStaticCtLog(log, cursors[logKey], startedAt);
      totalScanned += result.scanned;
      entries.push(...result.entries);
      cursors[logKey] = {
        next: result.next,
        tree_size: result.treeSize,
        lag: result.lag,
        checked_at: new Date().toISOString()
      };
    } catch (err) {
      errors.push({ log: log.description, message: err.message });
    }
  }

  return sourceResult({
    source: "static_ct",
    label: "Static CT logs",
    startedAt,
    entries,
    scannedEntries: totalScanned,
    errors,
    details: {
      log_count: staticLogs.length,
      parsed_entries: entries.length
    },
    statePatch: {
      static_ct: { cursors }
    }
  });
}

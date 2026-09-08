import { sourceResult } from "../common.js";
import { verifyCheckpoint } from "./checkpoint.js";
import { fetchTile, parseTileEntries } from "./tiles.js";

const MAX_TILES_PER_LOG_PER_RUN = Number(process.env.STATIC_CT_MAX_TILES_PER_LOG || 20);
const INITIAL_TAIL = Number(process.env.STATIC_CT_INITIAL_TAIL || 512);
const MAX_RUN_DURATION_MS = Math.min(300000, Math.max(1000, Number(process.env.STATIC_CT_MAX_RUN_MS) || 50000));

/**
 * Polls a single static CT API log from its current cursor position up to the verified checkpoint tree size.
 */
export async function pollStaticCtLog(log, cursorState = {}, startTime = Date.now()) {
  const normMonitoringUrl = String(log.monitoring_url || log.submission_url || "").replace(/\/?$/, "/");
  const checkpointUrl = `${normMonitoringUrl}checkpoint`;
  const remainingMs = () => Math.max(0, MAX_RUN_DURATION_MS - (Date.now() - startTime));
  const checkpointBudget = remainingMs();
  if (checkpointBudget <= 0) throw new Error("Static CT run budget exhausted before checkpoint");

  // 1. Fetch checkpoint
  const res = await fetch(checkpointUrl, {
    headers: { "User-Agent": "sgCertWatch/1.0" },
    signal: AbortSignal.timeout(Math.min(8000, checkpointBudget))
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
  const errors = [];
  const initialCursor = cursor;
  let scannedCount = 0;
  let tilesFetched = 0;

  // 4. Reading loop with budget enforcement
  while (cursor < treeSize && tilesFetched < MAX_TILES_PER_LOG_PER_RUN) {
    const tileBudget = remainingMs();
    if (tileBudget <= 0) {
      break; // Time budget reached, exit cleanly
    }

    const tileIndex = Math.floor(cursor / 256);
    const tileBaseIndex = tileIndex * 256;
    const isLastTile = Math.floor((treeSize - 1) / 256) === tileIndex;
    const rem = treeSize % 256;
    const partialWidth = isLastTile && rem !== 0 ? rem : null;

    try {
      const tileBuffer = await fetchTile(normMonitoringUrl, tileIndex, partialWidth, Math.min(12000, tileBudget));

      const expectedBundleCount = partialWidth ?? 256;
      const tileEntries = parseTileEntries(tileBuffer, log, tileBaseIndex, { expectedBundleCount });
      tilesFetched += 1;
      scannedCount += expectedBundleCount;

      // Filter entries at or beyond cursor
      for (const entry of tileEntries) {
        if (entry.cert_index >= cursor) {
          entries.push(entry);
        }
      }

      // Advance cursor to end of this tile or tree size
      cursor = Math.min(treeSize, (tileIndex + 1) * 256);
    } catch (tileErr) {
      errors.push({ tile_index: tileIndex, message: tileErr.message });
      break;
    }
  }

  const lag = Math.max(0, treeSize - cursor);
  const progressed = cursor > initialCursor;
  if (lag > 0 && !progressed && !errors.length) {
    errors.push({ message: remainingMs() <= 0
      ? "Static CT run budget exhausted before any tile was read"
      : "Static CT poll made no progress with unread entries" });
  }

  return {
    ok: errors.length === 0,
    errors,
    progressed,
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
  const startIndex = Number.isSafeInteger(Number(state.index)) && Number(state.index) >= 0 && staticLogs.length
    ? Number(state.index) % staticLogs.length : 0;
  let attemptedLogs = 0;
  let successfulLogs = 0;
  let progressedLogs = 0;

  for (let offset = 0; offset < staticLogs.length; offset += 1) {
    if (Date.now() - startedAt >= MAX_RUN_DURATION_MS) {
      break;
    }

    const log = staticLogs[(startIndex + offset) % staticLogs.length];
    attemptedLogs += 1;
    const logKey = log.log_id || log.description;
    try {
      const result = await pollStaticCtLog(log, cursors[logKey], startedAt);
      totalScanned += result.scanned;
      entries.push(...result.entries);
      if (result.ok) successfulLogs += 1;
      if (result.progressed) progressedLogs += 1;
      errors.push(...result.errors.map((error) => ({ log: log.description, ...error })));
      cursors[logKey] = {
        next: result.next,
        tree_size: result.treeSize,
        lag: result.lag,
        checked_at: new Date().toISOString(),
        last_error: result.errors[0]?.message || null
      };
    } catch (err) {
      errors.push({ log: log.description, message: err.message });
    }
  }

  if (!staticLogs.length) {
    errors.push({ message: "No readable static CT logs found" });
  } else if (!attemptedLogs) {
    errors.push({ message: "Static CT run budget exhausted before any log was polled" });
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
      attempted_log_count: attemptedLogs,
      successful_log_count: successfulLogs,
      progressed_log_count: progressedLogs,
      budget_exhausted: Date.now() - startedAt >= MAX_RUN_DURATION_MS,
      parsed_entries: entries.length
    },
    statePatch: {
      static_ct: {
        index: staticLogs.length ? (startIndex + attemptedLogs) % staticLogs.length : 0,
        cursors
      }
    }
  });
}

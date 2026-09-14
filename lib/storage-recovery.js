// Operational guard while the database cannot safely accept connections.
// Clear only after database recovery and read/write validation have completed.
export function respondIfStorageRecovery(response) {
  if (process.env.SGCERTWATCH_STORAGE_RECOVERY !== "true") return false;
  response.setHeader("Retry-After", "900");
  response.setHeader("Cache-Control", "private, no-store");
  response.status(503).json({
    error: "storage_recovery",
    maintenance: true,
    message: "Stored history is temporarily unavailable while database recovery is arranged. New collection is paused."
  });
  return true;
}

import { configured, listFindings, searchFindings } from "../lib/supabase.js";
import { respondIfStorageRecovery } from "../lib/storage-recovery.js";
import { parseSearchParams, encodeCursor, decodeCursor } from "../lib/findings-query.js";

export default async function handler(request, response) {
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  if (respondIfStorageRecovery(response)) return;

  const q = request.query ?? {};

  // search=1 opt-in: bounded historical search with cursor pagination
  if (q.search === "1") {
    const parsed = parseSearchParams(q);
    if (!parsed.ok) {
      response.status(400).json({ error: parsed.error, message: parsed.message });
      return;
    }
    const { params } = parsed;

    // Decode cursor if provided
    let cursorState = null;
    if (q.cursor) {
      const decoded = decodeCursor(q.cursor, params);
      if (!decoded.ok) {
        response.status(400).json({
          error: "cursor_invalid",
          message: `Cursor is invalid or expired (${decoded.error}). Please reload and start a new search.`,
        });
        return;
      }
      cursorState = decoded.state;
    }

    try {
      const evaluatedAt = cursorState?.evaluated_at ?? new Date().toISOString();
      const result = await searchFindings(params, cursorState, evaluatedAt);
      const hasMore = result.findings.length > params.limit;
      const page = result.findings.slice(0, params.limit);

      let nextCursor = null;
      if (hasMore && page.length > 0) {
        const last = page[page.length - 1];
        nextCursor = encodeCursor({
          params,
          last_id: last.id,
          last_observed_at: last.observed_at,
          last_priority: last.priority_score ?? last.score ?? 0,
          evaluated_at: evaluatedAt,
        });
      }

      response.status(200).json({
        storage_configured: configured(),
        findings: page,
        page: {
          has_more: hasMore,
          next_cursor: nextCursor,
          scope: "stored_history",
          evaluated_at: evaluatedAt,
        },
      });
    } catch (error) {
      response.status(500).json({ error: "search_query_failed", message: error.message });
    }
    return;
  }

  // Legacy route: limit/view only
  try {
    const limit = q.limit || 50;
    const findings = await listFindings(limit, { view: q.view });
    response.status(200).json({
      storage_configured: configured(),
      findings,
    });
  } catch (error) {
    response.status(500).json({ error: "findings_query_failed", message: error.message });
  }
}

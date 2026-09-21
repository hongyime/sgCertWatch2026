/**
 * api/reviews.js
 *
 * Authenticated analyst review endpoint.
 * GET  /api/reviews?finding_id=<id>  — read current review state
 * POST /api/reviews                  — create or update a review
 *
 * Authentication: Supabase access token via Authorization: Bearer <token>
 * The token is verified server-side; reviewer UUID checked against REVIEWER_USER_IDS.
 * Never exposes TRIAGE_TOKEN. Legacy /api/triage remains separate.
 */

import { verifyReviewer, extractBearerToken } from "../lib/reviewer-auth.js";
import { respondIfStorageRecovery } from "../lib/storage-recovery.js";

// Read env vars at request time (not module load) so tests can inject them.

function json(res, status, body) {
  res.setHeader("Cache-Control", "no-store");
  res.status(status).json(body);
}

function serviceHeaders(extra = {}) {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json",
    ...extra,
  };
}

export default async function handler(request, response) {
  if (!["GET", "POST"].includes(request.method)) {
    response.setHeader("Allow", "GET, POST");
    return json(response, 405, { error: "method_not_allowed" });
  }

  if (respondIfStorageRecovery(response)) return;

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return json(response, 503, { error: "reviewer_not_configured" });
  }

  // Authenticate
  const token = extractBearerToken(request);
  const auth = await verifyReviewer(token);
  if (!auth.ok) {
    const status = auth.reason === "server_misconfigured" || auth.reason === "reviewer_not_configured" ? 503 : 401;
    return json(response, status, { error: auth.reason });
  }

  if (request.method === "GET") {
    const findingId = typeof request.query?.finding_id === "string"
      ? request.query.finding_id.trim() : "";
    if (!findingId || findingId.length > 64) {
      return json(response, 400, { error: "invalid_finding_id" });
    }
    try {
      const resp = await fetch(
        `${process.env.SUPABASE_URL}/rest/v1/finding_reviews?finding_id=eq.${encodeURIComponent(findingId)}&limit=1`,
        { headers: serviceHeaders() }
      );
      if (!resp.ok) return json(response, 502, { error: "upstream_unavailable" });
      const rows = await resp.json();
      const review = rows[0] ?? null;
      return json(response, 200, { review });
    } catch {
      return json(response, 502, { error: "upstream_unavailable" });
    }
  }

  // POST
  let body;
  try {
    body = typeof request.body === "string" ? JSON.parse(request.body) : request.body;
  } catch {
    return json(response, 400, { error: "invalid_json" });
  }

  // Validate body size (8 KiB)
  const bodyStr = JSON.stringify(body);
  if (bodyStr.length > 8192) return json(response, 400, { error: "body_too_large" });

  const findingId    = typeof body?.finding_id    === "string" ? body.finding_id.trim()    : "";
  const status       = typeof body?.status        === "string" ? body.status.trim()        : "";
  const disposition  = typeof body?.disposition   === "string" ? body.disposition.trim()   : "";
  const note         = typeof body?.note          === "string" ? body.note.slice(0, 2000)  : "";
  const revision     = typeof body?.revision      === "number" ? body.revision             : 1;
  const requestUuid  = typeof body?.request_uuid  === "string" ? body.request_uuid.trim()  : "";

  if (!findingId || findingId.length > 64) return json(response, 400, { error: "invalid_finding_id" });
  if (!requestUuid || requestUuid.length > 64) return json(response, 400, { error: "invalid_request_uuid" });

  try {
    const rpcResp = await fetch(`${process.env.SUPABASE_URL}/rest/v1/rpc/upsert_finding_review`, {
      method: "POST",
      headers: serviceHeaders(),
      body: JSON.stringify({
        p_finding_id:   findingId,
        p_status:       status,
        p_disposition:  disposition,
        p_note:         note,
        p_actor:        auth.userId,
        p_revision:     revision,
        p_request_uuid: requestUuid,
      }),
    });

    if (rpcResp.status === 409 || (rpcResp.status >= 400 && rpcResp.status < 500)) {
      const err = await rpcResp.json().catch(() => ({}));
      const msg = err?.message ?? err?.hint ?? "conflict";
      if (msg.includes("revision_conflict")) return json(response, 409, { error: "revision_conflict" });
      if (msg.includes("invalid_transition")) return json(response, 400, { error: "invalid_transition" });
      if (msg.includes("disposition_required")) return json(response, 400, { error: "disposition_required_for_resolved" });
      return json(response, 400, { error: "invalid_request", message: msg });
    }
    if (!rpcResp.ok) return json(response, 502, { error: "upstream_unavailable" });

    const review = await rpcResp.json();
    return json(response, 200, { ok: true, review });
  } catch {
    return json(response, 502, { error: "upstream_unavailable" });
  }
}

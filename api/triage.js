import { checkBearer } from "../lib/auth.js";
import { serviceHeaders } from "../lib/supabase.js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

function json(response, status, body) {
  response.status(status).json(body);
}

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return json(response, 405, { error: "method_not_allowed" });
  }

  const auth = checkBearer(request, process.env.TRIAGE_TOKEN);
  if (!auth.ok) {
    return json(response, auth.reason === "server_misconfigured" ? 500 : 401, { error: "unauthorized" });
  }

  let body;
  try {
    body = typeof request.body === "string" ? JSON.parse(request.body) : request.body;
  } catch (_err) {
    return json(response, 400, { error: "invalid_json" });
  }

  const findingId = typeof body?.finding_id === "string" ? body.finding_id.trim() : "";
  const action = typeof body?.action === "string" ? body.action.trim() : "";
  if (!findingId || findingId.length > 64) {
    return json(response, 400, { error: "invalid_finding_id" });
  }
  if (action !== "false_positive") {
    return json(response, 400, { error: "unsupported_action" });
  }

  if (!SUPABASE_URL || !ANON_KEY) {
    return json(response, 500, { error: "server_misconfigured" });
  }

  try {
    // 1. Record the triage action (service role, insert-only audit trail).
    const actionResp = await fetch(`${SUPABASE_URL}/rest/v1/triage_actions`, {
      method: "POST",
      headers: serviceHeaders({ Prefer: "return=minimal" }, "api/triage.js"),
      body: JSON.stringify({ finding_id: findingId, action })
    });
    if (!actionResp.ok) {
      return json(response, 502, { error: "triage_log_failed" });
    }

    // 2. Suppress the finding: RLS public-read policy hides suppressed rows from the dashboard.
    const patchResp = await fetch(
      `${SUPABASE_URL}/rest/v1/findings?id=eq.${encodeURIComponent(findingId)}`,
      {
        method: "PATCH",
        headers: serviceHeaders({ Prefer: "return=minimal" }, "api/triage.js"),
        body: JSON.stringify({ suppressed: true })
      }
    );
    if (!patchResp.ok) {
      return json(response, 502, { error: "finding_update_failed" });
    }

    return json(response, 200, { ok: true, finding_id: findingId, action, state: "pending_verification" });
  } catch (_err) {
    return json(response, 502, { error: "upstream_unavailable" });
  }
}

import { configured, getState } from "../lib/supabase.js";

export default async function handler(request, response) {
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const row = await getState("ct_poll_status");
    response.status(200).json({
      storage_configured: configured(),
      status: row?.value || { ok: false, message: "No CT poll has run yet." },
      updated_at: row?.updated_at || null
    });
  } catch (error) {
    response.status(500).json({ error: "source_status_failed", message: error.message });
  }
}

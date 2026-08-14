import { configured, listFindings } from "../lib/supabase.js";

export default async function handler(request, response) {
  if (request.method !== "GET") {
    response.setHeader("Allow", "GET");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  try {
    const limit = request.query?.limit || 50;
    const findings = await listFindings(limit);
    response.status(200).json({
      storage_configured: configured(),
      findings
    });
  } catch (error) {
    response.status(500).json({ error: "findings_query_failed", message: error.message });
  }
}

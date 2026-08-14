import { loadData } from "../lib/data.js";
import { scoreCertificate } from "../lib/scoring.js";
import { configured, upsertFindings } from "../lib/supabase.js";

function authorized(request) {
  const expected = process.env.INGEST_TOKEN;
  if (!expected && process.env.VERCEL_ENV === "production") return false;
  if (!expected) return true;

  const authorization = request.headers.authorization || "";
  const bearer = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  return bearer === expected || request.headers["x-ingest-token"] === expected;
}

function entriesFromBody(body) {
  if (Array.isArray(body)) return body;
  if (Array.isArray(body?.entries)) return body.entries;
  if (Array.isArray(body?.certificates)) return body.certificates;
  if (body?.message_type === "certificate_update") return [body.data || body];
  return [body];
}

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  if (!authorized(request)) {
    response.status(process.env.INGEST_TOKEN ? 401 : 503).json({
      error: process.env.INGEST_TOKEN ? "unauthorized" : "ingest_not_configured"
    });
    return;
  }

  try {
    const data = loadData();
    const entries = entriesFromBody(request.body).filter(Boolean);
    const findings = entries
      .map((entry) => scoreCertificate(entry, data))
      .filter(Boolean);

    const persisted = await upsertFindings(findings);
    response.status(200).json({
      received: entries.length,
      matched: findings.length,
      storage_configured: configured(),
      persisted: persisted.length,
      findings: configured() ? persisted : findings
    });
  } catch (error) {
    response.status(500).json({ error: "ingest_failed", message: error.message });
  }
}

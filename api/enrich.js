import { enrichDomain } from "../lib/domain/enrichment.js";
import { normalizeHost } from "../lib/domain/registrable.js";

export default async function handler(request, response) {
  if (request.method !== "GET" && request.method !== "POST") {
    response.setHeader("Allow", "GET, POST");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  const domain = request.query?.domain || request.body?.domain;
  if (!domain || typeof domain !== "string") {
    response.status(400).json({ error: "missing_domain", message: "Parameter 'domain' is required" });
    return;
  }

  try {
    const host = normalizeHost(domain);
    const enrichment = await enrichDomain(host);
    response.status(200).json(enrichment);
  } catch (error) {
    response.status(500).json({ error: "enrichment_failed", message: error.message });
  }
}

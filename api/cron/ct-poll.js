import { loadData } from "../../lib/data.js";
import { scoreCertificate } from "../../lib/scoring.js";
import { getState, setState, upsertFindings } from "../../lib/supabase.js";

const BATCH_SIZE = 4;
const RESULT_LIMIT = 25;
const LOOKBACK_DAYS = 14;

function authorized(request) {
  const expected = process.env.CRON_SECRET;
  if (!expected) return process.env.VERCEL_ENV !== "production";
  return request.headers.authorization === `Bearer ${expected}`;
}

function compact(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function pollTokens(data) {
  const brandTokens = data.watchlist.brands
    .flatMap((brand) => brand.tokens || [])
    .filter((token) => compact(token).length >= 3);
  const schemeTokens = data.schemes.schemes.flatMap((scheme) => scheme.tokens || []);
  return [...new Set([...schemeTokens, ...brandTokens])].sort();
}

function crtRowToEntry(row, token) {
  const domains = String(row.name_value || "")
    .split(/\s+/)
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean);

  return {
    dns_names: domains,
    common_name: row.common_name || domains[0] || "",
    not_before: row.not_before || row.entry_timestamp || null,
    issuer: { aggregated: row.issuer_name || "" },
    cert_index: row.id || row.min_cert_id || null,
    cert_link: row.id ? `https://crt.sh/?id=${row.id}` : `crtsh:${token}`,
    seen: row.entry_timestamp ? Date.parse(row.entry_timestamp) / 1000 : Date.now() / 1000,
    source: "crtsh_token_search"
  };
}

async function queryCrtSh(token) {
  const url = new URL("https://crt.sh/");
  url.searchParams.set("q", `%${token}%`);
  url.searchParams.set("output", "json");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  let response;
  try {
    response = await fetch(url, {
      headers: { "User-Agent": "sgCertWatch/0.1 (+https://sgcertwatch.vercel.app)" },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    throw new Error(`crt.sh ${response.status}`);
  }

  const rows = await response.json();
  const cutoff = Date.now() - LOOKBACK_DAYS * 24 * 60 * 60 * 1000;
  return rows
    .filter((row) => {
      const timestamp = Date.parse(row.entry_timestamp || row.not_before || "");
      return Number.isNaN(timestamp) || timestamp >= cutoff;
    })
    .slice(0, RESULT_LIMIT)
    .map((row) => crtRowToEntry(row, token));
}

export default async function handler(request, response) {
  if (!["GET", "POST"].includes(request.method)) {
    response.setHeader("Allow", "GET, POST");
    response.status(405).json({ error: "method_not_allowed" });
    return;
  }

  if (!authorized(request)) {
    response.status(401).json({ error: "unauthorized" });
    return;
  }

  const data = loadData();
  const tokens = pollTokens(data);
  const state = await getState("ct_poll_cursor");
  const start = Number(state?.value?.index || 0) % tokens.length;
  const batch = Array.from({ length: BATCH_SIZE }, (_, offset) => tokens[(start + offset) % tokens.length]);

  const errors = [];
  const entries = [];
  for (const token of batch) {
    try {
      entries.push(...await queryCrtSh(token));
    } catch (error) {
      errors.push({ token, message: error.message });
    }
  }

  const findings = entries
    .map((entry) => scoreCertificate(entry, data))
    .filter(Boolean);
  const persisted = await upsertFindings(findings);
  const nextIndex = (start + BATCH_SIZE) % tokens.length;

  await setState("ct_poll_cursor", { index: nextIndex });
  const status = {
    ok: errors.length === 0,
    source: "crt.sh public JSON search",
    checked_at: new Date().toISOString(),
    batch,
    scanned_entries: entries.length,
    matched: findings.length,
    persisted: persisted.length,
    errors
  };
  await setState("ct_poll_status", status);

  response.status(200).json(status);
}

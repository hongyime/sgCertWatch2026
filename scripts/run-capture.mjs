// H-1 (15R): GitHub Actions capture pipeline — Actions only, never Vercel (DECISION-04).
// Visits each high-scoring finding with Playwright, records HTTP status/title/server/
// cloaking signal, and stores in the captures table for stage-2 verification.
import { chromium } from "playwright";
import crypto from "node:crypto";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY  = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ALERT_MIN    = parseInt(process.env.ALERT_MIN_SCORE || "70", 10);
const MAX_CAPTURES = parseInt(process.env.MAX_CAPTURES || "50", 10);
const TIMEOUT_MS   = parseInt(process.env.PAGE_TIMEOUT_MS || "20000", 10);

const HEADERS = {
  Authorization: `Bearer ${SERVICE_KEY}`,
  "Content-Type": "application/json",
  apikey: SERVICE_KEY
};

async function getUncaptured() {
  const since = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
  const url = `${SUPABASE_URL}/rest/v1/findings?select=id,registrable,domains,score` +
    `&score=gte.${ALERT_MIN}&suppressed=eq.false&observed_at=gte.${since}` +
    `&order=score.desc&limit=${MAX_CAPTURES}`;
  const r = await fetch(url, { headers: { ...HEADERS, apikey: HEADERS.apikey } });
  if (!r.ok) throw new Error(`findings query ${r.status}`);
  const findings = await r.json();

  // Exclude already-captured this week
  const capUrl = `${SUPABASE_URL}/rest/v1/captures?select=finding_id&captured_at=gte.${since}`;
  const cr = await fetch(capUrl, { headers: { ...HEADERS, apikey: HEADERS.apikey } });
  const captured = cr.ok ? new Set((await cr.json()).map(c => c.finding_id)) : new Set();

  return findings.filter(f => !captured.has(f.id));
}

async function faviconFingerprint(page, baseUrl) {
  try {
    const resp = await page.request.get(`${baseUrl}/favicon.ico`, { timeout: 5000 });
    if (!resp.ok()) return null;
    const buf = await resp.body();
    return crypto.createHash("sha256").update(buf).digest("hex").slice(0, 16);
  } catch (_) { return null; }
}

async function captureDomain(domain, findingId) {
  const url = `https://${domain}`;
  const browser = await chromium.launch({ headless: true });
  const detail = {};
  let result = { finding_id: findingId, captured_at: new Date().toISOString(),
    http_status: null, title: null, server: null, favicon_mmh3: null,
    cloaking_detected: false, screenshot_url: null, detail: {} };

  try {
    // Pass 1: browser-like UA
    const ctx1 = await browser.newContext({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36"
    });
    const page1 = await ctx1.newPage();
    let resp1;
    try {
      resp1 = await page1.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT_MS });
    } catch (_) {}
    const status1 = resp1?.status() ?? null;
    const title1  = await page1.title().catch(() => null);
    const server1 = resp1?.headers()?.["server"] ?? null;
    const favicon1 = resp1 ? await faviconFingerprint(page1, url).catch(()=>null) : null;
    detail.pass1 = { status: status1, title: title1 };

    // Pass 2: bot-like UA (cloaking detection)
    const ctx2 = await browser.newContext({ userAgent: "Googlebot/2.1 (+http://www.google.com/bot.html)" });
    const page2 = await ctx2.newPage();
    let resp2;
    try { resp2 = await page2.goto(url, { waitUntil: "domcontentloaded", timeout: TIMEOUT_MS }); } catch (_) {}
    const title2 = await page2.title().catch(() => null);
    detail.pass2 = { status: resp2?.status() ?? null, title: title2 };

    // Cloaking: significantly different content between passes
    const cloaking = title1 && title2 && title1 !== title2 &&
      (title2.toLowerCase().includes("error") || title2.toLowerCase().includes("not found") ||
       (title1.length > 10 && title2.length < 5));

    result = {
      ...result,
      http_status: status1,
      title: title1,
      server: server1,
      favicon_mmh3: favicon1,
      cloaking_detected: Boolean(cloaking),
      detail
    };
    await ctx1.close();
    await ctx2.close();
  } catch (err) {
    result.detail = { error: err.message };
  } finally {
    await browser.close();
  }
  return result;
}

async function storeCapture(capture) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/captures`, {
    method: "POST",
    headers: { ...HEADERS, Prefer: "return=minimal" },
    body: JSON.stringify(capture)
  });
  if (!r.ok) {
    const msg = await r.text();
    console.error(`store capture failed: ${r.status} ${msg}`);
  }
}

async function main() {
  if (!SUPABASE_URL || !SERVICE_KEY) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
    process.exit(1);
  }
  const findings = await getUncaptured();
  console.log(`Capturing ${findings.length} findings...`);
  let done = 0;
  for (const f of findings) {
    const domain = f.registrable || (f.domains || [])[0];
    if (!domain) continue;
    console.log(`  [${++done}/${findings.length}] ${domain} (score ${f.score})`);
    const capture = await captureDomain(domain, f.id);
    await storeCapture(capture);
  }
  console.log(`Capture run complete: ${done} processed.`);
}

main().catch(e => { console.error(e); process.exit(1); });

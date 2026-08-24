import dns from "node:dns/promises";
import https from "node:https";
import http from "node:http";

const DEFAULT_TIMEOUT_MS = 4000;
const USER_AGENT = "sgCertWatch/2.0 (Security Threat Research Monitor; +https://sgcertwatch.vercel.app)";

/**
 * Resolve DNS records for a domain with timeout handling
 */
export async function resolveDns(domain, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const result = {
    a: [],
    aaaa: [],
    cname: [],
    mx: [],
    ns: []
  };

  const resolveWithTimeout = (promise) =>
    Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error("DNS timeout")), timeoutMs))
    ]);

  try {
    const a = await resolveWithTimeout(dns.resolve4(domain));
    result.a = a;
  } catch {
    // Expected if no A record
  }

  try {
    const aaaa = await resolveWithTimeout(dns.resolve6(domain));
    result.aaaa = aaaa;
  } catch {
    // Expected if no AAAA record
  }

  try {
    const cname = await resolveWithTimeout(dns.resolveCname(domain));
    result.cname = cname;
  } catch {
    // Expected if no CNAME
  }

  try {
    const mx = await resolveWithTimeout(dns.resolveMx(domain));
    result.mx = mx.map((m) => ({ exchange: m.exchange, priority: m.priority }));
  } catch {
    // Expected if no MX
  }

  try {
    const ns = await resolveWithTimeout(dns.resolveNs(domain));
    result.ns = ns;
  } catch {
    // Expected if no NS
  }

  return result;
}

/**
 * Probes HTTP/HTTPS endpoint for live status, title, server header, and redirects
 */
export async function probeHttp(domain, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = globalThis.fetch) {
  const result = {
    live: false,
    status: null,
    final_url: null,
    title: null,
    server: null,
    content_type: null,
    error: null
  };

  if (!fetchImpl) {
    return result;
  }

  const urlsToTry = [`https://${domain}`, `http://${domain}`];

  for (const url of urlsToTry) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const resp = await fetchImpl(url, {
        method: "GET",
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent": USER_AGENT,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
      });
      clearTimeout(timer);

      result.live = true;
      result.status = resp.status;
      result.final_url = resp.url;
      result.server = resp.headers.get("server") || null;
      result.content_type = resp.headers.get("content-type") || null;

      const text = await resp.text().catch(() => "");
      const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (titleMatch && titleMatch[1]) {
        result.title = titleMatch[1].trim().slice(0, 200);
      }

      // If we got a successful or meaningful response, stop
      break;
    } catch (err) {
      result.error = err.message || String(err);
    }
  }

  return result;
}

/**
 * Fetch RDAP registration data with timeout
 */
export async function queryRdap(domain, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = globalThis.fetch) {
  const result = {
    created_at: null,
    updated_at: null,
    expires_at: null,
    registrar: null,
    status: [],
    error: null
  };

  if (!fetchImpl) return result;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    const resp = await fetchImpl(rdapUrl, {
      method: "GET",
      signal: controller.signal,
      headers: {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": USER_AGENT
      }
    });
    clearTimeout(timer);

    if (resp.ok) {
      const data = await resp.json();
      if (Array.isArray(data.events)) {
        for (const ev of data.events) {
          if (ev.eventAction === "registration") result.created_at = ev.eventDate;
          if (ev.eventAction === "last changed" || ev.eventAction === "last update") result.updated_at = ev.eventDate;
          if (ev.eventAction === "expiration") result.expires_at = ev.eventDate;
        }
      }
      if (Array.isArray(data.status)) {
        result.status = data.status;
      }
      if (Array.isArray(data.entities)) {
        const registrarEntity = data.entities.find((e) => Array.isArray(e.roles) && e.roles.includes("registrar"));
        if (registrarEntity?.vcardArray?.[1]) {
          const fnRow = registrarEntity.vcardArray[1].find((row) => row[0] === "fn");
          if (fnRow) result.registrar = fnRow[3];
        }
      }
    }
  } catch (err) {
    result.error = err.message || String(err);
  }

  return result;
}

/**
 * Full domain active capture & enrichment pipeline
 */
export async function enrichDomain(domain, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetch ?? globalThis.fetch;

  const [dnsResult, httpResult, rdapResult] = await Promise.all([
    resolveDns(domain, timeoutMs).catch(() => ({ a: [], aaaa: [], cname: [], mx: [], ns: [] })),
    probeHttp(domain, timeoutMs, fetchImpl).catch(() => ({ live: false })),
    options.skipRdap ? Promise.resolve(null) : queryRdap(domain, timeoutMs, fetchImpl).catch(() => null)
  ]);

  const hasDns = Boolean(dnsResult.a.length || dnsResult.aaaa.length || dnsResult.cname.length);
  const isLive = Boolean(hasDns || httpResult.live);

  return {
    domain,
    enriched_at: new Date().toISOString(),
    live: isLive,
    dns: dnsResult,
    http: httpResult,
    rdap: rdapResult
  };
}

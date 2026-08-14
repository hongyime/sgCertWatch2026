const FIREHOSE_URL = "https://api.certspotter.com/v1/issuances/firehose";
const CURSOR_KEY = "certspotter_after";
const STATUS_KEY = "status";

function json(data, init = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      ...(init.headers || {})
    }
  });
}

function toIngestEntry(issuance) {
  return {
    dns_names: issuance.dns_names || [],
    not_before: issuance.not_before || null,
    issuer: {
      aggregated: issuance.issuer?.friendly_name || issuance.issuer?.name || ""
    },
    cert_index: issuance.id,
    cert_link: `certspotter:${issuance.id}`,
    seen: Math.floor(Date.now() / 1000),
    source: "certspotter_firehose"
  };
}

async function writeStatus(env, status) {
  await env.SG_CERTWATCH_STATE.put(STATUS_KEY, JSON.stringify({
    checked_at: new Date().toISOString(),
    ...status
  }));
}

async function pollFirehose(env) {
  if (!env.INGEST_URL || !env.INGEST_TOKEN) {
    await writeStatus(env, { ok: false, error: "missing_ingest_configuration" });
    return { ok: false, error: "missing_ingest_configuration" };
  }

  const after = await env.SG_CERTWATCH_STATE.get(CURSOR_KEY);
  const url = new URL(FIREHOSE_URL);
  url.searchParams.set("expand", "dns_names");
  url.searchParams.append("expand", "issuer");
  if (after) url.searchParams.set("after", after);

  const response = await fetch(url, {
    headers: env.CERTSPOTTER_API_TOKEN
      ? { Authorization: `Bearer ${env.CERTSPOTTER_API_TOKEN}` }
      : {}
  });

  const bodyText = await response.text();
  if (!response.ok) {
    const status = {
      ok: false,
      upstream_status: response.status,
      retry_after: response.headers.get("Retry-After"),
      error: bodyText.slice(0, 500)
    };
    await writeStatus(env, status);
    return status;
  }

  const issuances = JSON.parse(bodyText);
  if (!Array.isArray(issuances)) {
    const status = { ok: false, error: "unexpected_firehose_response" };
    await writeStatus(env, status);
    return status;
  }

  if (issuances.length > 0) {
    await env.SG_CERTWATCH_STATE.put(CURSOR_KEY, issuances.at(-1).id);
  }

  const entries = issuances.map(toIngestEntry);
  let ingestResult = { matched: 0, persisted: 0 };
  if (entries.length > 0) {
    const ingestResponse = await fetch(env.INGEST_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.INGEST_TOKEN}`
      },
      body: JSON.stringify({ entries })
    });

    ingestResult = await ingestResponse.json();
    if (!ingestResponse.ok) {
      const status = {
        ok: false,
        upstream_count: issuances.length,
        ingest_status: ingestResponse.status,
        error: ingestResult
      };
      await writeStatus(env, status);
      return status;
    }
  }

  const status = {
    ok: true,
    upstream_count: issuances.length,
    matched: ingestResult.matched || 0,
    persisted: ingestResult.persisted || 0,
    cursor: issuances.at(-1)?.id || after || null,
    retry_after: response.headers.get("Retry-After")
  };
  await writeStatus(env, status);
  return status;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/status") {
      const status = await env.SG_CERTWATCH_STATE.get(STATUS_KEY, "json");
      return json(status || { ok: false, error: "no_status_yet" });
    }

    if (url.pathname === "/run") {
      const expected = env.WORKER_RUN_TOKEN;
      const authorization = request.headers.get("Authorization") || "";
      if (expected && authorization !== `Bearer ${expected}`) {
        return json({ error: "unauthorized" }, { status: 401 });
      }
      return json(await pollFirehose(env));
    }

    return json({
      name: "sgcertwatch-ct-firehose",
      status: "/status",
      run: "/run"
    });
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(pollFirehose(env));
  }
};

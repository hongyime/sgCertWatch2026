import { SchedulerEngine } from "./core.mjs";

function json(data, status = 200) {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}

async function authorized(request, token) {
  if (!token || token.length < 32) return false;
  const supplied = request.headers.get("Authorization") || "";
  if (supplied.length > 1024) return false;
  const encoder = new TextEncoder();
  const [a, b] = await Promise.all([supplied, `Bearer ${token}`].map(value => crypto.subtle.digest("SHA-256", encoder.encode(value))));
  const left = new Uint8Array(a);
  const right = new Uint8Array(b);
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

function coordinator(env) {
  return env.SCHEDULER.get(env.SCHEDULER.idFromName("sgcertwatch-scheduler-v1"));
}

// Fetch-only Durable Objects support a plain exported class, with no runtime dependency.
export class SchedulerCoordinator {
  constructor(ctx, env) { this.storage = ctx.storage; this.env = env; }

  async fetch(request) {
    const url = new URL(request.url);
    const engine = new SchedulerEngine(this.storage, this.env);
    try {
      if (request.method === "GET" && url.pathname === "/status") {
        const status = await engine.status();
        return json(status, status.ok ? 200 : 503);
      }
      if (request.method === "POST" && url.pathname === "/tick") {
        const result = await engine.tick(Number(url.searchParams.get("scheduledAt")));
        return json(result, result.ok ? 200 : 503);
      }
      return json({ error: "not_found" }, 404);
    } catch {
      console.error(JSON.stringify({ component: "scheduler", error: "coordinator_failure" }));
      return json({ error: "coordinator_failure" }, 503);
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/status") return json({ error: "not_found" }, 404);
    if (!env.STATUS_TOKEN || env.STATUS_TOKEN.length < 32) return json({ error: "status_unconfigured" }, 503);
    if (!await authorized(request, env.STATUS_TOKEN)) return json({ error: "unauthorized" }, 401);
    if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
    try { return await coordinator(env).fetch(new Request("https://coordinator/status")); }
    catch { return json({ error: "coordinator_unavailable" }, 503); }
  },

  async scheduled(controller, env) {
    try {
      const response = await coordinator(env).fetch(new Request(
        `https://coordinator/tick?scheduledAt=${controller.scheduledTime}`, { method: "POST" }));
      if (!response.ok) throw new Error("scheduler_tick_failed");
    } catch {
      // Reject scheduled execution so Cloudflare records a failed invocation.
      console.error(JSON.stringify({ component: "scheduler", error: "scheduler_tick_failed" }));
      throw new Error("scheduler_tick_failed");
    }
  }
};

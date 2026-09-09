import { SchedulerEngine, STATE_KEY, WORKFLOWS, MINUTE } from "../core.mjs";

export class FakeStorage {
  constructor() { this.values = new Map(); this.tail = Promise.resolve(); this.writes = 0; }
  async get(key) { return structuredClone(this.values.get(key)); }
  async transaction(callback) {
    const previous = this.tail;
    let release;
    this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    const draft = new Map(structuredClone([...this.values]));
    try {
      const result = await callback({
        get: async key => structuredClone(draft.get(key)),
        put: async (key, value) => {
          if (this.failPut?.(value)) throw new Error("storage failure must not leak private details");
          draft.set(key, structuredClone(value));
          this.writes++;
        }
      });
      this.values = draft;
      return result;
    } finally { release(); }
  }
  async seed(change) {
    const state = await this.get(STATE_KEY);
    change(state);
    this.values.set(STATE_KEY, structuredClone(state));
  }
}

export const BASE_TIME = Date.parse("2026-09-08T00:00:00Z");
export const TEST_ENV = {
  GITHUB_OWNER: "owner", GITHUB_REPO: "repo", GITHUB_REF: "main",
  GITHUB_TOKEN: "repo-scoped-test-token", STATUS_TOKEN: "protected-status-test-token-32-characters",
  DISPATCH_ENABLED: "true"
};

export function run(now, options = {}) {
  return { id: 1, status: "completed", conclusion: "success", event: "schedule", head_branch: "main",
    created_at: new Date(now - 20 * MINUTE).toISOString(), run_started_at: new Date(now - 20 * MINUTE).toISOString(),
    updated_at: new Date(now - MINUTE).toISOString(), ...options };
}

export function harness(options = {}) {
  const h = { time: BASE_TIME, env: { ...TEST_ENV, ...options.env }, storage: options.storage || new FakeStorage(),
    calls: [], rows: Object.fromEntries(WORKFLOWS.map(w => [w.file, []])), heartbeatRows: [],
    dispatchStatus: 204, visibleDispatch: true, nextId: 100, timeoutMs: options.timeoutMs || 1000 };
  h.fetch = async (input, init = {}) => {
    const url = new URL(input);
    h.calls.push({ url, init });
    const overridden = await h.override?.(url, init, h);
    if (overridden !== undefined) return overridden;
    if (url.hostname === "api.github.com") {
      const workflow = url.pathname.split("/").at(-2);
      if (!h.rows[workflow]) throw new Error("unexpected workflow");
      if (url.pathname.endsWith("/dispatches")) {
        const id = h.nextId++;
        if (h.visibleDispatch) h.rows[workflow].unshift(run(h.time, { id, status: "queued", conclusion: null,
          event: "workflow_dispatch", created_at: new Date(h.time).toISOString(),
          run_started_at: new Date(h.time).toISOString(), updated_at: new Date(h.time).toISOString() }));
        return h.dispatchStatus === 200 ? Response.json({ workflow_run_id: id }) : new Response(null, { status: h.dispatchStatus });
      }
      const branch = url.searchParams.get("branch");
      const status = url.searchParams.get("status");
      const rows = h.rows[workflow].filter(r => (!branch || r.head_branch === branch)
        && (!status || r.status === status || r.conclusion === status))
        .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
      return Response.json({ total_count: rows.length, workflow_runs: rows.slice(0, Number(url.searchParams.get("per_page"))) });
    }
    if (url.hostname.endsWith(".supabase.co")) {
      const keys = url.searchParams.get("key").slice(4, -1).split(",");
      return Response.json(h.heartbeatRows.filter(row => keys.includes(row.key)));
    }
    if (url.hostname === "alerts.example.test") return new Response("OK", { status: 200 });
    throw new Error("unexpected external destination");
  };
  h.engine = () => new SchedulerEngine(h.storage, h.env, { fetch: h.fetch, now: () => h.time, timeoutMs: h.timeoutMs });
  h.tick = (scheduledAt = h.time) => h.engine().tick(scheduledAt);
  h.advance = minutes => { h.time += minutes * MINUTE; };
  h.state = () => h.storage.get(STATE_KEY);
  h.status = () => h.engine().status();
  h.dispatches = file => h.calls.filter(c => c.url.pathname.endsWith("/dispatches") && (!file || c.url.pathname.includes(file)));
  h.alerts = () => h.calls.filter(c => c.url.hostname === "alerts.example.test");
  h.healthy = (minutesAgo = 1) => {
    for (const w of WORKFLOWS) h.rows[w.file] = [run(h.time, { id: h.nextId++,
      created_at: new Date(h.time - minutesAgo * MINUTE).toISOString(),
      run_started_at: new Date(h.time - minutesAgo * MINUTE).toISOString(),
      updated_at: new Date(h.time - minutesAgo * MINUTE).toISOString() })];
  };
  return h;
}

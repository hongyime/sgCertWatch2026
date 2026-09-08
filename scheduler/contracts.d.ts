export interface SchedulerEnv {
  SCHEDULER: { idFromName(name: string): unknown; get(id: unknown): { fetch(request: Request): Promise<Response> } };
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
  GITHUB_REF: string;
  GITHUB_TOKEN: string;
  STATUS_TOKEN: string;
  DISPATCH_ENABLED?: "true" | "false";
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
  ALERT_WEBHOOK_URL?: string;
  ALERT_WEBHOOK_SECRET?: string;
  SUPABASE_URL?: string;
  SUPABASE_PUBLISHABLE_KEY?: string;
}

export interface TransactionStorage {
  get(key: string): Promise<any>;
  put(key: string, value: any): Promise<void>;
  transaction<T>(callback: (transaction: TransactionStorage) => Promise<T>): Promise<T>;
}

export interface RuntimeDependencies {
  fetch?: typeof fetch;
  now?: () => number;
  uuid?: () => string;
  timeoutMs?: number;
}

// All persisted/status timestamps are UTC epoch milliseconds. No raw API payloads
// or exception messages enter status, storage, alerts or application logs.
export interface RunSummary {
  id: number;
  status: string;
  conclusion: string | null;
  createdAt: number;
  startedAt: number;
  updatedAt: number;
  dispatch: boolean;
}

// Parent integration contract:
// - ingest.yml, intel.yml and notifications.yml accept workflow_dispatch with
//   inputs: {scheduler: "cloudflare"}. Parent owns these workflow definitions.
// - Parent maintains workflow concurrency and an atomic DB execution lock.
//   GitHub schedules/manual triggers can race the final read/dispatch boundary.
// - Optional anon RLS permits ONLY a SELECT of ct_poll_status/intel_poll_status/
//   notifications_poll_status
//   in public.ingest_state. last_success_at is preferred for CT scan freshness;
//   checked_at is the legacy fallback only for a healthy completed pipeline.
//   last_external_trigger_at is read for provenance and never treated as progress.
//   Notifications publish pending, processing, dead, oldest_pending_at, state,
//   checked_at, started_at, finished_at. No payloads/recipients or RPC calls are read.
//   Any dead letters trigger critical; pending age triggers warning >=30m/critical >=60m.
// - Actual scan recency comes from last_started_at before any dispatch, regardless
//   of successful skipped fallback workflows. Active GitHub runs still block dispatch.
//   CT/intel use the parent's 14m/55m actual-start minimum with durable 15m/60m
//   dispatch slots. Confirmed own dispatches use the same slack, preventing a
//   30-second queue delay or request jitter from turning 15-minute cadence into 20.
//   Reservations record origin and run_id versus time_window correlation.
//   Heartbeat validation/freshness is per workflow. Transport/JSON failure is
//   global; absent/malformed sibling rows cannot stop a workflow with valid data.
//   A never-observed missing row bootstraps through GitHub recency + reservations;
//   losing or corrupting an established heartbeat gates only its own scan.
// - workflow.metrics stores unique actual start/success counts, timestamps and max
//   gaps since configuredSince. soak.workflows has the same counters for the current
//   active window (valid config, dispatch enabled, heartbeat + alert channel configured).
//   observedActiveMs excludes gaps >10m; elapsedActiveMs alone is not soak evidence.
//   No automatic 24h pass is asserted. Parent verifies counts, gaps, freshness,
//   continuous active duration, alert configuration and GitHub history separately.
//   ok=false or health=down/degraded must not count as healthy progress.
// - GH success proves workflow completion, not data persistence when a job skips.
//   Enable the direct heartbeat to detect successful-but-skipped/no-progress runs.
// - GET /status requires Authorization: Bearer STATUS_TOKEN; no mutation route.
// - Neither GitHub dispatch nor Telegram sendMessage has an idempotency key.
//   Unknown dispatch outcomes hold for two intervals before rechecking/retrying;
//   Alert transitions retry unknown outcomes after a >=5m exponential cooldown,
//   honor longer server Retry-After, and dead-letter after five attempts. Expired
//   sending leases are recoverable. A lost response can duplicate delivery:
//   the stable event ID lets webhook receivers implement their own deduplication.
//   Recovery retains previousNotice and queues a resolved-incident summary when
//   an alert was attempted or awaiting a configured channel. Pending recovery
//   keeps status nonhealthy until acknowledged; unconfigured never-attempted
//   incidents may close without a message. Known 429 headers survive body timeout.
// - A webhook is configured only via ALERT_WEBHOOK_URL (HTTPS), never request input.
//   Optional ALERT_WEBHOOK_SECRET is sent as a Bearer header. Payload schema v1:
//   {schema_version, source, event_id, subject, kind, observed_at,
//    resolved_before_delivery, prior_delivery_state, recovered_at}; event_id is stable
//   across explicit rejection retries. Receivers should deduplicate that ID.
//   Telegram takes precedence when both complete channels are configured.

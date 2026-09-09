export interface SchedulerEnv {
  SCHEDULER: { idFromName(name: string): unknown; get(id: unknown): { fetch(request: Request): Promise<Response> } };
  GITHUB_OWNER: string;
  GITHUB_REPO: string;
  GITHUB_REF: string;
  GITHUB_TOKEN: string;
  STATUS_TOKEN: string;
  DISPATCH_ENABLED?: "true" | "false";
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
// - ingest.yml and intel.yml accept workflow_dispatch with
//   inputs: {scheduler: "cloudflare"}. Parent owns these workflow definitions.
// - Parent maintains workflow concurrency and an atomic DB execution lock.
//   GitHub schedules/manual triggers can race the final read/dispatch boundary.
// - Optional anon RLS permits ONLY a SELECT of ct_poll_status/intel_poll_status
//   in public.ingest_state. last_success_at is preferred for CT scan freshness;
//   checked_at is the legacy fallback only for a healthy completed pipeline.
//   last_external_trigger_at is read for provenance and never treated as progress.
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
//   active window (valid config, dispatch enabled, heartbeat configured).
//   config.monitoringMode and soak.monitoringMode are "dashboard" or "webhook".
//   Dashboard is the default supported mode: config.alertChannel="none" and
//   config.proactiveAlerts=false. A valid ALERT_WEBHOOK_URL opts into webhook mode.
//   Dashboard health/soak never require delivery; active incidents still fail health.
//   observedActiveMs excludes gaps >10m; elapsedActiveMs alone is not soak evidence.
//   No automatic 24h pass is asserted. Parent verifies counts, gaps, freshness,
//   continuous active duration, CT/intel evidence and GitHub history separately.
//   Check delivery outcomes only in webhook mode, never require a notification worker.
//   ok=false or health=down/degraded must not count as healthy progress.
// - GH success proves workflow completion, not data persistence when a job skips.
//   Enable the direct heartbeat to detect successful-but-skipped/no-progress runs.
// - GET /status requires Authorization: Bearer STATUS_TOKEN; no mutation route.
// - GitHub dispatch has no idempotency key.
//   Unknown dispatch outcomes hold for two intervals before rechecking/retrying;
//   Alert transitions retry unknown outcomes after a >=5m exponential cooldown,
//   honor longer server Retry-After, and dead-letter after five attempts. Expired
//   sending leases are recoverable. A lost response can duplicate delivery:
//   the stable event ID lets webhook receivers implement their own deduplication.
//   Recovery retains previousNotice and queues a resolved-incident summary when
//   an alert was attempted or awaiting a configured webhook. Pending recovery
//   keeps webhook status nonhealthy until acknowledged. Known 429 headers survive
//   body timeout. Dashboard notices use state="dashboard_only", attempts=0; actual
//   recovery sets recoveredAt, preserves previousNotice and clears notice without
//   creating a recovery delivery or incrementing alertsDelivered. Historical failed,
//   unknown, sending, dead_letter or sent receipts are not rewritten by mode changes.
// - State version 2 uses the existing scheduler-v1 key and coordinator identity.
//   Migration preserves CT/intel state, metrics, reservations, leases, cooldowns,
//   incidents and configuredSince. Retired notification workflow/incident records
//   move to retiredSubjects.notifications and never affect health, delivery or soak.
//   workflows, assessments and soak.workflows contain only ingest and intel.
//   Assessment backlogAgeMs/backlogMonitoring and heartbeat.outbox are removed.
//   Migration projects read-only on GET and persists transactionally on a tick;
//   existing fencing still applies. Migration and monitoring-mode changes start
//   a fresh observed soak window on the next qualified tick. Old lifetime counters
//   remain intact; counters are never synthesized from elapsed time or receipts.
// - A webhook is configured only via ALERT_WEBHOOK_URL (HTTPS), never request input.
//   Optional ALERT_WEBHOOK_SECRET is sent as a Bearer header. Payload schema v1:
//   {schema_version, source, event_id, subject, kind, observed_at,
//    resolved_before_delivery, prior_delivery_state, recovered_at}; event_id is stable
//   across explicit rejection retries. Receivers should deduplicate that ID.

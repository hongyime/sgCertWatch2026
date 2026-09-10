# sgCertWatch2026

sgCertWatch2026 is a Singapore-focused Certificate Transparency monitoring dashboard. It collects the static watch lists, keyword lists, allow lists, and scheme metadata that define what the monitor should look for, and includes a deployable multi-source scoring and monitoring surface.

## What It Contains

- `watchlist.json` stores the domains and organisations to monitor.
- `keywords.json` stores matching terms used to classify certificate activity.
- `allowlist.json` stores expected or intentionally ignored certificate patterns.
- `schemes.json` stores structured scheme metadata for downstream dashboard work.
- `lib/scoring.js` scores CT certificate entries against the seed data.
- `lib/ct/` contains the CertStream, direct CT log, and `crt.sh` source adapters.
- `api/findings.js` exposes recent stored findings for the dashboard.
- `api/source-status.js` exposes source health for the dashboard.
- `.github/workflows/ingest.yml` polls CT sources on GitHub Actions with a 15-minute target.
## Usage

### Database storage maintenance

New databases use `supabase/schema.sql`. Existing databases can apply
`supabase/index-cleanup.sql` to remove the unused certificate-identity index
after reviewing current query usage. The September 10 audit found zero scans,
no dependent constraints/objects, and no identity-column lookup in the runtime.
The scanner computes the finding ID and upserts through its primary key.
The migration checks the exact index definition, aborts if it has changed, and
uses a one-second lock timeout and five-second statement timeout. It preserves
all findings, sightings, evidence, keys, policies and other indexes.

If a future identity lookup needs it, run `supabase/index-cleanup-rollback.sql`
as a standalone statement outside a transaction. It rebuilds the index
concurrently. This is a limited storage saving; retained history continues to
grow, and it does not by itself bring the database under the Free allowance.

Validate the seed data and scoring engine:

```bash
npm run validate
npm run test:unit
npm run test:intel
npm run test:reliability
```

## Ingestion

CT polling runs on GitHub Actions (`scripts/run-ingest.mjs`), which executes the multi-source
orchestrator directly against Supabase using repository secrets - no HTTP hop through Vercel.
Cursors stay in Supabase `ingest_state`, so a delayed or skipped run catches up on the next tick.

GitHub's fallback schedule targets `:07`, `:22`, `:37`, and `:52` UTC each hour. A September 8 audit found gaps of several hours. The independent Cloudflare dispatcher in `scheduler/` targets the same workflow every 15 minutes, with hourly intelligence. It dispatches and watches only these two scan workflows; scanning never runs on Cloudflare or Vercel. GitHub runner queues can still delay starts. See [GitHub's schedule limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

Required repository secrets: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`. The dashboard functions need `SUPABASE_URL` and `SUPABASE_ANON_KEY` only. Apply `supabase/schema.sql` for a new database, then `supabase/run-locks.sql` before deploying the reliability runners. No messaging credentials are required.

The poller samples CertStream, tails a rotating set of direct RFC6962 CT logs, reads Let's Encrypt logs through the Static CT API tile reader, and keeps `crt.sh` as a fallback comparison source. Findings and source health are stored in Supabase so the dashboard can show partial coverage instead of treating one source outage as a total outage.

The Actions job polls six direct logs with up to 128 entries each, and permits 30 tiles per static log within a 90-second static-source budget. Logs rotate across runs so later logs are not starved. Malformed responses retain the failed range for retry, while earlier completed static tiles are retained. HTTP 429 pauses sibling logs for at least one hour within each adapter, honoring longer `Retry-After` values. Cooldowns are saved before scoring and survive restarts or later write failures without advancing unsaved cursors. Other operators continue. Findings and CT sightings are saved in batches of 200 rows. These are sampling limits, not full CT coverage.

Primary health comes from direct/static CT, so an idle WebSocket or backup cannot hide a primary outage. Atomic service-only database leases supplement GitHub concurrency. Renewal/release are owner-checked, and cursor/status writes validate and lock the lease row in the same transaction. Database or lease failure stops checkpoint advancement. CT has a 13-minute execution deadline within its 15-minute lease; intel has seven minutes within ten. Recent-start gates prevent fallback dispatches from repeating expensive work.

Findings and sightings are saved before cursor advancement. Telegram notifications were removed at the user's request: the scanner never enqueues notifications, the notification workflow has no automatic triggers or delivery steps, and its CLI is a retired no-op. The Monitor panel has no notification queue dependency. Historical outbox tables, migrations and internal regression helpers are retained without deleting stored data; they are not part of the active pipeline. The Domains view remains the authoritative findings list.

### Independent Scheduler Setup

Use the existing Cloudflare account's free Workers plan. The scheduler uses one cron and one SQLite Durable Object for dispatch reservations, cooldowns and deduplicated incidents. Do not change its Worker name, binding or migration tag after activation without migrating state. No paid plan is required for this small dispatcher; usage shares account limits.

Create a fine-grained GitHub token with resource owner `hongyime`, selected repository `sgCertWatch2026`, and Actions read/write. A token targeting your personal account cannot dispatch this organization-owned repository, even when Actions write is enabled. Place setup values in ignored `.env.scheduler`, never tracked files or chat. Install it as Worker `GITHUB_TOKEN`, not the machine's broad GitHub token. Install a random `STATUS_TOKEN` of at least 32 characters. Configure `SUPABASE_URL` and an anon/publishable `SUPABASE_PUBLISHABLE_KEY` for actual pipeline heartbeats; never install a service-role database key in the Worker. Dashboard-only monitoring is the default: incidents and recoveries are recorded without sending messages. An existing private HTTPS `ALERT_WEBHOOK_URL` (optional bearer `ALERT_WEBHOOK_SECRET`) remains opt-in, not a setup requirement. Telegram variables are ignored.

Validate with `wrangler deploy --dry-run --config scheduler/wrangler.jsonc`, then deploy with the same config after tests and workflow rollout. The checked-in config defaults to paused. After the scoped token's Actions write access is verified, explicitly activate with `--var DISPATCH_ENABLED:true`; retain that override on subsequent active deployments. The protected `GET /status` requires `Authorization: Bearer <STATUS_TOKEN>`; public requests cannot dispatch scans. Missing dispatch credentials remain explicit, while dashboard-only mode is valid without a messaging channel. Monitor shows external triggering only after the scanner records an actual Cloudflare-origin dispatch. A full reliability verification requires live recovery checks and a measured 24-hour CT/intel soak, not only unit-test success.

Run `node scripts/verify_soak.mjs` with `SCHEDULER_STATUS_URL`, `SCHEDULER_STATUS_TOKEN`, `SUPABASE_URL` and `SUPABASE_ANON_KEY` in the local environment. It requires 24 observed hours, fresh CT/intel heartbeats, cadence counters, no scheduler gaps and independent committed CT run history. Dashboard mode does not require notification-worker runs or delivery receipts; active incidents still fail verification. Optional webhook mode also checks unresolved delivery failures. An unfinished soak exits nonzero. CI uses disposable PostgreSQL 17 for retained outbox tests and lease fencing; never point the disposable-database tests at production.

### crt.sh Backup

The supported endpoint is `https://crt.sh/?identity=<encoded-token>&output=json&exclude=expired`, not `/api` or a CT log `/ct/v1` path. Identity search uses the provider's text index; it is not complete substring discovery. Expired certificates are excluded upstream, while the 14-day observation filter and newest-15 limit are applied locally. `minNotBefore` is not a date filter for identity queries. See the [operator's implementation](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc).

The [operator's May 2026 notice](https://groups.google.com/g/crtsh/c/PsNhy2WVXhg) documents overloaded replicas, recurring HTTP 50x failures and inefficient result sorting. This optional comparison source cannot be an availability dependency for the monitor.

By default, one rotating token is queried at most hourly. The entire request/body has a 20-second deadline and a 4 MiB response cap. There are no immediate retries: failures pause for 1, 2, 4, 8, 16, then 24 hours; HTTP 429 pauses for at least 24 hours, honoring longer `Retry-After` values. The cursor, last attempt, last success and next poll are persisted in Supabase across Actions runs. A valid JSON `[]` means no results; HTTP 404, HTML errors and malformed JSON never count as successful empty searches. Monitor shows the error and retry time while direct/static CT continue separately.

## Threat Intelligence

Apply `supabase/intel.sql` to an existing database before deploying this feature. New installations also include its definitions in `supabase/schema.sql`.

`.github/workflows/intel.yml` runs hourly at minute 7 and supports manual dispatch from GitHub's Actions tab. Supabase stores the next permitted request time before each provider call, so manual runs and restarts respect the same limits. Add repository secrets `ABUSECH_AUTH_KEY` and `URLSCAN_API_KEY`; these are not Vercel environment variables.

| Source | Requests | Evidence |
| --- | --- | --- |
| [OpenPhish](https://openphish.com/phishing_feeds.html) | One community feed download per 12 hours | Phishing host, feed fingerprint |
| [URLhaus](https://urlhaus-api.abuse.ch/) | One recent-URLs request per 6 hours | Malware report and online/offline state |
| [ThreatFox](https://threatfox.abuse.ch/api/) | One recent-IOCs request per 6 hours | Domain/URL IOC, confidence and malware family |
| [urlscan](https://urlscan.io/docs/api/) | Up to three searches and three result reads per 6 hours | Existing public scan, title, report and screenshot link |

URLhaus and ThreatFox share an account cooldown: HTTP 429 pauses both for at least 72 hours (longer when requested by the provider). Authentication failures pause for 24 hours. urlscan respects quota response headers. No automatic URL submissions, paid tiers, PhishTank, Google Cloud or Vercel scanning are used.

Feed results are matched locally against up to 500 distinct stored, unsuppressed CT candidates scoring at least 60. Selection alternates between scores 60-69 and scores >=70, allowing near-threshold domains to gain evidence alongside existing alerts. Exact certificate hostnames must match; sibling hosts, shared IPs and parent domains do not inherit evidence. OpenPhish's community feed is limited and updates every 12 hours; URLhaus's recent endpoint returns at most 1,000 entries from three days. This enrichment is supplementary and incomplete.

Expiring observations live in `intel_evidence`. The CT score and training corpus remain unchanged. A fresh OpenPhish hit, online URLhaus report, ThreatFox confidence >=75, or explicit urlscan phishing/malware verdict adds at most 10 review-priority points when the CT score is >=60. An ordinary urlscan sighting adds context only. The Domains view uses review priority for Watch now; evidence details link to provider reports. Monitor displays intelligence health separately from CT health.

## Licence

This repository is licensed under Apache-2.0. See `LICENSE` and `NOTICE` for details.

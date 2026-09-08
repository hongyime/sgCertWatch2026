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
- `.github/workflows/ingest.yml` polls CT sources on GitHub Actions every 15 minutes.
## Usage

Validate the seed data and scoring engine:

```bash
npm run validate
npm run test:unit
npm run test:intel
```

## Ingestion

CT polling runs on GitHub Actions (`scripts/run-ingest.mjs`), which executes the multi-source
orchestrator directly against Supabase using repository secrets - no HTTP hop through Vercel.
Cursors stay in Supabase `ingest_state`, so a delayed or skipped run catches up on the next tick.

The schedule targets `:07`, `:22`, `:37`, and `:52` UTC each hour. It is active, but a September 8 audit found scheduled gaps of several hours. Offsetting the cron reduces peak-time contention, not GitHub's underlying delays or dropped triggers. The dashboard marks scans older than an hour overdue. Reliable timing needs an independent scheduler to dispatch this same workflow; any extra trigger must retain the `ct-ingest` GitHub concurrency group, not run a competing scanner. See [GitHub's schedule limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

Required repository secrets: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`. Optional alerting secrets:
`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `DISCORD_WEBHOOK_URL`, `ALERT_WEBHOOK_URL`,
`ALERT_WEBHOOK_SECRET`. The dashboard functions need `SUPABASE_URL` and `SUPABASE_ANON_KEY` only, with the schema in `supabase/schema.sql`.

The poller samples CertStream, tails a rotating set of direct RFC6962 CT logs, reads Let's Encrypt logs through the Static CT API tile reader, and keeps `crt.sh` as a fallback comparison source. Findings and source health are stored in Supabase so the dashboard can show partial coverage instead of treating one source outage as a total outage.

The Actions job polls six direct logs with up to 128 entries each, and permits 30 tiles per static log within a 90-second static-source budget. Static logs rotate across runs so later logs are not starved. Tile framing and bundle counts are validated before cursor advancement; malformed or truncated responses retain the failed tile for retry, while earlier completed tiles are retained. Findings and CT sightings are saved in batches of 200 rows. These are sampling limits, not full CT coverage; GitHub scheduled runs can be delayed.

Primary health comes from direct/static CT, so an idle WebSocket or backup cannot hide a primary outage. Findings and sightings are committed before cursors, with failed-write ranges replayed next run; completed cursors and scan status are committed before optional notifications. Failed stages are recorded when the database is reachable. Telegram delivery is best-effort, capped at 20 sends/30 seconds per scan, with only delivered domains added to alert deduplication history.

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

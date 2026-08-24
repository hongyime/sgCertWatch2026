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
npm test
```

## Ingestion

CT polling runs on GitHub Actions (`scripts/run-ingest.mjs`), which executes the multi-source
orchestrator directly against Supabase using repository secrets - no HTTP hop through Vercel.
Cursors stay in Supabase `ingest_state`, so a delayed or skipped run catches up on the next tick.

Required repository secrets: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`. Optional alerting secrets:
`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `DISCORD_WEBHOOK_URL`, `ALERT_WEBHOOK_URL`,
`ALERT_WEBHOOK_SECRET`. The dashboard functions need `SUPABASE_URL` and `SUPABASE_ANON_KEY` only, with the schema in `supabase/schema.sql`.

The poller samples CertStream, tails a rotating set of direct RFC6962 CT logs, reads Let's Encrypt logs through the Static CT API tile reader, and keeps `crt.sh` as a fallback comparison source. Findings and source health are stored in Supabase so the dashboard can show partial coverage instead of treating one source outage as a total outage.

## Licence

This repository is licensed under Apache-2.0. See `LICENSE` and `NOTICE` for details.

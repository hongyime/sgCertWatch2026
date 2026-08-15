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
- `api/cron/ct-poll.js` is the protected Vercel function used for periodic multi-source CT polling.

## Usage

Validate the seed data and scoring engine:

```bash
npm run validate
npm test
```

Persistence requires `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, with the schema in `supabase/schema.sql`. The scheduler also requires `CRON_SECRET`.

Production CT polling is scheduled by Supabase `pg_cron` every 5 minutes and calls the protected Vercel function at `/api/cron/ct-poll`. It samples CertStream, tails a rotating set of direct RFC6962 CT logs, and keeps `crt.sh` as a fallback comparison source. Findings and source health are stored in Supabase so the dashboard can show partial coverage instead of treating one source outage as a total outage.

## Licence

This repository is licensed under Apache-2.0. See `LICENSE` and `NOTICE` for details.

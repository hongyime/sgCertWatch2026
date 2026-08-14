# sgCertWatch2026

sgCertWatch2026 is a Singapore-focused Certificate Transparency monitoring dashboard. It collects the static watch lists, keyword lists, allow lists, and scheme metadata that define what the monitor should look for, and includes the first deployable scoring and ingest surface.

## What It Contains

- `watchlist.json` stores the domains and organisations to monitor.
- `keywords.json` stores matching terms used to classify certificate activity.
- `allowlist.json` stores expected or intentionally ignored certificate patterns.
- `schemes.json` stores structured scheme metadata for downstream dashboard work.
- `lib/scoring.js` scores CT certificate entries against the seed data.
- `api/findings.js` exposes recent stored findings for the dashboard.
- `api/cron/ct-poll.js` is the Vercel Cron job for periodic CT polling.

## Usage

Validate the seed data and scoring engine:

```bash
npm run validate
npm test
```

Persistence requires `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, with the schema in `supabase/schema.sql`.

Production CT polling runs through Vercel Cron every 5 minutes. It uses small rotating `crt.sh` public JSON searches, scores the returned certificates, and stores findings in Supabase. This is not full CT firehose coverage, but it keeps the project on Vercel and Supabase only.

## Licence

This repository is licensed under Apache-2.0. See `LICENSE` and `NOTICE` for details.

# sgCertWatch2026

sgCertWatch2026 is a Singapore-focused Certificate Transparency monitoring dashboard. It collects the static watch lists, keyword lists, allow lists, and scheme metadata that define what the monitor should look for, and includes the first deployable scoring and ingest surface.

## What It Contains

- `watchlist.json` stores the domains and organisations to monitor.
- `keywords.json` stores matching terms used to classify certificate activity.
- `allowlist.json` stores expected or intentionally ignored certificate patterns.
- `schemes.json` stores structured scheme metadata for downstream dashboard work.
- `lib/scoring.js` scores CT certificate entries against the seed data.
- `api/ingest.js` accepts CT certificate events and stores matched findings when Supabase is configured.
- `api/findings.js` exposes recent stored findings for the dashboard.
- `scripts/poll_certstream.js` bridges the public CertStream feed into the ingest API.

## Usage

Validate the seed data and scoring engine:

```bash
npm run validate
npm test
```

Run the CertStream bridge after setting `INGEST_URL` and `INGEST_TOKEN`:

```bash
npm run poll:certstream
```

Production ingest requires `INGEST_TOKEN`. Persistence requires `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, with the schema in `supabase/schema.sql`.

## Licence

This repository is licensed under Apache-2.0. See `LICENSE` and `NOTICE` for details.

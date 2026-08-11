# sgCertWatch2026

sgCertWatch2026 is a design and data repository for a Singapore-focused Certificate Transparency monitoring dashboard. It collects the static watch lists, keyword lists, allow lists, and scheme metadata that define what the monitor should look for.

## What It Contains

- `watchlist.json` stores the domains and organisations to monitor.
- `keywords.json` stores matching terms used to classify certificate activity.
- `allowlist.json` stores expected or intentionally ignored certificate patterns.
- `schemes.json` stores structured scheme metadata for downstream dashboard work.
- `docs/` contains planning and implementation notes for the monitoring dashboard.

## Usage

Install or run steps are intentionally light because this repository currently stores data and design assets rather than an application runtime. Consumers can read the JSON files directly from the repository and validate them with any JSON parser before wiring them into a monitoring job or dashboard.

## Licence

This repository is licensed under Apache-2.0. See `LICENSE` and `NOTICE` for details.
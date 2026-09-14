# Current state — 14 September 2026

SGCertWatch collection is paused by the owner's choice: ingest/intel/capture
workflows disabled and the external scheduler has no cron triggers. Preserve all
records; no project pause, paid upgrade or collection restart is authorized.

The Supabase database has zero filesystem space available and its db/rest health
is UNHEALTHY with PostgreSQL in recovery mode (02:05 UTC). SQL cannot connect.
Provider recovery is needed before retained-data and capacity validation can
continue. The Last 30 Days Vercel dashboard attributes 3h10m / 78.3% to this app;
it includes deployments before ingestion left Vercel on 24 August.

This change adds an opt-in production SGCERTWATCH_STORAGE_RECOVERY guard. It
returns no-store 503s without database calls; triage authentication stays first.
The UI explains the outage and pauses automatic/visibility refreshes. Manual
refresh or reload remains possible. It does not recover disk or CPU allowance.
The full unit pipeline and desktop/mobile browser flows pass locally, including
13 polling/recovery tests. Hosted checks and production activation are next.

Keep the separate lossless-storage PR #14 draft pending. Do not apply migrations
against the recovering database. After provider recovery, validate retained data,
bounded reads/writes, migration space, rollback and measured capacity before
clearing this guard or considering a collection restart. Earlier implementation
history remains in JOURNAL.md and git history.

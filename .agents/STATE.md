# Current state — 16 September 2026

Collection is paused (owner directive, 2026-09-14). All records retained.
No collection restart, paid upgrade or record deletion authorised.

## Merged today (2026-09-16)

- **PR #17** `feat/lossless-evidence-storage` — lossless evidence storage +
  atomic writes. Merged to main.
- **PR #18** `maintenance/db-space-recovery-20260916` — drops two write-only
  indexes on `finding_sources` + VACUUM FULL + REINDEX. Merged to main.
  Migration file: `supabase/space-recovery.sql` (ready to apply).

## Blocked: DB in PostgreSQL recovery mode

The database reports `FATAL: 57P03` (PostgreSQL WAL replay in progress).
Project API shows ACTIVE_HEALTHY — the issue is at the PostgreSQL layer, not
the API layer. This is automatic; no action required beyond waiting.
This is NOT a monthly-quota reset. Storage (500 MB free-tier limit) is a
permanent cap, not monthly. DB grew to ~777 MB before the cap was hit.

**When DB exits recovery mode, run immediately:**
```
supabase db query --linked -f supabase/space-recovery.sql
```
Then measure: `SELECT pg_size_pretty(pg_database_size(current_database()));`

## Next steps

1. Wait for PostgreSQL to exit recovery (automatic, minutes–hours).
2. Apply space-recovery.sql — should bring DB from ~777 MB to ~400–450 MB.
3. If DB remains under 500 MB: re-evaluate collection restart with owner.
4. Earlier implementation history and open decisions in JOURNAL.md.

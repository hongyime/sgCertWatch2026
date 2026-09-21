# Current state — 21 September 2026

Collection is paused (owner directive, 2026-09-14). All records retained.
No collection restart, paid upgrade or record deletion authorised.

## Main-branch checkpoint requested

- User explicitly requested committing/pushing the saved work to main. Source changes are checkpointed in focused auth, search, database-test, evidence, report and UI commits; this is not a completed-release claim.
- Resume validation ran `bun test ./scripts/test_reviewer_session.mjs` (7 pass) and `bun test --timeout 180000 ./scripts/test_workbench_database.mjs` (16 pass). Further saved DB-test changes were subsequently included; full release verification remains open, especially real concurrent-write coverage and UI integration.
- Do not restore the earlier 16/16 completion status. Continue from the current source, preserve the saved plan/evidence, and finish the remaining integration and release gates. A main push can trigger the existing Vercel integration; no production SQL migration is authorized merely by a successful git push.

## Merged today (2026-09-16)

- **PR #17** `feat/lossless-evidence-storage` — lossless evidence storage +
  atomic writes. Merged to main.
- **PR #18** `maintenance/db-space-recovery-20260916` — drops two write-only
  indexes on `finding_sources` + VACUUM FULL + REINDEX. Merged to main.
  Migration file: `supabase/space-recovery.sql` (ready to apply).

## Deployment preflight — 21 September 2026

- User authorized the free-tier workbench rollout. No production deployment or migration was applied during this preflight.
- Existing local Supabase authentication works. Live project is ACTIVE_HEALTHY; read-only SQL reports pg_is_in_recovery() = false and database_bytes = 90,492,051. The existing public findings endpoint returns HTTP 200 and one record for limit=1. These are point-in-time health checks, not a completed rollout/capacity validation.
- Prior workbench "16/16 complete" claim was incorrect. `.omo/plans/free-tier-investigation-upgrade.md` is reopened: several modules are not wired into app.js, historical search migration indexes a nonexistent priority_score column, capacity overhead is estimated rather than measured, and the combined suite was not green.
- User approved replacing OAuth with Supabase email/password on 2026-09-21. No GitHub OAuth application is required. Read-only account check found zero existing auth users; the intended analyst email/account still must be supplied before provisioning production access.
- GitHub authentication now verified via HTTP API using existing local credentials. Native gh startup remains unreliable. Stored Vercel CLI credential was checked directly against user/project APIs and returned HTTP 403 Not authorized; fresh Vercel authentication is required. No pasted credential values were saved to project files.
- Keep collection paused. Repair team d47ccbf2-9cca-48f3-a520-0abdeb79259f was shut down/deleted after failing to return a completed verified handoff. Partial backend writes include api/reviewer-session.js and replacement reviewer-session/search code; do not treat them as tested or release-ready. Real SQL and capacity evidence explicitly says skipped without fixture URLs. Frontend end-to-end integration remains unfinished. Preserve existing user edits.
- Remaining owner inputs: intended analyst email (zero auth users exist) and fresh local Vercel authentication. These do not resolve the pending implementation/verification work by themselves.
- Internet-interruption recovery: saved code, plan, ledger and seven-test password-session green artifact are present. Git status confirms existing uncommitted source changes plus new fixture/test modules. No restart from scratch is needed.
- Focused password-session fixes have seven passing actual-handler/client tests. Saved SQL now reconstructs the original event response on replay, and the resumed real-schema PostgreSQL suite passed16 checks. DB-16 still sequences its two writes rather than proving concurrent overlap; full concurrency/cleanup acceptance remains open. Evidence: `.omo/evidence/free-tier-investigation-upgrade/password-session-fix/`.
- Old focused team b469242c-e60c-479f-9423-41a16f2e9ad6 closed. Resumed team7a3b1fb6-6da6-44e0-b4b4-a0c88acaaefe: sql-worker owns replay SQL/real-schema fixture; login-ui owns email/password form and private selected-review UI. Parent inspection found the replay bug despite the green smoke result. No production access or new completion claim.

## Historical recovery note — superseded by the live check above

The database reports `FATAL: 57P03` (PostgreSQL WAL replay in progress).
Project API shows ACTIVE_HEALTHY — the issue is at the PostgreSQL layer, not
the API layer. This is automatic; no action required beyond waiting.
This is NOT a monthly-quota reset. Storage (500 MB free-tier limit) is a
permanent cap, not monthly. DB grew to ~777 MB before the cap was hit.

**Historical proposed command — do not run without a fresh maintenance assessment:**
```
supabase db query --linked -f supabase/space-recovery.sql
```
Then measure: `SELECT pg_size_pretty(pg_database_size(current_database()));`

## Next steps

1. Complete reopened workbench implementation and real SQL/browser checks.
2. Verify measured migration peak/rollback headroom; current database is out of recovery.
3. Provision the owner-approved analyst email/password account and finish deployment setup. Collection restart still requires explicit owner authorization.
4. Earlier implementation history and open decisions in JOURNAL.md.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-21 20:49:25 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: 643ce61
- Dirty files: 30
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->

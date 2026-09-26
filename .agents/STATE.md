# Current state — 26 September 2026

## Reviewer setup completed

- `git pull --ff-only origin main` found the checkout current at `b52c4e5`.
  The reviewer backend/UI and prior workbench fixes are already committed.
- Fresh owner-supplied Vercel access succeeded. Added the existing analyst
  account to the production `REVIEWER_USER_IDS` allowlist and read it back.
  No account was recreated; no credentials were written to files or logs.
- Deployment `dpl_H2WWNFkL7D1Tm2Ds9PVBJXfXDWhr` is READY/PROMOTED from
  `b52c4e5`, serving `sgcertwatch.hong-yi.me` and `sgcertwatch.vercel.app`.
- Live checks: homepage 200 with reviewer UI; findings API 200; reviews
  without a token -> 401 `missing_token`; invalid token -> 401 `token_invalid`;
  empty login body -> 400 `invalid_body`. Auth responses are `no-store`.
- Earlier pre-existing handoff edits recorded a real-credential login returning
  503 `reviewer_not_configured` on September 26 before this setup. The missing
  allowlist is now fixed, but a production password login/save is NOT verified
  in this continuation because the owner password is unavailable here.
- Focused tests: `node --test scripts/test_reviewer_session.mjs
  scripts/test_workbench_review.mjs` -> 22 passed, 0 failed, 1 skipped.
  The skipped test requires `WORKBENCH_REVIEW_DATABASE_URL`; the real SQL was
  verified previously, not rerun in this session. Browser fixture sign-in,
  review save and sign-out passed.
- README and `.env.example` now document reviewer setup. Reviewer UUIDs and
  credentials belong in server configuration, outside committed examples.

## Collection status differs from the previous handoff

- September 14's recorded directive was to pause collection. Live GitHub state
  on September 26 instead shows CT Ingest enabled with successful scheduled
  runs (checked run `36209950564`). Intel and capture remain disabled.
- Checked-in Cloudflare config also enables dispatch and a five-minute cron;
  live Cloudflare configuration was not inspected in this continuation.
- Asked the owner whether to leave CT running or pause it. No collection,
  scheduler, paid-plan, database migration or retained-record changes made.
  Do not report collection as paused based on the old handoff.

## Next steps and evidence limits

1. Owner can sign in on the live dashboard using the existing analyst account.
   Confirm a real review only when the owner has an intended finding/review;
   do not pollute production with a synthetic review for testing.
2. If the owner no longer has the password, assist account recovery without
   storing or requesting passwords in shared project files.
3. Resolve the collection-status question with the owner before changing it.
4. The broader workbench plan still has reopened gates in
   `.omo/plans/free-tier-investigation-upgrade.md`; do not claim completion
   of every historical task based on this configuration fix.

Detailed September 23 implementation, SQL verification and rollout history is
preserved in Git (`b52c4e5:.agents/STATE.md`) and `.agents/JOURNAL.md`.
The pre-existing automated state block below is preserved, not current evidence.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-26 11:08:23 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: b52c4e5
- Dirty files: 0
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->

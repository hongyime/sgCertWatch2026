# Current state — 26 September 2026

## Branch consolidation — 2026-09-26

- All eight original local work branches and the remaining remote storage branch
  are included in the consolidated history. GitHub had no open PRs at audit time.
  No branch, stash, retained record or user file was deleted.
- Storage implementation was already identical to main. Joined its histories
  and the patch-equivalent maintenance docs while retaining pinned CI actions.
  Recovered evaluator progress from the old performance snapshot; kept current
  scoring precision, memoization and Public Suffix List parsing corrections.
- Reviewed all six stashes. Recovered reviewer UI tests, real database replay/
  concurrency assertions, reliable fixture cleanup, synthetic UI auth and the
  `.postplan/` deployment exclusion. Obsolete modal UI was adapted to the current
  inline form; superseded code was not restored over newer implementations.
- Recovered browser coverage exposed a stray CSS brace and hidden reviewer
  controls remaining visible. Fixed those, restored failed-login password
  clearing and submit disabling, and wired recovered tests into CI.
- Verification: 42 browser/backend checks passed (2 optional SQL checks skipped);
  separate disposable PostgreSQL suite 18/18, with both containers verified gone;
  full core unit suite and release-data validation passed. Workflow YAML and
  evaluator syntax passed. Full corpus evaluation was not rerun for log changes.
- Audit and per-branch/stash dispositions:
  `.agents/handoffs/2026-09-26-main-integration.json`.
- Credentials, dependency/build caches, generated evidence and local tool/session
  files remain excluded. Production data and collector scheduling are unchanged.

## Reviewer configuration verified before consolidation

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

## Collection should remain running

- September 14's recorded directive was to pause collection. Live GitHub state
  on September 26 instead shows CT Ingest enabled with successful scheduled
  runs (checked run `36209950564`). Intel and capture remain disabled.
- Checked-in Cloudflare config also enables dispatch and a five-minute cron;
  live Cloudflare configuration was not inspected in this continuation.
- Owner confirmed on September 26 that CT collection must remain running;
  this supersedes the historical CT pause. Intel/capture activation is separate.
- Latest three checked CT runs were successful GitHub schedule events at
  September 25 20:33/23:29 and September 26 01:54 UTC, roughly 2-3 hours
  apart despite the configured 15-minute schedule. Live Cloudflare dispatch
  health remains unverified. No scheduler changes made.

## Next steps and evidence limits

1. Owner can sign in on the live dashboard using the existing analyst account.
   Confirm a real review only when the owner has an intended finding/review;
   do not pollute production with a synthetic review for testing.
2. If the owner no longer has the password, assist account recovery without
   storing or requesting passwords in shared project files.
3. Keep CT running; investigate schedule gaps and live Cloudflare dispatch
   before claiming reliable 15-minute collection.
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

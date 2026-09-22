# Current state — 22 September 2026

Collection is paused (owner directive, 2026-09-14). All records retained.
No collection restart, paid upgrade or record deletion authorised.

## Last change — 2026-09-22

Five layered CI regressions introduced by the "investigation workbench" UI
checkpoint (commit 4f31167, 2026-09-21) were root-caused and fixed in commit
5dbf7483:

1. **Test asset whitelist** — new `lib/ui/*.js` modules were not whitelisted in
   the test runner's asset allowlist, causing import failures.
2. **Missing `await`** — `renderFindingList()` was called without `await`,
   creating a race condition that caused intermittent test failures.
3. **Desktop-only table view** — the card list required by tests was hidden
   behind a desktop-only table view toggle.
4. **Empty-state copy regression** — the empty-state message text was changed,
   breaking the test's string assertion.
5. **SECURITY regression** — `lib/ui/evidence-timeline.js` rendered evidence
   links without URL sanitization, leaving the app vulnerable to
   `javascript:`/`data:` URI injection, spoofed hosts, and `onerror` injection.
   Fixed by porting the exact sanitization allowlist from pre-regression commit
   643ce619 into `evidence-timeline.js`. Verified against the test's full
   malicious-URL rejection list.

Commit 5dbf7483 pushed to main. Main CI is now green.
PR #19 (actions/setup-node v4→v7), which was blocked by the broken CI, was
subsequently merged.

## Status

DONE — all five regressions fixed and verified. Main CI green. PR #19 merged.
Ended because: task complete.

## Next steps

1. Complete reopened workbench implementation and real SQL/browser checks.
2. Verify measured migration peak/rollback headroom.
3. Provision the owner-approved analyst email/password account and finish
   deployment setup. Collection restart still requires explicit owner
   authorization.
4. Earlier implementation history and open decisions in JOURNAL.md.

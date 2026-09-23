# Current state — 23 September 2026

Collection is paused (owner directive, 2026-09-14). All records retained.
No collection restart, paid upgrade or record deletion authorised.

## Last change — 2026-09-23

Re-verified the reopened "free-tier investigation workbench" plan against the
ACTUAL committed code on main (post CI-fix commit 5dbf7483, HEAD 25cfd5d) using
real test runs, not code-reading alone. Found and fixed 6 confirmed bugs with
new regression tests added (all passing; full `npm run test:unit` still green,
34 tests, 0 failures, 0 regressions):

1. **Task 1 (scope honesty)**: `renderFindingList()` said "~50" regardless of
   actual response size and said "No matching stored findings" (implying
   global absence) for a loaded-scope miss. Fixed to show the real loaded
   count and "No matches in loaded findings". `test_workbench_scope.mjs`'s
   `loaded-scope` test: FAIL -> PASS. `recovery-is-not-zero` still passes.
   ("Recent findings (50 loaded)" dropdown option was already correctly
   renamed from "All stored findings" in an earlier pass — that describes the
   fixed query limit, not a claimed result count, so left as-is.)
2. **Saved-view URL round-trip bug**: `encodeFilter()` in
   `lib/ui/saved-views.js` only wrote the `s=` URL param when severity was
   both non-empty AND not "watch" — an explicit "show all severities" (`""`)
   is falsy in JS, so it was silently dropped and reload/share-link always
   reverted to "watch". Fixed (`if (filter.severity !== "watch")`). New pure
   test `all-severities-url-round-trips` passes.
3. **Cursor expiry NaN bypass**: `decodeCursor()` in `lib/findings-query.js`
   checked `Date.parse(expires_at) <= Date.now()`; `Date.parse("not-a-date")`
   is `NaN`, and `NaN <= x` is always `false`, so a garbled `expires_at` was
   treated as "not yet expired" instead of rejected. Fixed to check
   `Number.isFinite(...)` first and return `cursor_malformed`. New test
   `invalid-cursor-expiry-is-rejected` passes.
4. **Export data loss**: `lib/ui/report.js`'s `exportedFinding()` did
   `domains.slice(0, 3).join("; ")` for BOTH CSV and JSON export — silently
   dropped any 4th+ domain and flattened the JSON array into a string.
   Restructured: `exportedFinding()` now keeps domains/sources/matched_brands
   as real arrays (fixes JSON export), and `toCsvRow()` flattens arrays to
   strings only for the CSV path, joining the FULL array (no truncation).
   New test `domains-preserved-in-full` passes; existing `csv-roundtrip` and
   `export-scope-matches-selection` still pass unchanged.
5. **Broken category presets**: `PRESET_VIEWS`' "Government"/"Banks" entries
   searched the literal English words "government"/"bank" as free text —
   these never appear in any finding's registrable/domains/matched_brands
   field, so the presets almost certainly matched nothing real, despite a
   comment claiming they used "actual brand IDs/categories from
   watchlist.json". Implemented a `category:<id>`/`verdict:<id>` sentinel
   query convention: presets now encode `category:government` /
   `category:bank` / `verdict:phishing`, and a new `matchesFindingQuery()`
   (extracted from `filteredFindings()` in app.js) resolves `category:`
   against real `watchlist.json` brand IDs by category and `verdict:` against
   real intel-evidence verdicts, falling back to the original substring
   search for any other query. Filter storage SHAPE is unchanged (`{query,
   severity}`), so `private-data-never-saved`'s schema assertion still
   passes. CAVEAT (now closed, see item 10 below): at the time this fix
   landed, only hand-traced verification existed — no end-to-end Playwright
   test yet clicked the actual preset button and asserted brand-category-
   correct results.
6. **Print report leaks background list**: `styles.css`'s `@media print`
   block hid nav/toolbar/coverage-strip/footer/export-buttons but never hid
   `#finding-list-container`, so printing a single finding's report also
   printed the entire background findings list. Added it to the hidden
   selector list. Not independently test-verified (no visual-print test
   exists yet); low risk, single CSS rule.
7. **Desktop findings table deleted by the prior CI-fix**: commit `5dbf7483`
   fixed "desktop-only table view hiding the card list needed by tests" by
   deleting the ENTIRE `isDesktop` table-rendering branch in
   `renderFindingList()`, leaving only card rendering at every viewport —
   silently breaking Task 5's contract (no `.finding-list-table`, no
   `data-finding-id`/`aria-selected` rows, no `[data-open-detail]` buttons at
   >=1024px). This IS what made `selection-survives-refresh` fail. Confirmed
   via `git show 4f31167:app.js` (the original table markup) and
   `test_workbench_primitives.mjs`'s own comments ("Uses mobile viewport so
   the app renders cards, not the desktop table") which show the suite always
   expected both modes to coexist — the CI-fix's real regression was
   elsewhere (most likely the missing-`await` race it fixed separately), not
   the `isDesktop` branch itself. Restored the table, extracted as
   `renderFindingRow`/`renderFindingTableBody` in `lib/ui/findings-list.js`
   (matching the existing `renderFindingCard` pattern) rather than re-inlining
   into app.js. `test_workbench_layout.mjs`: 1 FAIL -> 3/3 PASS. Re-verified
   `test_workbench_primitives.mjs` (3/3 named tests still pass, same pre-
   existing file-level-exit pattern as before, not a new regression) and
   `test_workbench_scope.mjs` (2/2 pass). `npm run test:unit` still green.

`lib/ui/finding-details.js` exists and is fully correct/tested standalone,
but `app.js`'s `buildDialogBodyHtml()` still has its own 50-line duplicate
instead of importing it — real dedup work, deferred (moderate risk: would
need converting `buildDialogBodyHtml`/`openDetailPanel`/`openFindingDetails`
to async via a dynamic `import()`, matching the lazy-load pattern already
used for evidence-timeline/related-findings/impersonation; NOT done yet).

`enhanceDetailPanel()` in app.js DOES already genuinely wire
evidence-timeline.js / related-findings.js / impersonation.js into both the
desktop detail-panel and mobile dialog (real HTML sections appended, not just
imports) — this appears to have landed as part of the 2026-09-22 CI-fix
commit 5dbf7483. Confirmed by reading the code; NOT yet re-confirmed by a
fresh browser test on current HEAD (the browser-based verify-user-flows.mjs
check that originally found these "unwired" was run against the STALE commit
62b36e3, eight commits behind current HEAD).

8. **Task 9 (analyst sign-in + review UI, previously entirely missing)**: Built the
   frontend for the already-tested backend (`api/reviewer-session.js`,
   `api/reviews.js`, `lib/ui/reviewer-session.js`, `lib/reviewer-auth.js`).
   Added `#reviewer-auth` sign-in/sign-out block to `index.html`; added
   `reviewerSession` singleton, `updateReviewerAuthUI()`, and an "Analyst
   Review" panel (desktop + mobile) with `loadReviewPanel()`/
   `renderReviewForm()`/`submitReview()` (idempotent `request_uuid`, 409-
   conflict reload) to `app.js`. `renderFindingRow`/`renderFindingTableBody`
   in `lib/ui/findings-list.js` now take `isSignedIn` to show "Open to
   review" vs "Sign in to review". New end-to-end test
   `analyst-sign-in-and-review` in `test_workbench_review.mjs` passes
   (intercepts `/api/reviewer-session` + `/api/reviews` at page level since
   Supabase Auth itself is unreachable from the loopback fixture).
9. **Task 8 (historical search UI, previously entirely missing)**: Wired the
   already-tested `search=1` backend to a new search bar in `index.html`
   (`#historical-search-btn`/`#historical-search-bar`) and `app.js`
   (`runHistoricalSearch`, `exitHistoricalSearch`, `updateHistoricalSearchBar`,
   debounced re-search on query/severity change). New end-to-end test
   `historical-search-has-user-control` in `test_workbench_search.mjs`
   proves it finds a record outside the normal 50-row batch. **Caught a real
   race while building this, not by inspection**: the 300ms debounce timer
   scheduled by typing a short (<3 char) query was not cancelled on exit or
   on an explicit search click, so it could fire AFTER the user exited
   historical mode and call `showHistoricalSearchError()`, which
   unconditionally sets `bar.hidden = false` — forcibly re-showing the exited
   search bar. Confirmed via a MutationObserver diagnostic on `bar.hidden`
   (logged `true` then `false` 7ms later) before fixing by clearing the
   timer in both `exitHistoricalSearch()` and the search-button handler.
   5/5 clean reruns after the fix, 0/5 before it.

10. **Bug 5's caveat closed, and 2 more real bugs found while closing it**:
    added `preset-views-match-real-brand-categories` to
    `test_workbench_views.mjs` — an end-to-end test that clicks Government/
    Banks/phishing and asserts against real `watchlist.json` brand IDs (dbs=
    bank, singpass=government, shopee=commerce; findings scored BELOW 70 to
    also prove severity isn't silently narrowed). Writing it surfaced:
    (a) `applyFilter()` did `filter.severity || "watch"`, coercing an
    explicit empty-string severity ("all severities", used by every preset)
    back to "watch" — the SAME class of bug as the earlier `encodeFilter()`
    fix, just in the click-to-apply path instead of the URL path. Fixed to
    `??`. (b) `renderFindingList()`'s desktop-table swap did
    `querySelector`+`remove()` BEFORE an `await import(...)`, then
    `appendChild` AFTER — an older, already-superseded render and a newer
    one could interleave across that gap and leave two tables (or a leaked
    stale one) in the DOM. Reproduced 3/3 times via a MutationObserver
    diagnostic on the container's childList; fixed by moving the removal
    (now `removeAll`, not just the first match) to happen atomically with
    failure 3/3 times before them.

11. **Task 7/8 real-SQL verification — partial, then blocked by environment**:
    stood up a disposable `postgres:16-alpine` container (Docker, port 5544)
    to finally exercise the `WORKBENCH_*_DATABASE_URL` suites that had been
    skipped all session. `test_workbench_capacity.mjs`'s
    `real-disposable-postgres` test (Task 7's checker, incl. the previously-
    suspected `SET statement_timeout=$1` bind-placeholder bug) now runs and
    **PASSES cleanly** — both the generous-limit PASS case and the tight-
    limit FAIL case work correctly against a real Postgres. The suspected
    bind bug did NOT materialize; the checker is sound. (Needed
    `?sslmode=disable` on the URL — the checker explicitly honours that,
    intentionally distinct from `--insecure-tls`.) `test_workbench_search.mjs`
    (`workbench-search.sql`) and `test_workbench_review.mjs`
    (`workbench-review.sql`) both then failed with `role "anon" does not
    exist` — both migrations `grant`/`revoke` against Supabase's built-in
    `anon`/`authenticated`/`service_role` roles, which a vanilla Postgres
    image doesn't have; these 3 roles need to be created before applying
    either migration. Before that could be done, **Docker Desktop's backend
    wedged** (`docker ps`/`docker version`/`wsl --shutdown` all unresponsive
    90s+, after Windows-side processes still reported "Responding: True") —
    stopped retrying per the no-shotgun-debugging rule rather than keep
    burning time on an environment failure outside this session's control.
    Container `sgcw-disposable-pg` on port 5544 may still exist; state
    unknown until Docker recovers — **tear it down before reusing the name/
    port**. Search/review SQL migrations remain genuinely unverified against
    a real schema.

**Confirmed still broken / not yet attempted this pass:**
- **ROOT-CAUSED (closing a multi-session-old "not root-caused" item)**:
  `test_workbench_primitives.mjs`/`status.mjs`/`views.mjs`/`layout.mjs`
  showing every individual assertion passing (✔) but the FILE reporting a
  generic file-level `'test failed'` (no specific test named) is **not** a
  Playwright/node:test/Windows bug at all. These multi-test files have a
  cumulative runtime of 100–130+ seconds; whenever the external shell-tool
  timeout used to invoke `node --test` (60s/90s/100s/120s, whichever was
  picked that call) is shorter than the actual cumulative runtime, the tool
  harness SIGKILLs the node process mid-test, and node:test reports the
  incomplete run as a file-level failure with no named test — while tests
  that finished before the kill still show their correct checkmarks.
  Reproduced directly on `test_workbench_status.mjs`: with a 120000ms
  timeout it died at 105s mid-3rd-test (`'test failed'`, no test named,
  only 2/3 checkmarks shown); with a 300000ms timeout the SAME file ran to
  completion in 129296ms, 3/3 pass, exit code 0. No code fix needed — always
  give these files a timeout comfortably above ~150s (or use
  `--test-name-pattern` isolation) when running the full file in one call.
- `scripts/check_workbench_capacity.mjs`'s reported `SET statement_timeout =
  $1` SQL bind-placeholder bug (Task 7) is now VERIFIED SOUND — see item 11
  above: `real-disposable-postgres` ran against a real Postgres and PASSED
  cleanly (both the PASS and FAIL cases). `test_workbench_search.mjs`'s
  `real-sql-rpc` and `test_workbench_review.mjs`'s equivalent are still
  UNVERIFIED — both failed on missing Supabase roles (`anon`/
  `authenticated`/`service_role`) before Docker wedged; see item 11.
- Production SQL migrations (`supabase/workbench-search.sql`,
  `supabase/workbench-review.sql`) have never been applied to production
  Supabase. 0 auth users still exist; owner has not yet supplied an analyst
  email. Vercel CLI auth is still a stored-403; needs a fresh `vercel login`.

Git: local `main` and `origin/main` were already in sync at `25cfd5d` before
this pass (nothing to pull/push) — a prior session (commit 5dbf7483) already
fixed 5 CI regressions incl. an evidence-timeline.js XSS/URL-sanitization
issue and got PR #19 merged. No teams from the earlier repair attempts
(`b469242c`, `7a3b1fb6`) are still active; `team_list` now returns empty.

## Status

IN PROGRESS — 10 confirmed bugs/gaps fixed with new passing regression tests;
`npm run test:unit` still fully green (34 tests, 0 failures). The desktop
findings table (Task 5), analyst sign-in + review UI (Task 9), historical-
search UI (Task 8), and Bug 5's category/verdict preset e2e test were all
missing or broken and are now built/restored/added and passing, including
a real debounce-timer race (Task 8) and two more real races/bugs (severity
coercion + duplicate-table DOM race) caught while building the preset test.
The primitives/status/views file-level flakiness (confirmed pre-existing, not
caused by this pass) and search/review real-Postgres SQL verification remain
open (Task 7's capacity checker IS now verified sound). Do NOT treat this as
task-level plan completion — see reopened checkboxes in
`.omo/plans/free-tier-investigation-upgrade.md`.

## Next steps

1. Once Docker recovers: tear down `sgcw-disposable-pg` (port 5544) if it
   still exists, recreate it, add `anon`/`authenticated`/`service_role`
   roles, then run `test_workbench_search.mjs` and `test_workbench_review.mjs`
   against real Postgres (Task 7's capacity checker is already verified).
2. Dedup `app.js`'s `buildDialogBodyHtml()` against `lib/ui/finding-details.js`'s
   `renderDialogBody()` (moderate risk, deferred).
3. Provision the owner-approved analyst email/password account and finish
   Vercel re-auth before any production rollout. Collection restart still
   requires explicit owner authorization.

## History

- 2026-09-22: Five layered CI regressions from the investigation-workbench UI
  checkpoint (commit 4f31167) fixed in commit 5dbf7483 — test-asset
  whitelist, missing `await`, desktop-only table view, empty-state copy, and
  an evidence-timeline.js URL-sanitization XSS regression. Main CI green;
  PR #19 merged.
- Earlier implementation history and open decisions in JOURNAL.md.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-23 21:45:21 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: 20735ed
- Dirty files: 0
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->

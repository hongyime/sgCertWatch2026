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
   passes. CAVEAT: verified the string round-trips and the matching logic was
   traced by hand against confirmed real data shapes (brand.id="singpass"
   etc. from watchlist.json, matched_brands:["singpass"] from
   lib/scoring.js:964, verdict enum from app.js's intelVerdict()) — there is
   NOT yet an end-to-end Playwright test that clicks the actual preset button
   and asserts the rendered results are brand-category-correct. Do not treat
   this as fully verified until that test exists.
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

**Confirmed still broken / not yet attempted this pass:**
- No analyst sign-in UI anywhere in `index.html`/`app.js`. Backend
  (`api/reviewer-session.js`, `lib/ui/reviewer-session.js`,
  `lib/reviewer-auth.js`) is solid and already has 7 passing focused tests
  plus real-Postgres review-table tests, but there is zero UI entry point —
  Task 9's frontend integration has not been started.
- No historical-search UI control; `search=1` backend (Task 8) is fully
  built and its 9 non-real-DB tests all pass, but nothing in app.js ever
  requests it.
- `test_workbench_primitives.mjs` and `test_workbench_status.mjs` both show
  every individual assertion passing (✔) but the FILE exits failed — same
  pattern also seen transiently on `test_workbench_views.mjs` and confirmed
  again on `test_workbench_layout.mjs`'s own run this pass. Each passes
  cleanly when isolated with `--test-name-pattern`, and re-running
  `test_workbench_primitives.mjs` after the desktop-table fix below showed
  the identical pattern with zero new failures — so this is very likely a
  Playwright/node:test/Windows environment teardown-timing issue common to
  every multi-test Playwright file in this suite, not a functional bug and
  not caused by any fix in this pass. Still not root-caused; do not keep
  papering over it with isolation flags forever.
- `scripts/check_workbench_capacity.mjs`'s reported `SET statement_timeout =
  $1` SQL bind-placeholder bug (Task 7) is UNVERIFIED either way: its
  `real-disposable-postgres` test is skipped (no
  `WORKBENCH_CAPACITY_DATABASE_URL` set) in every run so far this session.
  Same for `test_workbench_search.mjs`'s `real-sql-rpc` test (no
  `WORKBENCH_SQL_DATABASE_URL` set) — the actual SQL migrations have still
  never been exercised against a real schema in this repair pass.
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

IN PROGRESS — 7 confirmed bugs fixed with new passing regression tests;
`npm run test:unit` still fully green (34 tests, 0 failures). The desktop
findings table (Task 5) was found deleted by the prior CI-fix and is now
restored and passing. Login UI, historical-search UI, the primitives/status/
views file-level flakiness (confirmed pre-existing, not caused by this pass),
and all real-Postgres SQL verification remain open. Do NOT treat this as
task-level plan completion — see reopened checkboxes in
`.omo/plans/free-tier-investigation-upgrade.md`.

## Next steps

1. Build the Task 9 login UI (backend is ready) and the Task 8 historical-
   search UI (backend is ready) — biggest remaining chunks of real work.
2. Set up a disposable Postgres and actually run the `WORKBENCH_*_DATABASE_URL`
   real-SQL suites at least once before claiming Task 7/8 SQL is sound.
3. Add an end-to-end Playwright test proving the `category:`/`verdict:`
   presets actually filter correctly against real brand data.
4. Root-cause (or file as a known/accepted flake with evidence) the
   primitives.mjs/status.mjs/views.mjs file-level-fail-despite-all-tests-
   passing pattern.
5. Provision the owner-approved analyst email/password account and finish
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

- Updated: 2026-09-23 11:05:31 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: b96e7eb
- Dirty files: 0
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->

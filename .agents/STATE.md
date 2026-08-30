# Agent State

Current task: Phase 6 real monitor implementation.

Progress:
- No prior `.agents/STATE.md` existed at session start.
- Read `AGENTS.md` and `README.md`.
- Confirmed clean worktree on `main`.
- Inspected top-level file inventory and core JSON data files.
- Parsed all four core JSON files successfully.
- Inspected representative CI/security workflow configuration.
- Starting first phase as a data validation gate for the core JSON files before manual verification work.
- Added `scripts/validate_data.py` and `.github/workflows/data-validation.yml`.
- Ran `python scripts/validate_data.py`; validation passed and reported 69 unverified allowlist entries plus 11 unverified scheme entries.
- Phase 1 complete: structural seed-data validation passes locally and is wired into CI for data/script/workflow changes.
- Phase 2 complete as an enforcement gate: `python scripts/validate_data.py --release` fails until all allowlist and scheme entries are verified with metadata, and the CI workflow exposes this via a `workflow_dispatch` `release_readiness` input.
- Removed generated `scripts/__pycache__` output.
- Phase 3 started as the first official-source verification batch.
- Verified 4 allowlist entries with source metadata: `dbs.com`, `dbs.com.sg`, `posb.com.sg`, `ocbc.com`.
- Ran `python scripts/validate_data.py`; validation passed and now reports 65 unverified allowlist entries plus 11 unverified scheme entries.
- Ran `python scripts/validate_data.py --release`; it still fails as expected because launch readiness remains incomplete.
- Phase 4 complete: verified 12 Singapore government/service allowlist entries with official-source metadata.
- Phase 5 complete: verified all 11 scheme entries with official-source metadata.
- Ran `python scripts/validate_data.py`; validation passed and now reports 53 unverified allowlist entries plus 0 unverified scheme entries.
- Ran `python scripts/validate_data.py --release`; it still fails as expected because 53 allowlist entries remain unverified.
- Continued verification through the remaining allowlist.
- Verified 51 additional allowlist entries from official-source URLs.
- Moved `paylah.com.sg` and `qoo10.sg` out of active allowlist suppression into `pending_verification` because exact registrable ownership/current validity could not be proven strongly enough.
- Ran `python scripts/validate_data.py`; validation passed with 67 active allowlist entries, 0 unverified, and 11 schemes, 0 unverified.
- Ran `python scripts/validate_data.py --release`; strict release-readiness validation passed.
- Completed follow-up research on pending candidates:
  - `paylah.com.sg` resolves and returns a blank HTTP 200 page, but HTTPS times out and no official DBS/POSB source confirms that exact registrable.
  - `qoo10.sg` and `www.qoo10.sg` still do not resolve; public/current sources show MAS suspended Qoo10 payment services in September 2024 and the Singapore High Court ordered Qoo10 wound up in November 2024.
- Kept both candidates in non-suppressing `pending_verification` and updated their rationale.
- Re-ran `python scripts/validate_data.py` and `python scripts/validate_data.py --release`; both passed.
- Started Vercel deployment preparation.
- Added a static dashboard (`index.html`, `styles.css`, `app.js`) that reads the existing JSON seed files at runtime.
- Added `package.json` with a release validation script and `vercel.json` for static hosting headers/clean URLs.
- Confirmed Supabase is not needed for the current deployable surface because no runtime database/auth path exists yet.
- Vercel team available via connector: `theprawnvercel` (`team_ARK7HKobyCMp0PCArQTLxbz6`).
- No existing `sgcertwatch` Vercel project was found in that team.
- Vercel CLI is installed, but networked account/team commands timed out locally; Vercel connector deploy returned `INVALID_ARGUMENT` for this unlinked local project.
- Created Vercel project `theprawnvercel/sgcertwatch`.
- Pushed commit `40475b9` to `origin/main`.
- Linked the local checkout to Vercel project `sgcertwatch`.
- Connected the Vercel project to GitHub repository `https://github.com/hongyime/sgCertWatch2026.git` using `vercel git connect`.
- Deployed production: `https://sgcertwatch.vercel.app` is aliased to ready deployment `dpl_9NaFcTj24HT9Ykwf6kapDaB1fKjg`.
- Added custom domain `sgcertwatch.hong-yi.me` to the Vercel project. Vercel reports it is attached and verified with a valid current CNAME, but recommends changing Cloudflare DNS to CNAME `sgcertwatch` -> `54c38f6ce13cfacb.vercel-dns-017.com.` with proxy disabled.
- User explicitly chose not to do the Vercel-recommended DNS cleanup because DNS should remain managed through Cloudflare.
- Started Phase 6 real monitor work.
- Added reusable CT scoring engine in `lib/scoring.js`.
- Added Vercel API `api/findings.js` for dashboard feed reads.
- Added optional Supabase REST adapter in `lib/supabase.js` and schema in `supabase/schema.sql`.
- The earlier push-style ingest endpoint and CertStream bridge were removed after the user clarified that 5-minute scheduled polling is acceptable.
- Added scoring tests in `scripts/test_scoring.js` and wired them into package scripts/CI.
- Production `INGEST_TOKEN` was removed from Vercel after deleting the old ingest endpoint.
- Ran release validation and scoring tests; both passed.
- Pushed Phase 6 commit `f671505`; Vercel Git deployment `dpl_Hyg3uown9USfDDWcSZx4YevEWrya` is `READY` and includes two Node serverless functions.
- Completed Supabase wiring for project `umixzwbsajyhiuaethxq`.
- Applied `supabase/schema.sql`; `public.findings` exists with RLS enabled and direct Data API grants revoked from `anon`/`authenticated`, leaving server-side `service_role` access.
- Set Vercel production env vars `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `CRON_SECRET`.
- Wrote local ignored `.env.local` with Vercel Cron settings.
- Fixed Vercel function packaging by statically importing seed JSON in `lib/data.js`.
- Verified synthetic ingest/readback earlier, then removed the old endpoint when replacing ingestion with Vercel Cron.
- Removed the scheduled GitHub Actions bridge; no GitHub secret is needed for polling now.
- Removed the synthetic smoke-test finding; `public.findings` count returned to 0.
- Started dashboard UX cleanup after user feedback.
- Made summary cards and dataset tabs switch the data table directly across watched brands, suspicious keywords, allowlist, and schemes.
- Collapsed `paylah.com.sg` and `qoo10.sg` pending-candidate details under manual review notes so normal users do not see long internal rationale by default.
- Added plain-language first-screen context and a live-feed status area.
- Added 60-second live feed refresh in the browser.

Current understanding:
- This is a data/configuration repository for a Singapore-focused Certificate Transparency monitoring dashboard.
- There is no application runtime or package manifest in the current tree.
- Core data files are `watchlist.json`, `keywords.json`, `allowlist.json`, and `schemes.json`.
- Seed allowlist and scheme verification status is intentionally incomplete; launch is blocked until `verified:false` entries are verified.
- Current data counts: 73 watched brands, 50 suspicious keywords, 69 allowlist entries, 11 scheme entries.
- 67 active allowlist entries are verified; 0 active allowlist entries remain unverified; all 11 scheme entries are verified.
- 2 non-suppressing pending candidates remain for future human/source review: `paylah.com.sg` and `qoo10.sg`.
- Follow-up research confirms neither pending candidate should be restored to active suppression without stronger proof.
- CI includes seed-data validation and scoring-engine tests for data/scoring changes.

- Batch F complete (B2): structural anchor predicate shipped (commit 4c5df27) - exact/squat-exact unconditional, fuzzy needs context-token or deception marker, geography removed. F2 spread dbs-token-auth.rest vs dbs-login-verify.cfd = 0pts (both 147). Post-F official eval: FP@70=129 (~12876/day stage-one candidates), adversarial 53/60.

Next steps:
- alerts/day stage-2 floor (50/day) is not met by the scorer alone (600k artifact eval: ~6,050/day at alert_min); stage-2 remains gated on post-capture verification, not raw scorer output per amended DECISION-10 and B3 Finding 3.
- 600k-negative artifact mining is complete for current G evidence. Do not commit the huge artifact; keep using local/artifact/sharded JSONL for future reruns.
- Supabase JWT/key cleanup is no longer an active item; user explicitly said to skip/ignore rotation on 2026-08-29.
- Batch G TP loss 3 items (41->38): documented, within noise, not compensated per spec. Rebuild positive set once more monitor findings accumulate (Batch I framework in place).
- Batches I/G/H fully committed and pushed to main. 15R capture workflow live on Actions schedule.
- 2026-08-28 Codex follow-up on items 2/3/4:
  - H-3 unblocked: current Chrome v3 log list exposes live usable Google Argon/Xenon 2026h2/2027h1 and DigiCert Wyvern/Sphinx 2026h2/2027h1/2027h2 RFC6962 endpoints; all 10 returned `get-sth` 200 and one-entry `get-entries` 200.
  - `scripts/mine_extended_negatives.mjs` now defaults to Google,DigiCert operators from the live Chrome list, has env knobs for operators/states/sample window, and syncs `fixtures/corpus/extended_negatives.jsonl` into `corpus.json`; `mine-negatives.yml` stages both files.
  - Smoke-mined 94 new live CT negatives (extended file 2606 -> 2700) and synced 1837 previously missing extended negatives into `corpus.json` (current `extended_negatives_added` 2700).
  - 15R capture pipeline manually verified via Actions run 33179003348: success, `MAX_CAPTURES=5`, processed 5 findings and wrote captures without errors.
  - Fixed remaining current gov/trust exact-anchored FP class: `subdomain_brand_squat` now applies the common-word context requirement for bare exact segments; targeted gov/trust FP@70 is 0/265 candidates.
  - Verification: `python scripts/validate_data.py --release` passed; `npm run test:unit` passed including e2e. Full `node scripts/eval.js` was stopped after running silently for several minutes; use the 600k workflow then rerun eval for final G metrics.
- 2026-08-28 continuation:
  - Full `mine-negatives.yml` run 33181258726 succeeded but only reached 68,231 extended negatives, not 600k, because the per-log sample window capped the run. The workflow pushed commit `99ca748` remotely and GitHub warned `corpus.json` was 83.37 MB.
  - 600k negatives cannot be safely synced into `corpus.json` or committed as one JSONL file under current record size; use local/artifact/sharded JSONL plus `scripts/eval_extended_negatives.mjs` for G rerun evidence.
  - `scripts/build_sg_advisories.mjs` now treats MAS IAL as the only potential domain-IOC source and records CSA/SingCERT, ScamShield, SPF, and GovTech ScamShield as source-status only. Current official pages fetch HTTP 200 but expose no safe machine-readable malicious-domain IOC feed; `fixtures/corpus/sg_advisories.jsonl` is intentionally empty and `fixtures/corpus/sg_advisory_sources.json` records fetch/source status.
  - Validation passed after SG source cleanup: `python scripts/validate_data.py --release`. Unit test suite passed after restart.
  - Interim streaming eval over the pulled 68,231-negative checkpoint completed: FP@70=58, TN=68,173, extrapolated alerts/day=5,100. This is not the final G rerun; corrected Actions run 33186128572 is generating/uploading the 600k artifact.
  - Corrected Actions run 33186128572 completed successfully and uploaded `extended-negatives-jsonl`, but the artifact contained 333,815 negatives, not 600k. Widened workflow sampling to 3,000,000 entries/log and added 25k progress logs for the next 600k retry.
  - Widened Actions run 33188880545 completed successfully and uploaded a 541,825-negative artifact, still short of 600k by 58,175. Increased workflow sampling to 4,000,000 entries/log for the next retry.
  - 4,000,000-entry single-window run 33192705501 completed successfully but only uploaded 381,900 negatives. Logs showed the miner stops after one trailing window per log; patched it to support `MAX_WINDOWS_PER_LOG` and set the workflow to scan up to 3 trailing windows/log.
  - Multi-window run 33196667853 completed successfully and uploaded a 600,000-line artifact at `C:\Users\bryan\AppData\Local\Temp\sgcertwatch_artifact_33196667853\extended_negatives.jsonl` (314,283,132 bytes). Full streaming G eval completed on all 600,000 negatives: FP@70=605, TN=599,395, suppressed=2, extrapolated alerts/day=6,050.
- 2026-08-29 continuation:
  - User explicitly deprioritized Supabase JWT rotation.
  - Added `plan.html` to `.gitignore`, committed `3162441` (`chore: ignore local plan html`), and pushed to `main`.
  - Production browser flow was verified on `https://sgcertwatch.vercel.app/` and `https://sgcertwatch.hong-yi.me/`: app loads, live Supabase feed connects, dataset tabs/search/filter work, and finding detail dialog opens.
  - `https://3xiv17lbp26g.postplan.dev/` is a stale static planning page, not the production app.
- 2026-08-29 items 2-7 restart:
  - Item 2 complete: live Chrome v3 log list currently exposes 10 Google/DigiCert candidate RFC6962 logs. 9/10 returned `get-sth` 200 and one-entry `get-entries` 200 in the fresh check; DigiCert Sphinx2027h1 returned `get-sth` 200 but one trailing `get-entries` probe returned 400.
  - Item 3 complete: fresh `capture.yml` workflow dispatch run 33229261575 succeeded on commit `2f5c929`; capture step ran with `MAX_CAPTURES=5`, queried Supabase, found 0 uncaptured findings, and exited cleanly.
  - Item 4 complete: `npm run test:unit` passed, including the gov/trust common-word regression test. Additional targeted scan over 260 gov/trust candidate rows found 0 exact-anchored gov/trust FP offenders at score >=70.
  - Item 5 complete/no rebuild: live Supabase classification check found 14 new live SG-positive domains beyond the fixture, below the 200-new-finding threshold. Existing fixture has 514 SG-positive monitor rows; `corpus.json` already contains 513 monitor positives.
  - Item 6 complete as evidence, not a new commit of data: the existing 600,000-line artifact from Actions run 33196667853 remains the full G rerun evidence (FP@70=605, TN=599,395, suppressed=2, extrapolated alerts/day=6,050). A fresh full local rerun was stopped after an extended silent runtime; a capped artifact sanity rerun over 10,000 rows completed with FP@70=8, TN=9,992.
  - Item 7 complete: refreshed `fixtures/corpus/sg_advisory_sources.json`; MAS IAL, ScamShield, CSA/SingCERT, SPF, and GovTech ScamShield remain status-only sources with 0 extracted usable domain IOCs. `fixtures/corpus/sg_advisories.jsonl` remains empty.
  - Verification this pass: `python scripts/validate_data.py --release` passed; `npm run test:unit` passed.
- 2026-08-29 frontend restructure:
  - User reported raw CT log IDs/degraded source rows on the front page and asked for `Domains to watch now` to be the first/main user flow.
  - Reworked the static UI into top-level views: Domains, Watchlist, Review, Monitor. The default first view is now the live suspicious-domain feed headed `Domains to watch now`; detection config moved to Watchlist; CT source rows moved to Monitor behind a details disclosure.
  - Added `favicon.svg` to remove the browser favicon 404.
  - Local Playwright verification on desktop and mobile confirmed first active panel is `alerts`, visible heading is `Domains to watch now`, first card is a finding, no CT log hash IDs appear in the first-view text, Watchlist search still returns DBS allowlist results, and Monitor source details are collapsed by default.
  - Verification: `python scripts/validate_data.py --release` passed; `npm run test:unit` passed.
  - Commit `fe75d12` (`feat: make domains feed the primary view`) was pushed to `main`, but Vercel production is still serving the older deployment because explicit `vercel deploy --prod --yes` failed with the free daily deployment limit: `Resource is limited - try again in 24 hours (more than 100, code: "api-deployments-free-per-day")`.
- 2026-08-30 deployment retry:
  - Retried production deploy after quota reset; initial explicit deployment `dpl_AnrQf8BYQ97KvtMdSSZK6kHLj1Bp` was accepted.
  - While inspecting deployment headers, found and fixed malformed CSP in `vercel.json`: `frame-ancestors 'none` was missing the closing quote.
  - Verification after CSP fix: `python scripts/validate_data.py --release` passed; `npm run test:unit` passed.
  - Tightened the default Domains view to `Watch now (>=70)` so low-score stored findings do not lead the analyst workflow. Local browser verification confirmed the default list hides a score-10 item, shows the score-88 item, and still shows low-score findings after switching to `All stored findings`.
  - Final production deploy `dpl_D7MPbmgXi6hqpnQET8UALidj8o3E` succeeded after commit `3f24350`. Both `https://sgcertwatch.vercel.app/` and `https://sgcertwatch.hong-yi.me/` served the final HTML.
  - Production Playwright verification passed on both aliases: active panel `alerts`, heading `Domains to watch now`, default filter `watch`, 8 visible review domains all score >=70, no raw CT log hashes in the first-view text, Watchlist allowlist search for `dbs` returns 2 results, Monitor source details are collapsed by default, JSON/API/favicon requests returned 200, and browser console errors were empty.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-08-28 21:34:58 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: 3722759
- Dirty files: 1
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->

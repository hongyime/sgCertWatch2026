# Agent State

Portfolio storage maintenance, 2026-09-10: Guarded migration `b5d0568` removed
`findings_cert_identity_idx` from production and recovered 27,762,688 bytes.
Live table files, privileges, constraints, RLS policies and retained indexes
match their pre-migration definitions; finding/sighting counts did not decrease.
Hosted run `34468234544` passed all 14 PostgreSQL migration checks on 2,500/5,000
synthetic findings/sightings, plus pipeline and desktop/mobile suites. The local
Docker bootstrap timed out before SQL; hosted PostgreSQL is the test evidence.
Runtime identity uses the finding primary key. Preserve all records, evidence,
other indexes and the existing scheduler/soak follow-up. Storage still exceeds
the Free allowance; larger lossless representation work remains necessary.
The read-only management role cannot EXPLAIN the restricted intelligence RPCs;
both functions exist. Ordinary feed/detail/source plans use retained indexes.

Current task: Organization-targeted scheduler is operational; first real Cloudflare CT scan is verified end to end. Real observation started 2026-09-09T00:45:44.188Z. Observe the first due hourly intel dispatch and verify the full measured day after 2026-09-10T00:51Z. Telegram remains removed.

Current evidence and next steps:
- Replacement token is in ignored `.env.scheduler` and the Worker's encrypted GITHUB_TOKEN secret, with other secrets retained. Deployment `732da869-4e63-4cbb-9c2c-ebf727c1fc75` is active in dashboard mode. Public status remains 401, public mutation 404, authenticated status 200. Checked-in config defaults paused: preserve `--var DISPATCH_ENABLED:true` on future active deployments. Never expose credentials or substitute a broad machine token.
- Real cron at 00:50 dispatched CT `34296724389`, correlated by returned run ID. It started 00:51:04Z and succeeded 00:56:41Z: 54,489 entries checked, 2,462 findings and 2,486 sightings saved. Monitor shows cloudflare provenance and fresh/completed status. Direct CT succeeded; static logs retain genuine timeouts and existing Geomys/IPng cooldowns. crt.sh stayed in hourly standby. Partial coverage is accurate.
- Runtime `d775852` removes active Telegram/queue paths and is pushed to main. Vercel deployment `dpl_HcD1BXfN6m4YpqrbnfmEYNQbfKN6` is ready. `notifications.yml` remains `disabled_manually` after rollout. Historical data/helpers remain dormant; no delivery credentials are required.
- Resolved token diagnosis: the first token had Actions read/write but targeted a personal resource owner, excluding this organization repository. Live identity, organization membership and dispatch checks confirmed the mismatch. The replacement targets hongyime and passes authorization. Endpoint required-permission headers describe requirements, not actual token grants. Future setup should select the organization and only sgCertWatch2026; keep credentials in ignored setup/Worker secrets and never export the broad machine token.
- Active scanner no longer enqueues notifications; retired CLI is a no-op even with legacy credentials. Monitor/API no longer reads or renders queue state. Scheduler has two workflows, default dashboard-only incidents, version-2 state migration and no Telegram delivery. Scheduler 78 tests, SQLite runtime smoke, dry run, full unit, intel/storage, release data and desktop/mobile UI checks pass; dependency audit has no vulnerabilities. Independent integration review is complete.
- Real enabled ticks preserve the existing coordinator and observe only ingest/intel. At 00:55 the CT reservation was matched to the actual run and prevented duplicate dispatch; the soak recorded its first actual start, ten observed minutes and no tick errors. Alerts delivered remain zero. Read-only SQL confirms zero notification jobs, including since the external scan started.
- CI `34296662606` passes PostgreSQL 17, all runtime suites and Chromium desktop/mobile on `497b647`; Vercel deploy is successful. Both production aliases again pass live Domains, details/evidence, JSON/CSV exports, Watchlist, Review, Monitor and favicon at 1440/390px, with external-trigger provenance visible and the Monitor screenshot inspected. All owned verification processes finished.
- Hourly intel correctly skipped as recent_actual_start during activation; its last verified completed run is `34294443227`. First Cloudflare-origin intel execution is not yet verified and must wait until due (not before about 01:15Z unless a fallback scan advances the timestamp). Do not force provider requests to test it.
- `node --env-file=.env.scheduler scripts/verify_soak.mjs` reaches real Worker/database evidence and correctly exits incomplete before 24 hours; active/healthy, two-workflow, fresh-observation and incident checks pass. Repeat after the measured day, not merely the deployment anniversary. Earliest practical verification: 2026-09-10 08:51 SGT. No full-day reliability pass is claimed.

Previous release baseline (notification requirements below are superseded by the current task):
- Runtime `7f853ba` is on main and deployed as `dpl_CYaZ3GNo5LDtPoyAHS2vWhbuFTgX`, READY on `sgcertwatch.vercel.app` and `sgcertwatch.hong-yi.me`. Vercel commit status confirms this deployment belongs to that SHA.
- All local core/intel/reliability/release-data suites pass; audit reports zero vulnerabilities. CI `34246781888` passes PostgreSQL 17 (30 outbox checks, 20-way lock contention, four blocked-expiry regressions), 74 scheduler tests and desktop/mobile Chromium. CodeQL, Semgrep, TruffleHog and LFS checks pass. Independent database, scheduler, browser and release-security reviews are complete.
- CT `34246820421` succeeded: 30,851 checked, 1,324 findings and 1,353 sightings saved, six direct logs successful. Static CT made progress despite a TrustAsia timeout and Geomys 429; crt.sh timed out. Live SQL confirms persisted Geomys pause until 16:46:33Z and crt.sh pause until 17:45:59Z. Partial coverage is accurate, not a total scanner outage.
- Duplicate dispatch `34247623022` succeeded with `scan_not_due`, no source-fetch stage and unchanged completed start/success timestamps. Intel `34246843332` succeeded; OpenPhish refreshed while the other three providers retained their six-hour schedules.
- Notifications `34246893819`, `34247316792` and `34247669614` succeeded with honest unconfigured/zero-backlog status. Durable queue schema is applied and SQL-tested; actual Telegram delivery is NOT verified because channel credentials are absent. No enqueue accumulation occurs without a configured channel.
- `scripts/verify_live.mjs` passes both production aliases at 1440/390px: default Domains, finding detail/evidence, JSON/CSV downloads, Watchlist allowlist search, Review, Monitor metadata, favicon, console and overflow checks. Production screenshots inspected, including the mobile first viewport. All owned local test/browser/server/container processes have stopped; reviewers are closed.
- Remaining scheduler gate: correct the supplied token's repository Actions read/write permission. Stage paused until verified, generate protected status token and use only Supabase anon/publishable access in Cloudflare. Never export service-role or the broad machine GitHub token. No messaging channel is required.
- After activation, verify real dispatches and persistent cooldown/restart behavior, then run `scripts/verify_soak.mjs` after 24 observed hours in dashboard mode. Simulated cadence and local tests do not satisfy this gate. No JWT rotation, Google Cloud, paid services or Vercel scanning. Detailed resume notes: `.agents/handoffs/2026-09-08-crtsh-resilience.md`.

Earlier investigation history (superseded by current evidence above):
- Official crt.sh root `/?identity=...&output=json` is supported. Upstream May 28, 2026 notice attributes recurring 50x failures to overloaded/frozen database replicas and inefficient result sorting.
- Local root and narrow domain probes both returned HTML HTTP 404; previous Actions run returned 502. Existing adapter incorrectly treats 404 as an empty successful search.
- Local defects: process-only breaker resets each Actions run; up to eight requests per scan; common fetch timeout stops at headers, leaving response-body reads unbounded.
- Implement bounded optional-backup polling with persisted cooldown, accurate errors/retry time, and regression tests. Primary direct/static CT stays on GitHub Actions, with no Vercel scans or new paid services.
- A read-only sidecar is auditing scheduler history and ingest recovery. See `.agents/handoffs/2026-09-08-crtsh-resilience.md`.
- crt.sh cooldown/body/error tests and all existing unit/intel tests pass. Dashboard fixture checks pass desktop/mobile with visible provider error and retry times.
- Audit found active GitHub schedules arriving hours apart (latest scheduled run 34194312243 succeeded 14:21-14:28 SGT). Offset cron is only a mitigation; asked user about free Cloudflare trigger for reliable timing.
- Implemented primary-only availability, persisted ingest failure stages, checkpoint-before-notification ordering, bounded alert delivery and regression tests. Worker is fixing static tile error propagation and fair log rotation in its dedicated files.
- Static CT now retains partial progress, propagates tile errors, rotates logs and strictly validates tile framing before advancing. All 24 static resilience scenarios pass, including non-DNS certificates and malformed/truncated 200 responses.
- Core/unit, 18 storage/API tests, intel quota/provenance tests, release data validation and desktop/mobile fixture checks pass. Failed backup cooldown is saved before scoring without advancing primary cursors. Ready for push, deployment and a live Actions scan; independent scheduler is not configured yet.
- Pushed `1546ae7`; deployed `dpl_AoUPiMmfZ8PgdUB14vRPKHYx1sGq`. CI `34206230379` passes. Both public aliases pass desktop/mobile flows.
- Live scan `34206246005` succeeded: 47,269 entries checked, 2,152 findings and 2,170 sightings saved. crt.sh returned a valid empty JSON result in ~6s and persisted an hourly next poll. One TrustAsia timeout and the static 90s budget stop yielded partial coverage.
- Follow-up distinguishes deliberate budget cancellation after progress from provider timeouts; malformed tiles and genuine timeouts remain errors. Independent review notes optional Telegram overflow has no durable notification retry queue; dashboard findings are retained, but alert delivery remains best-effort as documented.
- Follow-up `15aea1d` deployed as `dpl_8J9G1vVksDLAFh5Jfocpe5Ymtvfd`. All 26 static resilience scenarios and desktop/mobile fixtures pass. Live resume scan `34207087100` is running; baseline saved static index is 10 and crt.sh last attempt remains 08:45:54Z, next allowed 09:45:54Z.
- Resume scan `34207087100` succeeded: 27,797 checked and 1,074 findings saved. All six direct logs succeeded; crt.sh skipped without changing its attempt/retry timestamps. Rotated static logs exposed genuine 429 responses from Geomys/IPng and a TrustAsia timeout, so partial coverage remains accurate.
- Added static per-operator 429 cooldowns (minimum 1h, longer Retry-After honored), persisted before scoring while retaining unsaved primary cursors. Sibling logs pause immediately and other operators continue. All 29 static tests, seven runner recovery tests, core/intel suites and desktop/mobile fixtures pass. This final rate-limit addition is tested with mocked providers; two real scans above verified the main pipeline and restart behavior.
- Final runtime `5d7e84c` pushed and deployed as `dpl_vorTJr2MUxJWSxNvfgQkKFHCbrp4`. CI `34208305512` passes. Both public aliases pass final desktop/mobile flows, API/favicons and console/layout checks. No third provider scan was needed for the rate-limit patch; its restart/Retry-After behavior is covered by regression tests.
- Remaining: GitHub's active cron still has observed multi-hour delays; Cloudflare trigger preference/account setup is unanswered and no external scheduler was created. No Vercel scanning, Google Cloud, JWT rotation or new credentials were introduced. Some static operators remain degraded/rate-limited; direct CT is working and crt.sh is in scheduled standby.

Active continuation:
- CT remains discovery on GitHub Actions; widen polling budgets. No Vercel scans.
- Approved: OpenPhish, urlscan, URLhaus, ThreatFox. PhishTank excluded (signups disabled); Google Cloud excluded by user. JWT rotation remains skipped.
- Add separate expiring evidence with exact-host matches and capped review-priority boost, retaining original CT score and corpus labels.
- Conservative persisted source intervals and shared abuse.ch rate-limit cooldown are required. Credentials belong only in Actions secrets/local ignored configuration.
- Parallel ownership: storage/API/schema and dashboard workers; main agent owns adapters, runner, workflow, integration and verification.
- Provider adapters, persistent request reservations/cooldowns, priority helper and hourly Actions workflow implemented. Parser/provenance/rate-limit tests pass; existing unit suite and release data validation pass.
- ABUSECH_AUTH_KEY and URLSCAN_API_KEY configured in repository Actions secrets. Production database reachable (about 78k findings); storage worker optimizing bounded watch queries before migration/deployment.
- Applied `supabase/intel.sql` successfully. Live checks confirm evidence RLS, public read/no write, private candidate function and 500 distinct candidate registrables. Public state excludes private cooldown/cursor state.
- Desktop/mobile fixture browser checks pass for priority promotion, source badges, safe evidence links, filter refresh races and layout. Independent review fixes restart guards, quota reset retention, missing provider timestamps and wildcard exact-match handling.
- Main pushed through `e3e2660`; production deployment `dpl_2HcTE9UAPTDNfAg8Smw2ZFvuVtpj` ready. Restored deployment exclusions removed by automated config sync.
- First live intel Actions run `34179236224` succeeded: OpenPhish 300 entries, URLhaus 623, ThreatFox 964, urlscan 3 searches, all four OK and zero exact-host matches in selected CT candidates. Persisted next polls: OpenPhish 12h, other sources 6h.
- Validation CI exposed pre-existing scoring-before-install ordering; moving npm install before scoring tests. Wider CT run and live desktop/mobile checks in progress.
- Validation CI fixed and green in run `34179357817`. Both production domains pass live desktop/mobile flows, provider health, favicon and console checks. Findings API measured ~4.3s cold and ~0.4s warm.
- Candidate SQL now alternates near-threshold and existing-alert registrables. Live verification: 500 distinct candidates, including 250 scoring 60-69. New migration applied; original CT scores remain unchanged.
- Wider CT run `34179236340` failed after scoring at the large findings write (8-second DB timeout). Changed CT writes to 200-row batches with 30-second write timeouts, retaining short public read budgets; reduced static polling to 30 tiles/log and 90 seconds. Added ingest progress logs; retry required.
- Final CT retry `34180182808` succeeded in ~6 minutes: 58,109 checked, 2,536 findings persisted, 2,556 source sightings. Direct CT (544) and Static CT (57,565) healthy; CertStream standby; optional crt.sh backup returned HTTP 502, so overall coverage is partial.
- Final deployed code `7ca21b6`, deployment `dpl_C6Hsseo9c3X1bSCKSNamXFUT1NNq`. Both public domains passed desktop/mobile flows; latest public API checks pass. CI `34180169197` passes core and intel tests.
- Intel replay run `34179738030` succeeded without advancing provider check times, confirming persisted schedules avoid repeated provider requests. Live DB verification exercises evidence insert/read, blocked anon writes and host lookup inside a rolled-back transaction; no synthetic evidence remains.

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
- 2026-08-30 monitor cleanup:
  - User reported all Monitor detail rows showing base64 CT log IDs as degraded/stale. Root cause: `/api/source-status` returned raw per-log cursor rows as `sources` and only exposed `overall`, while the frontend expected `health` and `ok` source-run rows.
  - Scans are scheduled in GitHub Actions, not Vercel Edge/Cron: `.github/workflows/ingest.yml` runs `scripts/run-ingest.mjs` on `*/15 * * * *` plus manual `workflow_dispatch`. GitHub schedule delivery is not exact and recent scheduled runs were several hours apart, but the workflow is the authoritative scheduler after the Vercel quota/Edge constraint.
  - Added dashboard-facing `display_sources`, `health`, and scheduler metadata to `/api/source-status`; frontend now prefers `display_sources`, uses human labels, shows persisted counts, and no longer renders raw CT log IDs in normal Monitor details.
  - Added extra favicon metadata (`shortcut icon`, `apple-touch-icon`, Open Graph title/description) pointing at `favicon.svg` for browser/dashboard crawlers.
  - Updated Monitor top-line copy to `Primary sources active` when Direct CT or Static CT is ok, so a degraded `crt.sh` backup does not make the primary scan path look down.
  - Manual CT ingest workflow run 33286954335 succeeded. Production deploy `dpl_3TzKC8PNGhgYjRnGj1vqnh7xhHwP` succeeded from commit `a846f21` and is aliased to both public domains.
  - Production browser verification on both aliases: Monitor shows `Primary sources active`; details show grouped labels (`crt.sh backup`, `Direct CT logs`, `Live stream`, `Static CT logs`); no base64 CT log IDs render in the monitor detail text; `/api/source-status` includes `display_sources` and `schedule`.
- 2026-08-30 source-expansion research:
  - Best next source work is to widen the existing CT polling budget first: current workflow has a 14-minute job but defaults only `DIRECT_CT_LOGS_PER_RUN=2`, `DIRECT_CT_ENTRIES_PER_LOG=48`, and `STATIC_CT_MAX_TILES_PER_LOG=20`; the last successful ingest completed quickly, so there is room to increase coverage without returning to Vercel Edge/Cron.
  - External sources are possible as enrichment/positive-corpus feeds: Cert Spotter CT Search/Firehose, urlscan.io, OpenPhish, PhishTank, URLhaus, ThreatFox, and Google Safe Browsing/Web Risk. They need provenance storage, API keys/rate-limit handling, and source-specific semantics because most are not SG-specific CT discovery feeds.
  - SG-specific public machine-readable IOC sources still appear weak; previous MAS IAL, ScamShield, CSA/SingCERT, SPF, and GovTech research remains status-only unless partnership/API access appears.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-09 08:07:59 +08:00
- Machine: PRAWN-E14
- Harness: codex
- Event: session-start
- Branch: main
- HEAD: a5c04c3
- Dirty files: 28
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->

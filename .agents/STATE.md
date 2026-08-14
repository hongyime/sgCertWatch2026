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
- Added Vercel APIs: `api/ingest.js` for CT event ingestion and `api/findings.js` for dashboard feed reads.
- Added optional Supabase REST adapter in `lib/supabase.js` and schema in `supabase/schema.sql`.
- Added `scripts/poll_certstream.js` to bridge the public CertStream websocket feed into the ingest API.
- Added scoring tests in `scripts/test_scoring.js` and wired them into package scripts/CI.
- Set production `INGEST_TOKEN` in Vercel as a sensitive env var so production ingest is not open.
- Ran release validation and scoring tests; both passed.
- Pushed Phase 6 commit `f671505`; Vercel Git deployment `dpl_Hyg3uown9USfDDWcSZx4YevEWrya` is `READY` and includes two Node serverless functions.
- Completed Supabase wiring for project `umixzwbsajyhiuaethxq`.
- Applied `supabase/schema.sql`; `public.findings` exists with RLS enabled and direct Data API grants revoked from `anon`/`authenticated`, leaving server-side `service_role` access.
- Set Vercel production env vars `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and a rotated `INGEST_TOKEN`.
- Wrote local ignored `.env.local` with bridge settings.
- Fixed Vercel function packaging by statically importing seed JSON in `lib/data.js`.
- Verified synthetic `/api/ingest` persisted one high-severity finding to Supabase and `/api/findings` read it back.
- Added scheduled GitHub Actions bridge `.github/workflows/ct-ingest.yml` and set GitHub secret `INGEST_TOKEN`.

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

Next steps:
- Review and commit Phase 1-5 plus final verification changes if acceptable.
- JSON release-readiness gate is now green.
- Future review can investigate `paylah.com.sg` and `qoo10.sg`; do not add them back to active allowlist without exact-domain proof.
- No launch-blocking data decisions remain; pending candidates are intentionally non-suppressing.
- Commit and push the static app/data validation work so a Vercel Git project named `sgcertwatch` can be created from the GitHub repository.
- Do not apply Vercel's recommended Cloudflare DNS target change unless the user reverses the decision; keep DNS managed in Cloudflare.
- Monitor the scheduled `CT Ingest` workflow and dashboard feed; rotate the Supabase keys because secrets were pasted into chat during setup.

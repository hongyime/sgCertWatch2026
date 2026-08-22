# Agent Journal

- 2026-08-14: Began repository understanding pass; no prior shared agent state existed, so `.agents/STATE.md` was created for cross-agent handoff.
- 2026-08-14: Started first implementation phase as a core JSON data validation gate before manual allowlist/scheme verification.
- 2026-08-14: Completed Phase 1 structural validation and Phase 2 release-readiness enforcement gate; strict mode intentionally fails until all seeded allowlist and scheme entries are verified.
- 2026-08-14: Completed Phase 3 first verification batch for exact registrables `dbs.com`, `dbs.com.sg`, `posb.com.sg`, and `ocbc.com`; skipped weaker candidates until exact-domain proof is available.
- 2026-08-14: Completed Phase 4 Singapore government/service allowlist batch and Phase 5 scheme batch; remaining launch blocker is 53 unverified allowlist entries.
- 2026-08-14: Completed remaining active allowlist verification; strict release-readiness validation now passes after moving unproven `paylah.com.sg` and unresolved `qoo10.sg` to non-suppressing pending verification.
- 2026-08-14: Completed follow-up research for `paylah.com.sg` and `qoo10.sg`; kept both non-suppressing because exact official ownership/current legitimacy remains unproven.
- 2026-08-14: Added a static Vercel-ready dashboard over the committed JSON data; Supabase is deferred because the current product surface has no runtime data/auth requirement.
- 2026-08-14: Created and deployed Vercel project `theprawnvercel/sgcertwatch`; `sgcertwatch.vercel.app` is live, and `sgcertwatch.hong-yi.me` is attached with a recommended Cloudflare CNAME update remaining.
- 2026-08-14: Connected Vercel project `sgcertwatch` to GitHub repository `hongyime/sgCertWatch2026` for future Git deployments.
- 2026-08-14: User chose to keep `sgcertwatch.hong-yi.me` DNS managed through Cloudflare and skip Vercel's recommended DNS target cleanup.
- 2026-08-14: Started Phase 6 as real monitor implementation: scoring engine, ingest/feed APIs, optional Supabase persistence, and CertStream bridge.
- 2026-08-14: Deployed Phase 6 commit `f671505` to Vercel; production deployment is ready with Node serverless ingest/feed functions.
- 2026-08-14: Completed Supabase persistence setup for project `umixzwbsajyhiuaethxq`; Vercel env vars and GitHub scheduled ingest secret are configured, with synthetic ingest/readback verified.
- 2026-08-14: Verified scheduled `CT Ingest` workflow connectivity and removed the synthetic smoke-test finding from Supabase after readback.
- 2026-08-14: Updated dashboard UX so summary cards navigate datasets, live feed auto-refreshes, and pending verification details are collapsed by default for non-technical users.
- 2026-08-14: Removed Cloudflare ingestion after user rejected that architecture; deleted the Worker/KV resources and replaced the repo path with Supabase-scheduled Vercel polling plus Supabase state/persistence.
- 2026-08-14: Vercel Hobby blocked 5-minute Vercel Cron, so scheduling moved to Supabase `pg_cron`/`pg_net` calling the protected Vercel polling function.
- 2026-08-14: Production deployment `dpl_FdGAckR1XnXuUy5r3YUBu8Z7kQCC` is ready on both requested aliases; current CT source health is degraded because public `crt.sh` searches are returning timeout/502 responses.
- 2026-08-15: User approved reliability upgrade using CertStream sampling plus direct CT log polling, with `crt.sh` retained only as fallback/comparison and no Cloudflare infrastructure.
- 2026-08-15: Multi-source CT polling deployed to Vercel production; direct CT logs now keep monitoring active even when CertStream or `crt.sh` is degraded.
- 2026-08-15: Reworked the dashboard landing page so release readiness and live findings come first, manual review uses matching alert cards, and config data sits behind one collapsed explainer control.
- 2026-08-15: User clarified the decision-data section should stay expanded, and quiet CertStream samples should show standby rather than an error state.
- 2026-08-15: Deployed the expanded decision section and CertStream standby handling to Vercel production; protected poll verified direct CT logging remains active while `crt.sh` can degrade independently.
- 2026-08-22: Orientation audit of CT ingestion, scoring, security posture, and documentation.
  - CT ingestion:
    - a. Endpoints contacted: `LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"`, `${log.url}ct/v1/get-sth`, `${log.url}ct/v1/get-entries?start=${start}&end=${end}` (`lib/ct/direct-logs.js`); `CERTSTREAM_URL = process.env.CERTSTREAM_URL || "wss://certstream.calidog.io/"` (`lib/ct/certstream.js`); `https://crt.sh/?q=%${token}%&output=json` (`lib/ct/crtsh.js`).
    - b. Protocols: RFC6962 (`/ct/v1/get-sth`, `/ct/v1/get-entries`), WebSocket (`wss://`), HTTP search JSON (`crt.sh`). Static CT API (`/checkpoint`, `/tile/...`) is NOT implemented.
    - c. Log list: Fetched at runtime in `lib/ct/direct-logs.js` from `https://www.gstatic.com/ct/log_list/v3/log_list.json` via `usableRfc6962Logs()`.
    - d. Cursors: Stored in Supabase `public.ingest_state` under key `ct_source_state` via `getState()` / `setState()` in `lib/supabase.js`.
    - e. Precerts vs leaves: Precertificates are discarded (`entryType !== 0` -> null). Findings deduplicated on `sha256(fingerprint + "|" + registrable)` or fallback string; no `sha256(TBSCertificate)` deduplication.
    - f. `get-entries` advance: Advances by returned count (`start + rawEntries.length`).
  - Scoring:
    - g. Signals and weights: `brand:exact` (+35), `brand:fuzzy` (+25), `tld:mismatch` (+15), `kw` (+10 each, cap +25), `scheme` (+45), `allowlist` (0, suppressed).
    - h. Registrable domain: Hand-rolled in `lib/scoring.js` using `TWO_PART_SUFFIXES` Set (`com.sg`, `net.sg`, `org.sg`, `gov.sg`, `edu.sg`, `per.sg`) and slicing `parts.slice(-3)` or `parts.slice(-2)`.
    - i. Allowlist matching: Exact string equality `entry.verified && entry.registrable === registrable` in `lib/scoring.js`.
    - j. `max_edit_distance`: Configured per brand in `watchlist.json` (0, 1, or 2) and per scheme in `schemes.json` (1 or 2). Not length-banded.
    - k. Punycode & confusables: Not decoded or handled anywhere.
  - Security:
    - l. Supabase keys: `api/findings.js`, `api/source-status.js`, and `api/cron/ct-poll.js` all use `SUPABASE_SERVICE_ROLE_KEY` via `lib/supabase.js`. `SUPABASE_ANON_KEY` is unused.
    - m. `CRON_SECRET` check: `request.headers.authorization === 'Bearer ' + expected` in `api/cron/ct-poll.js` (not constant-time).
    - n. HTTP methods: `api/cron/ct-poll.js` accepts both `GET` and `POST`.
    - o. `innerHTML`: `app.js` renders findings via `innerHTML` interpolated template strings with `escapeHtml()`.
    - p. Links: Hostnames are rendered in `<strong>`, not `<a href>`. Allowlist/scheme sources render as `<a href>`.
  - Docs:
    - q. `TASKS.md` and `PRD.md` are absent.
    - r. Schema is defined in `supabase/schema.sql` (findings, finding_sources, ct_source_runs, ingest_state).
    - s. `package.json` specifies `"type": "module"`, `"dependencies": { "ws": "^8.18.0" }`, and test/validate scripts.
- 2026-08-22: Scoped Supabase keys in `lib/supabase.js` to `anonHeaders` (read-only for `findings`, `ct_source_runs`, `ingest_state`) and `serviceHeaders` (write/cron only, guarded by call-stack inspection). Added RLS select policies for anon in `supabase/schema.sql`. Added `SUPABASE_ANON_KEY` to `.env.example`.
- 2026-08-22: Security finding: The previous `authorized()` check in `api/cron/ct-poll.js` failed open on preview deployments when `CRON_SECRET` was unset (`process.env.VERCEL_ENV !== 'production'`), accepted GET requests, and used non-constant-time string comparison (`===`). Live from 2026-08-14 to 2026-08-22. Replaced with `lib/auth.js` constant-time `checkBearer()` requiring POST, secret length >= 32, and returning uniform 401 errors. Documented `pg_cron` POST schedule SQL in `README.md`.
- 2026-08-22: Added dependency `psl` pinned to exact version `1.9.0` for Public Suffix List-based registrable domain (eTLD+1) computation in `lib/domain/registrable.js`. Replaced hand-rolled `TWO_PART_SUFFIXES` in `lib/scoring.js`. Added unit tests in `scripts/test_registrable.js`.
- 2026-08-22: Implemented exact allowlist matching on registrable domain, brand matching across all labels and decomposed affix forms, `subdomain_brand_squat` (+40), and `brand_in_path_position` (+15) in `lib/scoring.js`. Tested with five specified fixtures (`dbs.com.sg`, `internet-banking.dbs.com.sg`, `dbs.com.sg.evil.xyz`, `login.dbs.secure-verify.top`, `singpass.gov.sg.auth-portal.cfd`).
- 2026-08-22: Extracted all scoring weights, thresholds, and caps into versioned `scoring.json` (v2). Updated `lib/scoring.js` to dynamic configuration, added `scoring_version` to findings table in `supabase/schema.sql`, and added structural validation in `scripts/validate_data.py`.
- 2026-08-22: Created 120-item labeled ground-truth evaluation corpus in `corpus.json` (60 malicious, 60 benign) and evaluation runner in `scripts/eval.js`. Measured baseline scoring performance before detection changes: Precision 100.00% (TP=25, FP=0), Recall 41.67% (FN=35, TN=60), F1 Score 58.82%. Added `.github/workflows/eval.yml` and wired regression gate into `package.json`.
- 2026-08-22: Commit 7B (Corpus rebuild): Rebuilt evaluation corpus with 751 labeled items (155 positives, 536 negatives [426 from 25–69 mined band], 60 adversarial fixtures) across `corpus.json` and `fixtures/corpus/{positives,negatives,adversarial}.jsonl`. Baseline metrics established at alert threshold 70: Precision 99.00%, Recall 44.24%, F1 61.09%. Adversarial pass rate: 17/60 passed, 43 missed (baseline target for Commits 12–14). Bias note: Public feeds report noisy/verified phishing, whereas fresh CT issuance has distinct characteristics. As the monitor operates, 100+ confirmed findings will supersede feed-derived positives.
- 2026-08-22: Commit 8 (Dynamic CT log list): Implemented `lib/ct/loglist.js` to fetch CertSpotter monitor.json as primary and Google v3 log list as cross-check, caching in `ct_logs` and selecting logs with shard window overlap `[now - 1d, now + 400d]`. Removed hardcoded Cloudflare filter in `direct-logs.js` (git history investigation confirmed it was added without documented cause in commit `18a0c3f`). Added `ct_logs` and `ct_log_cursors` tables to `supabase/schema.sql`.
- 2026-08-22: Commit 9 (Static CT API tile reader): Implemented `lib/ct/static/checkpoint.js`, `lib/ct/static/tiles.js`, and `lib/ct/static/client.js` following the c2sp.org/static-ct-api specification. Supports checkpoint cryptographic signature verification, partial/full tile data retrieval with 3-digit path encoding, x509 and precert entry parsing, 50s execution time budget cap, and integrated into `lib/ct/orchestrator.js` to ingest Let's Encrypt tiled logs (closing the blindspot since Feb 2026).
- 2026-08-22: Commit 10 (Ingestion correctness: precerts, cursors, locking): Implemented precertificate parsing for both RFC 6962 and static-ct-api via `wrapTbsDer`, extracted stable identity `(cert_issuer_dn_sha256, cert_serial)` to deduplicate precert/final cert pairs into merged finding records, added Postgres/state advisory locking to prevent overlapping cron runs, added right-anchored identity querying, 30m circuit breaker, and exponential backoff to `lib/ct/crtsh.js`, and updated `supabase/schema.sql` with identity columns and indexes.
- 2026-08-22: Commit 11 (Source health and lag reporting): Created `lib/ct/source-health.js` and updated `api/source-status.js` to report overall health, protocol-level breakdown (RFC 6962, Static CT API, WebSocket, HTTP), and per-source lag metrics against tree sizes. Added `source_health` table with RLS in `supabase/schema.sql`.












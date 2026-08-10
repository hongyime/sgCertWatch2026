# sgCertWatch2026 — Implementation Plan

| | |
|---|---|
| **Status** | Not started |
| **Revision** | rev 2 |
| **Last updated** | 2026-08-10 |
| **Companion docs** | [`PRD.md`](./PRD.md) · [`DESIGN.md`](./DESIGN.md) · [`BLINDSPOTS.md`](./BLINDSPOTS.md) |

## How to use this file

- One task ≈ one pull request. If a task needs more than one PR, split it and renumber.
- `deps:` must be merged before the task starts.
- **Done when** is the acceptance criterion. If it isn't checkable, the task is written wrong.
- Three **kill gates** (M1-14, M5-02, and the M2-02b release block) map to `PRD.md` §11. Stopping at a gate is a success of the process, not a failure of the project.

**Sequence:** M0 → M1 → *gate* → M2 → M3 → M4 → M5 → *gate* → M6 → M7. M8 is continuous.

| Milestone | Theme | Tasks | Est. |
|---|---|---|---|
| M0 | Repo and scaffold | 7 | 0.5 d |
| M1 | Ingester spike — **KILL GATE** | 14 | 2 d max |
| M2 | Normalisation, filtering, scoring | 15 | 2.5 d |
| M3 | Storage and API | 14 | 2.5 d |
| M4 | Dashboard (P0) | 12 | 2 d |
| M5 | Launch and calibration — **KILL GATE** | 9 | 1.5 d |
| M6 | P1 | 13 | 4 d |
| M7 | P2 | 11 | 4 d |
| M8 | Ongoing ops | 5 | continuous |

**~11 focused days to P0 launch.** M1 is the risky one — do it standalone, first, before committing to anything else.

---

## M0 — Repo and scaffold

- [ ] **M0-01 · Create repo and licence** — *deps: none*
  - **Do:** Create `hongyime/sgCertWatch2026`, public, MIT. `.gitignore` for Python + Node.
  - **Done when:** Repo exists, is public, has `LICENSE`.

- [ ] **M0-02 · SHELL baseline** — *deps: M0-01*
  - **Do:** Apply the standard repo scaffold (README stub, issue templates, CODEOWNERS, standard workflows).
  - **Done when:** Baseline matches other repos; CI green on an empty commit.

- [ ] **M0-03 · Python project layout** — *deps: M0-01*
  - **Do:** `ingester/` package with `uv`, pinned deps: `cryptography`, `asn1crypto`, `idna`, `tldextract`, `httpx`, `confusable-homoglyphs` (or equivalent UTS #39 data), `pytest`, `ruff`.
  - **Done when:** `uv sync && pytest` succeeds with one placeholder test.

- [ ] **M0-04 · Lint and test CI** — *deps: M0-03*
  - **Do:** Workflow running `ruff check`, `ruff format --check`, `pytest` on push and PR.
  - **Done when:** CI is required on PRs and fails on a deliberately broken commit.

- [ ] **M0-05 · Commit the doc set** — *deps: M0-01*
  - **Do:** Add `docs/PRD.md`, `DESIGN.md`, `TASKS.md`, `BLINDSPOTS.md`. README links all four.
  - **Done when:** All four render on GitHub with working cross-links.

- [ ] **M0-06 · Commit the data files and schemas** — *deps: M0-01*
  - **Do:** Add `data/watchlist.json`, `allowlist.json`, `keywords.json`, `schemes.json` plus a JSON Schema for each.
  - **Done when:** A schema-validation test runs in CI and fails on a deliberately malformed entry.

- [ ] **M0-07 · Secrets and config plan** — *deps: M0-01*
  - **Do:** `.env.example` listing `INGEST_SECRET`, `INGEST_URL`. Document that the secret lives in Actions secrets + Worker secrets, never in the repo.
  - **Done when:** `.env` is gitignored; README documents setup.

---

## M1 — Ingester spike ⚠️ KILL GATE

> **Timebox: 2 days.** Per `PRD.md` §11, if M1 exceeds 2 days, drop the project. Do not start M2 before M1-14 passes.
>
> Spike the **Static CT** backend first — it covers Let's Encrypt (`DESIGN.md` §3.1) and is operationally simpler than RFC 6962.

- [ ] **M1-01 · Fetch and cache the CT log list** — *deps: M0-03*
  - **Do:** Fetch `https://www.gstatic.com/ct/log_list/v3/log_list.json`, parse **both** `logs[]` and `tiled_logs[]`, write `data/log_list.cached.json`.
  - **Done when:** Cached file committed; a unit test asserts both sections parse and at least one tiled log is present.

- [ ] **M1-02 · Log selection logic** — *deps: M1-01*
  - **Do:** Filter to usable/qualified logs whose `temporal_interval` covers today, minus `data/log_denylist.json`.
  - **Done when:** Selector returns ≥ 2 RFC 6962 and ≥ 2 tiled logs, including a Let's Encrypt shard. Tested against the cached fixture.

- [ ] **M1-03 · `LogSource` protocol** — *deps: M0-03*
  - **Do:** Define the protocol and `RawLeaf` dataclass per `DESIGN.md` §3.3.
  - **Done when:** A fake in-memory source implements it and passes a shared conformance test.

- [ ] **M1-04 · Static CT: checkpoint reader** — *deps: M1-03*
  - **Do:** `GET <url>/checkpoint`, parse the signed note, return tree size. Signature verification deferred.
  - **Done when:** Returns a plausible, monotonically increasing tree size against a live Let's Encrypt shard.

- [ ] **M1-05 · Static CT: tile fetch and decode** — *deps: M1-04*
  - **Do:** Build tile paths, fetch data tiles, split concatenated `TileLeaf` entries. Handle partial tiles and **never cache a partial tile as final**.
  - **Done when:** A known full tile yields exactly 256 entries; a partial tile yields its advertised width; a golden-file test pins the parse.

- [ ] **M1-06 · RFC 6962: `get-sth` and `get-entries`** — *deps: M1-03*
  - **Do:** Implement both. **Advance the cursor by `len(returned)`, never by the requested range** — logs silently return fewer entries than asked.
  - **Done when:** A test with a mocked short response asserts the cursor advances by the actual count.

- [ ] **M1-07 · Leaf decoder: `x509_entry`** — *deps: M1-05, M1-06*
  - **Do:** Decode `MerkleTreeLeaf` → `TimestampedEntry`, parse full certs with `cryptography`.
  - **Done when:** Golden-file test over ≥ 20 captured leaves extracts the expected SANs.

- [ ] **M1-08 · Leaf decoder: `precert_entry`** — *deps: M1-07*
  - **Do:** Handle `PreCert { issuer_key_hash, tbs_certificate }`. **`tbs_certificate` is a TBSCertificate — `load_der_x509_certificate` will raise.** Parse with `asn1crypto.x509.TbsCertificate`.
  - **Done when:** Golden-file test over ≥ 20 captured precert leaves extracts SANs; precerts are **not** filtered out.

- [ ] **M1-09 · `cert_key` computation** — *deps: M1-08*
  - **Do:** `sha256(issuer_der || serial)`, identical for a precert and its final certificate.
  - **Done when:** A captured precert/final pair produces the same `cert_key`. This is the dedup key and it must be right before any data is stored.

- [ ] **M1-10 · Name extraction and eTLD+1** — *deps: M1-08*
  - **Do:** SAN `dNSName` + hostname-shaped CN; dedupe within cert; lowercase; wildcard and IDN flags; eTLD+1 via `tldextract` with a **pinned PSL snapshot committed to the repo**.
  - **Done when:** Tests cover wildcard, punycode, `.com.sg`, `go.gov.sg`, the IDN ccTLDs, and a cert with 100+ SANs. No runtime PSL fetch.

- [ ] **M1-11 · Retry, backoff, circuit breaker** — *deps: M1-06*
  - **Do:** Exponential backoff on 429/403/5xx; per-log failure counter; skip after 3 consecutive failures in a run.
  - **Done when:** An injected 429 sequence shows backoff then skip, and the run completes rather than crashing.

- [ ] **M1-12 · ⚠️ RDAP feasibility spike** — *deps: M1-10*
  - **Do:** Query `rdap.sgnic.sg` for a known `.sg` domain and a gTLD domain via IANA bootstrap. Determine whether creation dates are exposed or redacted. Resolves `DESIGN.md` Q1.
  - **Done when:** Answer recorded in `DESIGN.md` §4.6. **If `.sg` is redacted, the `age:*` signals still ship for non-`.sg` hits and `registrables.first_seen` becomes the `.sg` fallback** — do not drop the feature, narrow it.

- [ ] **M1-13 · Volume measurement** — *deps: M1-10*
  - **Do:** Tail ≥ 50,000 entries across one tiled and one RFC 6962 log. Record entries/sec, `.sg` yield per log, distinct `.sg` registrables/day extrapolated, precert ratio. Resolves `DESIGN.md` Q3 and Q4 (log choice).
  - **Done when:** Real numbers replace every estimate in `DESIGN.md` §8. **If actual volume is >2× the estimate, revise the caps before M3.**

- [ ] **M1-14 · ⚠️ GATE: spike review** — *deps: M1-01…M1-13*
  - **Do:** Run `python -m ingester.tail --log <name> --limit 5000` against both APIs, printing names to stdout. Record the lag policy decision (Q2).
  - **Done when:** Both APIs produce correct names end to end, **and total M1 elapsed effort is ≤ 2 days.** If over, stop and close the repo per `PRD.md` §11.

---

## M2 — Normalisation, filtering, scoring

- [ ] **M2-01 · Watchlist loader and validation** — *deps: M1-14*
  - **Do:** Load `watchlist.json`, validate against schema, assert every brand has `max_edit_distance`, `known_tlds`, and context tokens where `require_context` is true.
  - **Done when:** A brand missing context tokens while `require_context:true` fails CI.

- [ ] **M2-02 · Allowlist loader and suppression** — *deps: M2-01*
  - **Do:** Allowlisted registrables are **dropped from `certs` entirely** but still counted in `registrables` and `issuance_daily`.
  - **Done when:** `dbs.com.sg` produces zero `certs` rows but does increment `issuance_daily`. A test asserts suppression runs before scoring.

- [ ] **M2-02b · ⚠️ RELEASE BLOCK: verify every allowlist entry** — *deps: M2-02*
  - **Do:** Verify each seed entry by navigating from the brand's official site or a regulator listing. **Do NOT verify by searching for the domain — that is how a typosquat gets confirmed as legitimate.** Set `verified:true` with date and source.
  - **Done when:** Zero entries have `verified:false`, and CI blocks the release workflow while any remain. A wrong allowlist entry silently suppresses a real threat — the most dangerous failure mode in the project.

- [ ] **M2-03 · Normalisation: punycode and NFKC** — *deps: M1-10*
  - **Do:** Decode `xn--` labels via `idna`; apply NFKC for fullwidth and compatibility forms.
  - **Done when:** `ｄｂｓ` and `xn--...` forms normalise to `dbs`. Sets `is_idn`.

- [ ] **M2-04 · Normalisation: confusable fold** — *deps: M2-03*
  - **Do:** UTS #39 confusable folding to an ASCII skeleton.
  - **Done when:** Cyrillic `а`, Greek `ο`, and `rn`→`m` cases fold to the expected skeleton. **`trսst` must match `trust` at distance 0.**

- [ ] **M2-05 · Normalisation: separators, leet, trailing noise** — *deps: M2-04*
  - **Do:** Strip `-`/`_`/`.`; generate leet **variants** (`0→o 1→l/i 3→e 4→a 5→s 8→b`); strip trailing years and `-sg`.
  - **Done when:** `d-b-s`, `db5`, `singpass2026` all reach their brand. **A test asserts the `m1` token is NOT folded to `ml`** — leet must generate variants, not replace.

- [ ] **M2-06 · Affix decomposition** — *deps: M2-05*
  - **Do:** Split undelimited tokens into brand+keyword or keyword+brand, using only `affix:true` keywords. Respect per-brand `allow_affix:false`.
  - **Done when:** `dbsbank` → `dbs`+`bank` and `singpasslogin` → `singpass`+`login`. `medica` does **not** decompose to `ica`, because `ica` has `allow_affix:false`.

- [ ] **M2-07 · Mixed-script detection** — *deps: M2-03*
  - **Do:** Detect a single label mixing scripts per UTS #39 restriction levels. Fires **independent of any brand match**.
  - **Done when:** A Latin+Cyrillic label fires `idn:mixed_script` even when it matches no watchlist brand.

- [ ] **M2-08 · Bounded edit-distance matcher** — *deps: M2-05*
  - **Do:** Damerau–Levenshtein bounded by each brand's `max_edit_distance`. Return the best single match only.
  - **Done when:** `dbs` at distance 0 does not reach `ubs`; `singpasss` matches `singpass` at distance 1; `dl1` and `dl2` never both fire.

- [ ] **M2-09 · Context requirement** — *deps: M2-08*
  - **Do:** When `require_context:true`, a brand hit only scores if a curated `context_tokens` entry also appears in the registrable.
  - **Done when:** `nus-login.sg` fires; `bonus-deals.sg` does not. Every `require_context` brand has a positive and a negative test.

- [ ] **M2-10 · Keyword and combosquat signals** — *deps: M2-06*
  - **Do:** `kw:*` at +10 capped at +25; `combo:brand+kw` at +25.
  - **Done when:** Cap is enforced; `secure-login-verify-account.sg` cannot outscore an actual brand lookalike.

- [ ] **M2-11 · Scheme signals** — *deps: M2-05*
  - **Do:** Match `schemes.json` tokens at +45, plus +15 inside an active window.
  - **Done when:** `cdcvoucher-claim.top` scores in the Notable band on the scheme signal alone.

- [ ] **M2-12 · Shape, TLD and issuer signals** — *deps: M2-08*
  - **Do:** `tld:mismatch`, `shape:hyphens`, `shape:depth`, `idn:punycode`, `issuer:free_dv`.
  - **Done when:** Each has a unit test; `issuer:free_dv` sits behind a config flag so M5 can delete it cheaply.

- [ ] **M2-13 · RDAP client and age signals** — *deps: M1-12, M2-08*
  - **Do:** IANA bootstrap, per-server rate limit and daily cap, permanent cache keyed by registrable. `age:very_new` +25, `age:new` +15, `age:established` −10. Lookups only for hits ≥ 30.
  - **Done when:** A 200-lookup run stays inside the rate limit and re-runs hit cache with zero network calls. **No request ever goes to the suspect domain** — asserted by a test that fails if any non-registry host is contacted.

- [ ] **M2-14 · Score composition and `reasons`** — *deps: M2-09…M2-13*
  - **Do:** Additive, clamped 0–100, stable `reasons` strings, band labels per `DESIGN.md` §4.4.
  - **Done when:** Scoring is a pure function with no I/O; a snapshot test pins 40 fixture domains to exact scores and reasons.

- [ ] **M2-15 · Calibration harness** — *deps: M2-14*
  - **Do:** `scripts/calibrate.py` — sample N hits **stratified across `.sg` and `.com.sg`**, emit a shuffled CSV with scores hidden, accept a verdict column, compute precision per band.
  - **Done when:** Running on synthetic data produces a precision table. This is the instrument for M5-02.

---

## M3 — Storage and API

- [ ] **M3-01 · D1 database and migration runner** — *deps: M1-14*
  - **Do:** Create the D1 database; numbered SQL migrations in `worker/migrations/`, applied via Wrangler.
  - **Done when:** `wrangler d1 migrations apply` runs clean locally and remotely.

- [ ] **M3-02 · Schema v1** — *deps: M3-01*
  - **Do:** Implement `DESIGN.md` §5.2 exactly — all five tables, **including `UNIQUE(cert_key, domain)` and `registrables.issuers_seen` from the first migration.** Retrofitting either later is painful.
  - **Done when:** All tables and indexes exist; a duplicate `certs` insert is rejected by the unique index.

- [ ] **M3-03 · Worker scaffold** — *deps: M3-01*
  - **Do:** `worker/` with Wrangler, TypeScript, D1 binding, router, deployed to a workers.dev subdomain.
  - **Done when:** `GET /api/health` returns 200 from the deployed Worker.

- [ ] **M3-04 · HMAC auth middleware** — *deps: M3-03*
  - **Do:** Verify `X-Signature` over `timestamp || body` with WebCrypto; reject timestamps older than 5 minutes.
  - **Done when:** Valid passes; tampered body, wrong secret, and stale timestamp each return 401.

- [ ] **M3-05 · `POST /ingest`: registrables upsert** — *deps: M3-04, M3-02*
  - **Do:** Upsert `registrables`, merging `issuers_seen` as a set, advancing `last_seen`, incrementing `cert_count`, keeping `max_score`. **Never overwrite `first_seen` or `first_issuer`.**
  - **Done when:** Re-ingesting the same registrable preserves `first_seen` and grows `issuers_seen`. A test asserts issuer history accumulates — this is what makes M7-06 possible in 2027.

- [ ] **M3-06 · `POST /ingest`: certs and daily counters** — *deps: M3-05*
  - **Do:** Multi-row `INSERT … ON CONFLICT DO NOTHING` for `certs` at **9 rows per statement** (100-param ceiling), **≤400 rows per request** total (50-query ceiling). Increment `issuance_daily`.
  - **Done when:** A 400-row batch completes in one invocation without hitting query or parameter limits; a re-POST inserts 0 and reports them deduped.

- [ ] **M3-07 · Measure `D1.batch()` accounting** — *deps: M3-06*
  - **Do:** Use the `meta` object to determine whether `batch()` counts as 1 query or N against the 50-per-invocation ceiling. Resolves `DESIGN.md` Q4.
  - **Done when:** Finding recorded in `DESIGN.md`; the 400-row cap adjusted up or confirmed.

- [ ] **M3-08 · Daily write-budget guards** — *deps: M3-06*
  - **Do:** Track per-UTC-day writes; caps of 8,000 `certs` and 10,000 `registrables`; return 429 with `Retry-After` past either; record `capped` in `ingest_runs`.
  - **Done when:** Exceeding a cap returns 429 and marks the run `capped` rather than failing.

- [ ] **M3-09 · `GET /api/state` and checkpoint writes** — *deps: M3-03*
  - **Do:** Read checkpoints; update `log_state` on ingest. **Advance `log_state` even when a cap trips**, so tomorrow doesn't re-scan today.
  - **Done when:** A capped run still advances `last_index`; a test asserts it.

- [ ] **M3-10 · `GET /api/recent`** — *deps: M3-02*
  - **Do:** `limit`, `min_score`, `cursor` on `seen_at`. **Keyset, not offset.**
  - **Done when:** Paging 500 rows never repeats or skips; `meta.rows_read` stays proportional to `limit`.

- [ ] **M3-11 · `GET /api/first-seen`** — *deps: M3-05*
  - **Do:** `.sg` registrables first observed in a given day, from `idx_reg_first`. This is the all-issuance browse view.
  - **Done when:** Returns today's new `.sg` names; reads stay proportional to `limit`.

- [ ] **M3-12 · `GET /api/search`, index-shaped** — *deps: M3-02*
  - **Do:** Prefix and exact match only. **Reject `%`-leading patterns** with a 400 and a "prefix search only" hint.
  - **Done when:** A prefix query's `rows_read` is bounded by result count, not table size.

- [ ] **M3-13 · Response caching** — *deps: M3-10*
  - **Do:** `Cache-Control: public, max-age=30, stale-while-revalidate=60` plus the Worker Cache API on all read endpoints.
  - **Done when:** Two identical requests within 30 s produce exactly one D1 query. **Without this the free tier does not hold.**

- [ ] **M3-14 · Wire the Actions cron** — *deps: M3-06, M3-09, M2-14*
  - **Do:** `*/10` scheduled workflow: read state → fetch → decode → normalise → score → RDAP → POST. Secret from Actions secrets. **Never `set -x` in the ingest step.**
  - **Done when:** Three consecutive scheduled runs complete, rows land in all three tables, and no secret appears in the logs.

---

## M4 — Dashboard (P0)

- [ ] **M4-01 · Frontend scaffold** — *deps: M3-03*
  - **Do:** Vite + React + TypeScript + Tailwind, deployed static to Vercel.
  - **Done when:** Placeholder page live on a Vercel URL.

- [ ] **M4-02 · API client and generated types** — *deps: M4-01, M3-10*
  - **Do:** Typed fetch client with types derived from Worker response shapes, not hand-copied.
  - **Done when:** Changing a Worker response field breaks the frontend build.

- [ ] **M4-03 · Scored-hits table** — *deps: M4-02*
  - **Do:** Columns: time, domain, registrable, score badge, issuer, log. Keyset "load more".
  - **Done when:** Renders live data and pages without duplicates.

- [ ] **M4-04 · Score badge and copy lint** — *deps: M4-03*
  - **Do:** Render *Informational* / *Possible lookalike* / *Notable lookalike*. Add a test that **fails the build** if `phishing`, `malicious`, `fraudulent`, `scam`, or `fake` appear in UI strings.
  - **Done when:** The lint fails on a deliberately added banned word. Implements `PRD.md` §8.1.

- [ ] **M4-05 · "First seen today" view** — *deps: M3-11*
  - **Do:** Separate tab listing new `.sg` registrables, with suffix filter. **Kept distinct from the scored-hits view** so signal doesn't drown in routine renewals.
  - **Done when:** Both views are independently reachable and neither is the default-hidden one.

- [ ] **M4-06 · Reasons rendering** — *deps: M4-03*
  - **Do:** Render `reasons` as human-readable chips ("1 character from dbs", "registered 4 days ago").
  - **Done when:** Every signal in `DESIGN.md` §4.3 has a chip label; an unknown reason string degrades gracefully rather than crashing.

- [ ] **M4-07 · Search UI** — *deps: M4-02, M3-12*
  - **Do:** Search box wired to prefix search, with inline copy stating the prefix-only limitation.
  - **Done when:** `dbs` returns hits; a substring attempt shows the hint, not an error toast.

- [ ] **M4-08 · Score and issuer filters** — *deps: M4-03*
  - **Do:** Minimum-score slider and issuer filter, reflected in the URL query string.
  - **Done when:** A filtered URL is shareable and restores state on load.

- [ ] **M4-09 · Polling with visibility pause** — *deps: M4-03*
  - **Do:** Poll every 30 s; **pause on `visibilitychange`**; resume on focus.
  - **Done when:** A backgrounded tab issues zero requests, verified in the network panel.

- [ ] **M4-10 · Status strip** — *deps: M4-02, M3-03*
  - **Do:** Per-log lag and last successful run from `/api/health`. Clear stale banner if any log lags > 60 min.
  - **Done when:** Pausing the cron makes the banner appear within one poll cycle.

- [ ] **M4-11 · Empty, loading, error states** — *deps: M4-03*
  - **Do:** Skeleton rows, a real empty state, an error state with retry.
  - **Done when:** All three are reachable under forced conditions and none is a blank screen.

- [ ] **M4-12 · Methodology page** — *deps: M4-04*
  - **Do:** Explain every scoring signal; state that a high score means "matches a pattern, not proven malicious"; **link `BLINDSPOTS.md` and quote the scope line from `PRD.md` §9 verbatim**; document the issue-template correction route and its turnaround.
  - **Done when:** Live, linked from every score badge, and the blind-spots link is above the fold.

---

## M5 — Launch and calibration ⚠️ KILL GATE

- [ ] **M5-01 · 7-day unattended soak** — *deps: M3-14, M4-10*
  - **Do:** Run 7 days with no commits and no manual re-runs. Record every gap.
  - **Done when:** No gap over 60 minutes in `ingest_runs`. Satisfies S1.

- [ ] **M5-02 · ⚠️ GATE: 50-hit precision review** — *deps: M5-01, M2-15*
  - **Do:** Run the harness on the 50 highest-scored hits, stratified by suffix. Blind review against a written rubric. Commit results **including misses** to `docs/calibration/`.
  - **Done when:** **≥60% plausibly suspicious → proceed to M6.** 40–59% → one tuning pass, then re-review. **<40% after tuning → stop per `PRD.md` §11.**

- [ ] **M5-03 · Per-brand precision breakdown** — *deps: M5-02*
  - **Do:** Compute precision per brand. Expect `trust`, `income`, `mom` and `carousell` to be the worst.
  - **Done when:** Any brand under 20% precision is either retuned, moved to `require_context`, or removed — decision recorded in `watchlist.json` notes.

- [ ] **M5-04 · Delete or defend `issuer:free_dv`** — *deps: M5-02*
  - **Do:** Check whether it improved precision. It penalises Let's Encrypt users, who are mostly legitimate. Resolves `DESIGN.md` Q7.
  - **Done when:** Removed, or its contribution documented with numbers.

- [ ] **M5-05 · Latency measurement** — *deps: M5-01*
  - **Do:** Measure p50 from log-entry availability to dashboard visibility (**not** from `not_before`).
  - **Done when:** p50 over 7 days recorded; target < 15 min per S2.

- [ ] **M5-06 · Dynamic retention pruner** — *deps: M3-08*
  - **Do:** Scheduled prune: while DB size > 400 MB, delete oldest `certs` rows in capped batches. **Never prune `registrables` or `issuance_daily`.** Skip if remaining write budget < 25,000.
  - **Done when:** A dry run reports rows-to-delete and write cost; a live run stays inside budget. Implements `PRD.md` C4 — coverage wins, history gives.

- [ ] **M5-07 · Storage alarm** — *deps: M3-01*
  - **Do:** Daily check failing CI at 450 MB.
  - **Done when:** Runs daily and fails against a simulated 450 MB reading.

- [ ] **M5-08 · Keepalive workflow** — *deps: M3-14*
  - **Do:** Monthly no-op commit so Actions doesn't auto-disable scheduled workflows after 60 days.
  - **Done when:** Scheduled monthly and has run once successfully.

- [ ] **M5-09 · README, `robots.txt`, correction template, P0 release** — *deps: M5-02*
  - **Do:** README with the honest framing from `PRD.md` §2 including "this technique is not novel". Issue template for correction requests. `robots.txt` discouraging bulk crawling. Tag `v0.1.0`.
  - **Done when:** Presentable to a stranger, live on the custom domain, tag pushed.

---

## M6 — P1

- [ ] **M6-01 · `GET /api/stats` from `issuance_daily`** — *deps: M5-09*
  - **Do:** Issuance timeline, issuer breakdown, score distribution over a window. Reads rollups, **never scans `certs`**.
  - **Done when:** Chart queries read < 1,000 rows regardless of table size.

- [ ] **M6-02 · Issuance timeline chart** — *deps: M6-01*
  - **Do:** Observable Plot, `.sg` certs per day stacked by suffix. The domain-nerd headline.
  - **Done when:** Renders 90 days without visible jank.

- [ ] **M6-03 · Issuer breakdown chart** — *deps: M6-01*
  - **Do:** Which CA is signing what — usually one or two dominate.
  - **Done when:** Renders and is filterable into the tables.

- [ ] **M6-04 · Score distribution chart** — *deps: M6-01*
  - **Do:** Histogram with band boundaries marked. Completes G4.
  - **Done when:** Renders and band edges are visually clear.

- [ ] **M6-05 · Hits-per-hour chart** — *deps: M6-01*
  - **Do:** Scored hits per hour stacked by category.
  - **Done when:** Renders 7 days.

- [ ] **M6-06 · Precert/final reconciliation** — *deps: M3-02*
  - **Do:** When a final cert supersedes a precert with the same `cert_key`, update rather than insert.
  - **Done when:** A precert followed by its final cert yields exactly one row with `flags` updated.

- [ ] **M6-07 · `GET /api/domain/{name}`** — *deps: M3-02*
  - **Do:** All certs for a name, first-seen from `registrables`, SAN siblings, issuer history.
  - **Done when:** Correct for a name with multiple certs; reads use `idx_creg`.

- [ ] **M6-08 · Domain detail page** — *deps: M6-07*
  - **Do:** Per-domain page with cert history, first-seen, siblings.
  - **Done when:** Linked from every table row; deep-linkable.

- [ ] **M6-09 · JSON feed** — *deps: M3-10*
  - **Do:** `GET /api/feed.json`, JSON Feed 1.1, top N by score in the last 24 h.
  - **Done when:** Validates against the JSON Feed spec.

- [ ] **M6-10 · RSS feed** — *deps: M6-09*
  - **Do:** `GET /api/feed.xml`. Satisfies "subscribe without accounts".
  - **Done when:** Validates and loads in a real reader.

- [ ] **M6-11 · FTS5 spike** — *deps: M3-12*
  - **Do:** Determine whether D1 supports FTS5. Resolves `DESIGN.md` Q5. If yes, add substring search behind the existing endpoint; if no, close it out and keep the documented limitation.
  - **Done when:** Answer recorded in `DESIGN.md` either way.

- [ ] **M6-12 · CJK confusable research** — *deps: M5-02*
  - **Do:** Investigate simplified/traditional folding (OpenCC-style) and hanzi visual-similarity tables. **UTS #39 skeleton folding does essentially nothing for hanzi** — this is a separate problem, and edit distance is differently calibrated when one changed character out of four is a 25% edit.
  - **Done when:** A written finding in `docs/research/cjk.md` with a go/no-go. **No CJK brand tokens ship before this** — see `PRD.md` §7.

- [ ] **M6-13 · CJK brand tokens (conditional)** — *deps: M6-12*
  - **Do:** Only if M6-12 says go. Add Chinese brand tokens with their own calibration run.
  - **Done when:** A separate 50-hit calibration on CJK hits clears 60%, or the task is closed as declined.

---

## M7 — P2

- [ ] **M7-01 · Registrable clustering** — *deps: M6-07*
  - **Do:** Group `a.evil.sg` and `b.evil.sg` under one registrable in the UI.
  - **Done when:** Clustered rows collapse with an expandable count.

- [ ] **M7-02 · SAN-sibling clustering** — *deps: M7-01*
  - **Do:** Surface names sharing a certificate as one cluster.
  - **Done when:** A 50-SAN cert renders as one entry, not 50 rows.

- [ ] **M7-03 · Wildcard handling** — *deps: M7-02*
  - **Do:** Distinct treatment and display for `*.` names. **Link to `BLINDSPOTS.md` §2.1** — wildcards are the mechanism by which platform abuse hides.
  - **Done when:** Wildcards are visually distinguished and filterable.

- [ ] **M7-04 · crt.sh backfill** — *deps: M6-07*
  - **Do:** On-demand historical lookup for a searched name. **Rate-limited and cached — it's someone else's infrastructure.**
  - **Done when:** Capped per hour, cached, failures degrade gracefully.

- [ ] **M7-05 · Saved searches** — *deps: M6-07*
  - **Do:** URL-encoded, no accounts.
  - **Done when:** A saved search is a shareable URL restoring full state.

- [ ] **M7-06 · Issuer-change signal** — *deps: M3-05*
  - **Do:** **Do not start before twelve months of `registrables` history exists.** Flag a registrable whose new certificate comes from a CA absent from `issuers_seen`. Low weight only.
  - **Done when:** Signal exists, is weighted ≤ 10, and a calibration run shows it doesn't degrade overall precision. Read `BLINDSPOTS.md` §4 first — the Isolation Forest result is the trap this task walks toward.

- [ ] **M7-07 · Webhook alerts** — *deps: M7-05*
  - **Do:** Fire on new hits matching a saved search. **User-supplied endpoint only — no outbound mail to third parties (N1).**
  - **Done when:** Fires with retry and backoff; failures don't block ingestion.

- [ ] **M7-08 · Email alerts** — *deps: M7-07*
  - **Do:** Opt-in, double-opt-in, one-click unsubscribe.
  - **Done when:** Subscribe → confirm → receive → unsubscribe works end to end. **Re-read N1 before starting.**

- [ ] **M7-09 · Public read API with documented limits** — *deps: M3-13*
  - **Do:** Document endpoints, publish rate limits, add per-IP throttling.
  - **Done when:** Docs live; a load test confirms the throttle holds.

- [ ] **M7-10 · Watchlist contribution flow** — *deps: M0-06*
  - **Do:** Issue template plus CI-validated PR path for brands and allowlist entries. Contributors must cite which of the four inclusion criteria the brand meets.
  - **Done when:** A schema-invalid or criteria-free contribution fails CI with a useful message.

- [ ] **M7-11 · Partitioned tables spike** — *deps: M5-06*
  - **Do:** Evaluate monthly `certs` tables + `DROP TABLE` instead of `DELETE` pruning — would eliminate ~7,500 rows written/day. Adopt only if prune writes have become binding.
  - **Done when:** Decision and reasoning recorded in `DESIGN.md` §12.

---

## M8 — Ongoing ops (continuous)

- [ ] **M8-01 · Weekly log-list diff review** — *deps: M1-01*
  - **Do:** Refresh job opens a PR when the cached log list changes; review the diff. Watch for logs migrating from `logs[]` to `tiled_logs[]`.
  - **Done when:** Runs weekly and opens a PR on change rather than auto-merging.

- [ ] **M8-02 · Monthly free-tier audit** — *deps: M5-09*
  - **Do:** Record D1 rows read/written, storage, Worker requests. Satisfies S4.
  - **Done when:** Twelve months of readings committed to `docs/ops/`.

- [ ] **M8-03 · Quarterly recalibration** — *deps: M2-15*
  - **Do:** Re-run the 50-hit review. **Kill criteria still apply after launch.**
  - **Done when:** Each quarter's result committed to `docs/calibration/`, misses included.

- [ ] **M8-04 · Quarterly schemes refresh** — *deps: M0-06*
  - **Do:** Review `schemes.json` against Budget announcements and current advisories. Schemes are time-bound; a stale file quietly stops earning its weight.
  - **Done when:** Reviewed each quarter, with additions verified against official spellings before merge.

- [ ] **M8-05 · Allowlist maintenance** — *deps: M2-02b*
  - **Do:** Add legitimate domains as they false-positive. **The `carousell`/`carousel` collision is permanent and accepted** — expect recurring additions there.
  - **Done when:** Turnaround on correction requests meets the stated commitment, and additions from requests are logged visibly in `allowlist.json`.

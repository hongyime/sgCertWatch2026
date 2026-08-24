# Instruction Set B1 — sgCertWatch2026

Supersedes the open questions at the end of your last report. Read `.agents/STATE.md`
and `.agents/JOURNAL.md` first. Work the batches in order. **Stop at each STOP gate and
report before continuing.** Do not run batches back-to-back — that failure is what
produced commits 15–19.

---

## Standing corrections to your report

Two things you did not catch. Both change the priority order:

1. **`api/enrich.js` has never executed.** It does
   `import { normalizeHost } from "../lib/domain/registrable.js"`, and that module
   exports only `normaliseName`, `registrableDomain`, `subdomainLabels`. A named ESM
   import that does not resolve is a link-time error, so the function 500s on module
   load. The "Probe Domain" button has been dead since commit `e161700`. This is good
   news — DECISION-04 was violated in code but never in traffic. It also means:
   **if the uncommitted WIP adds a `normalizeHost` export to `registrable.js`, committing
   it silently arms an unauthenticated outbound-probe endpoint.** Treat that as the
   highest-severity item in the WIP, above the PSL bypass.

2. **There is no `.vercelignore`.** `corpus.json` (41 MB) and
   `fixtures/corpus/unfiltered_negatives.jsonl` (32 MB) are deployed as public static
   assets and are fetchable from the production origin. ~75 MB of eval data, publicly
   downloadable, on a 100 GB/month transfer allowance.

---

## Ruling on your three questions

**1. WIP disposition — keep the perf work, delete `FLAT_GTLDS` entirely.**

Not "make it safer." Delete it. The premise is wrong: it is not a fast path to the same
answer, it is a different and incorrect answer. `blogspot.com`, `pages.dev`, `web.app`,
`workers.dev`, and `herokuapp.com` are all in the PSL *private* section, so `psl.get()`
already returns the per-tenant registrable:

```
psl.get("dbs-secure.blogspot.com")    -> "dbs-secure.blogspot.com"
psl.get("singpass-verify.pages.dev")  -> "singpass-verify.pages.dev"
psl.get("ocbc-login.web.app")         -> "ocbc-login.web.app"
```

The bypass collapses those to the platform suffix, which lands on the allowlist path and
suppresses the finding. Free-hosting subdomains are a primary SG phishing channel; this
would have made the monitor blind to that entire class while reporting green.

**2. Commits 15–19 — de-scope forward, do not rewrite history.**

No `git revert` of `e161700`, `926c819`, `8d5a85b`, `1fb91df`, `e6faa68`. The repo is
public, `JOURNAL.md` cites those SHAs, and the drift is part of the record. Instead: one
explicit de-scope commit that removes the out-of-spec surface area, then reimplement
15–19 against spec. Append a dated JOURNAL line stating that 15–19 were implemented as
different work and are superseded by 15R–19R. Do not edit the existing JOURNAL entries.

**3. Alerts/day — yes, it blocks everything, and it is not a weights problem.**

1,907 brand-none false positives at threshold 70 is a structural defect, not a tuning
one. Signals added in commits 13–14 can independently reach the alert threshold with no
brand or scheme anchor present: `kw` cap 25 + `tld_high_risk` 12 + `issuer_free_dv` 8 +
`cert_age_under_1h` 10 + `domain_age_under_7d` 20 = 75. Every freshly issued Let's
Encrypt certificate on a cheap TLD clears the bar. Fix the gate, not the numbers.

---

## Batch A — stop the Vercel bleed (do this first, nothing else runs until it lands)

The project is paused for exceeding the Hobby Fluid Active CPU allowance (4 CPU-hours
per 30 days). Measured cost of `scoreCertificate` on this codebase is **7.3 ms of active
CPU per certificate**, which puts the entire monthly allowance at ~1.98M certificates —
about 6,600/hour. `CERTSTREAM_MAX_MESSAGES` alone is 2,500 per run at 288 runs/day.
The ingest loop cannot fit on Vercel Hobby at any level of optimisation, because Active
CPU billing prices exactly the CPU-bound work this pipeline is made of.

DECISION-04 already said capture belongs in GitHub Actions. Extend that: **all ingest and
scoring moves to GitHub Actions.** Standard runners are free and unlimited on public
repos, and this repo is public.

A1. **Before anything is unpaused**, disable the Supabase `pg_cron` job
    `sgcertwatch-ct-poll`. If Vercel is unpaused with that scheduler live, it re-pauses
    within the hour. Report the job state back before proceeding.

A2. Add `.vercelignore` excluding `corpus.json`, `fixtures/`, `scripts/`, `.agents/`,
    `eval_baseline.json`, and `supabase/`. Verify the deployed asset list afterwards.

A3. Add `.github/workflows/ingest.yml`: `schedule` every 15 minutes plus
    `workflow_dispatch`, `concurrency` group with `cancel-in-progress: false`, and a
    hard `timeout-minutes`. It runs the orchestrator directly against Supabase using
    repo secrets — no HTTP hop through Vercel. Cursors stay in `ingest_state`, so a
    delayed or skipped run catches up on the next tick.

A4. Delete `api/cron/ct-poll.js`, `api/cron/daily-digest.js`, and `api/enrich.js`.
    Vercel keeps exactly three functions: `api/findings.js`, `api/source-status.js`, and
    nothing else. Both are Supabase reads with negligible CPU. Add
    `"maxDuration": 10` for them in `vercel.json` and remove the 60s entry.

A5. Remove `CRON_SECRET`, `TELEGRAM_*`, `DISCORD_WEBHOOK_URL`, `ALERT_WEBHOOK_*`, and
    `SUPABASE_SERVICE_ROLE_KEY` from the Vercel project. The dashboard functions need
    `SUPABASE_URL` and `SUPABASE_ANON_KEY` only. Move the alerting secrets to GitHub
    Actions secrets. Rotate the service role key during the move — STATE.md line
    "rotate the Supabase keys because secrets were pasted into chat during setup" is
    still open from 2026-08-14.

**STOP.** Report: pg_cron state, deployed asset list, remaining Vercel functions and
env vars, and the first green Actions ingest run. Do not start Batch B.

---

## Batch B — precision gate

B1. Introduce a required anchor in `lib/scoring.js`. A finding may only score at or above
    the alert threshold if at least one anchor signal is present: `brand:exact`,
    `brand:fuzzy`, `subdomain_brand_squat`, `scheme`, `punycode_brand_match`,
    `confusable_skeleton_match`, or `homoglyph:ascii`. With no anchor, cap the total
    below threshold rather than dropping the finding — keep it visible in the dashboard
    at reduced severity. Express this in `scoring.json` (bump to v3) as an explicit
    `anchor_signals` list plus `no_anchor_score_cap`; do not hardcode it.

B2. Re-run `scripts/eval.js`. Acceptance is now **absolute, not relative to baseline**:
    alerts/day ≤ 50 at threshold 70, and no loss of true positives from the 165-item
    positive set. Report the confusion matrix and the alerts/day figure. If TP drops,
    stop and report — do not compensate by moving weights.

B3. Replace the regression gate in `scripts/eval.js` so it fails on absolute floors
    (alerts/day ≤ 50, adversarial ≥ 48/60) rather than tolerance against
    `eval_baseline.json`. The current gate passes because it measures against a weak
    baseline; that is how 37/60 shipped.

**STOP.** Report metrics before touching detection.

---

## Batch C — WIP and detection

C1. From the uncommitted WIP: keep the perf changes, drop `FLAT_GTLDS` and any
    `normalizeHost` export added to `registrable.js`. Commit as `perf:`, separately from
    anything else. Confirm `scripts/test_registrable.js` still asserts the free-hosting
    cases; if it does not, add them.

C2. Optimise the scoring hot path. The 7.3 ms/cert figure comes from expanding the
    unbounded side of the problem: `lib/scoring.js:377-385` runs
    `labels x asciiHomoglyphs(label) x 73 brands x tokens` per observed domain, and
    `minSubstringEditDistance` slides a full Damerau-Levenshtein window per pair.
    Invert it — precompute the homoglyph and skeleton expansions of the 73 brand tokens
    once at module load into a lookup structure, then gate every observed domain through
    a cheap membership check before any edit-distance work runs. Expand the fixed set,
    not the stream. Target ≤ 0.3 ms/cert with identical eval output; report both numbers.

C3. Address the 23 punycode/homoglyph misses scoring 0–65 in the adversarial suite.
    Report the failure classes first — do not start editing weights until the classes
    are named.

**STOP.**

---

## Batch D — reimplement 15–19 to spec

Only after A, B, and C are green. Order and content per spec v6: 15R capture in Actions
with Playwright; 16R Telegram-only plus 72h registrable dedupe via `alert_log`;
17R `api/triage.js` with `TRIAGE_TOKEN` and the FP → `pending_verification` flow;
18R allowlist source tiers, Tier-3 purge, verify tooling; 19R defang, CSP/HSTS,
`robots.txt`, disclaimer, and the `app.js:233` href fix — `escapeHtml` does not stop a
`javascript:` URL, so validate the scheme and add `rel="noopener noreferrer"`.

Note that 17R's triage endpoint is now the only remaining case for a write-capable Vercel
function. Keep it POST-only behind `TRIAGE_TOKEN`, writing to Supabase, with no outbound
network calls of any kind.

---

## Rules for this session

- One batch at a time. Report at every STOP.
- No commit may contain both a perf change and a behaviour change.
- If a spec item cannot be implemented as written, stop and say so. Do not substitute
  adjacent work and mark the slot complete — that is precisely what happened in 15–19.
- Update `.agents/STATE.md` after each step; append one dated line per durable decision
  to `.agents/JOURNAL.md`.

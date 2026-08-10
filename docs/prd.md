# sgCertWatch2026 — Product Requirements

| | |
|---|---|
| **Repo** | `hongyime/sgCertWatch2026` |
| **Status** | Proposed — not started |
| **Owner** | hongyime |
| **Licence** | MIT |
| **Revision** | rev 5 |
| **Last updated** | 2026-08-10 |
| **Companion docs** | [`DESIGN.md`](./DESIGN.md) · [`TASKS.md`](./TASKS.md) · [`BLINDSPOTS.md`](./BLINDSPOTS.md) |

**One-liner:** Watches the Certificate Transparency firehose and surfaces every new `.sg` domain and every lookalike of a Singapore brand, minutes after the cert is issued.

### Changelog

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-08 | Initial concept. Claimed novelty. |
| 2 | 2026-08 | Renamed from `certcat`. |
| 3 | 2026-08-08 | Ran the "does this already exist" gate. Novelty claim withdrawn — see §2. |
| 4 | 2026-08-09 | Split into PRD / DESIGN / TASKS. Corrected the CT-ecosystem assumption — the RFC 6962-only design in rev 3 would have missed Let's Encrypt entirely. |
| 5 | 2026-08-10 | Scope now covers **all `.sg` issuance**, not only scored hits (§7). Added domain-age enrichment via RDAP and `BLINDSPOTS.md` (§9). All rev 4 open questions resolved. Retention policy set (§6, C4). Non-goal N2 clarified to permit registry lookups. |

---

## 1. Summary

Every TLS certificate issued by a publicly trusted CA is published to Certificate Transparency logs. That is a real-time, free, global feed of *who just stood up a new domain*. Phishing infrastructure shows up there before it shows up anywhere else — a `dbs-secure-login.sg` cert appears in CT hours before the first victim clicks it.

Nobody runs a good Singapore-focused CT monitor. sgCertWatch2026 is that: an ingester that tails CT logs, tracks every `.sg` certificate issued, scores names against a Singapore brand watchlist for typosquat likelihood, and presents both as a live public dashboard.

It sits squarely on cyber + dataviz, and it is the project most likely to be genuinely useful to someone other than me.

---

## 2. Why this — and the honesty gate

This section exists so that future-me cannot quietly re-inflate the pitch. Read it before starting and again before giving up.

### 2.1 What already exists

The *technique* is thoroughly solved. `certstream`, `phishing_catcher`, `streamingphish` and `CertStreamMonitor` are mature open-source CT-phishing tools. Commercial SG brand-protection vendors already watch CT for local brands and sell it as a service. Certificate search sites like crt.sh and Cert Spotter have existed for a decade. There is at least one actively maintained streaming server that already handles both CT APIs correctly in a single binary.

**sgCertWatch2026 is not novel as a method. Do not build it believing it is.**

### 2.2 What doesn't exist

A **free, public, SG-focused CT dashboard**. The general tools are libraries you self-host and point at your own brand — not a hosted observatory of `.sg` issuance that anyone can open in a browser with no signup.

The value proposition is **convenient, local, and public**, not *novel*. That is a real win but narrower than rev 1 implied. This is not the highest-ceiling project in the pile; it is a well-scoped useful thing built on a solved technique.

### 2.3 The honest reasons to build it anyway

- I forked `matkap` (`theprawnhunter`) and wrote `networkScan2020`, `searchIG2020`, `emailverification`. The recon instinct is already there — this points it at something with defensive rather than offensive value.
- CT log data is free, public **by design**, and effectively infinite. No API keys, no scraping-ethics problem, no rate-limit roulette, no terms-of-service grey zone.
- It is a genuine streaming-data visualisation problem, which is the thing my portfolio lacks.
- The differentiator is packaging plus **SG-specific tuning that nobody outside Singapore would build** — see §2.5.

### 2.4 One narrow, time-limited edge (do not oversell this)

The CT ecosystem is mid-migration from the RFC 6962 API to the newer Static CT API ("tiled" logs). Let's Encrypt made its RFC 6962 logs read-only on 2025-11-30 and shut them down entirely on **2026-02-28** — it now writes only to tiled logs.

A large amount of copy-paste CT monitoring tooling still speaks RFC 6962 only, and has been quietly blind to the highest-volume issuer of free DV certificates since February 2026. **Rev 3 of this document had that same bug baked into its architecture.**

A dual-API ingester is a correctness requirement and worth one honest paragraph in the README. It is **not** a novelty claim — actively maintained tools have migrated. This edge closes as the ecosystem finishes moving.

### 2.5 The part that is actually locally specific

Three things here would not exist in a generic CT monitor, and they are where the real value sits:

- **Per-brand match tuning for SG's acronym problem.** A disproportionate share of high-value SG targets have tokens that are short (`dbs`, `cpf`, `nus`) or dictionary words (`trust`, `income`, `grab`, `scoot`). Getting these right is the difference between 60% precision and 20%, and it needs local knowledge, not a better algorithm.
- **Government scheme lures.** `cdcvoucher`, `gstvoucher`, `assurancepackage` — phished hard around every disbursement cycle, near-zero false-positive rate, invisible to anyone not living here.
- **`go.gov.sg`.** Singapore has an official government link shortener built specifically to counter phishing, and CSA advisories train citizens to treat the `gov.sg` suffix as *the* legitimacy check. That makes prefix-position squats maximally effective against people following official advice correctly.

---

## 3. Users and use cases

| User | Use case | What they need |
|---|---|---|
| SG security practitioners | "Anything impersonating a local bank overnight?" | High-signal top-of-list, sortable by score, timestamps |
| Brand and domain owners | Search their own name, see lookalikes | Reliable search, per-domain history, a pollable feed |
| Domain and PKI nerds | "How many `.sg` domains got certs this week, from which CA?" | Complete issuance stats, first-seen list, issuer breakdown |
| Me | A live thing on my domain demonstrating PKI, streaming, and scale | It stays up without babysitting |

**Explicit non-user:** anyone looking for a target list of newly registered domains to attack. See §8.

---

## 4. Goals

| ID | Goal |
|---|---|
| G1 | Ingest CT log entries continuously and durably, across **both** the RFC 6962 and Static CT APIs. |
| G2 | Track **every** `.sg` certificate observed — any public suffix ending in `.sg`, including the IDN ccTLDs — plus a configurable brand watchlist across all TLDs. |
| G3 | Score watchlist hits: normalisation-first (homoglyph, punycode, fullwidth, leet, affix), then bounded edit distance, keyword tokens, scheme tokens, and domain age. |
| G4 | Live dashboard: streaming table, first-seen list, issuance timeline, issuer breakdown, score distribution, search. |
| G5 | Stay inside free tiers under sustained load, indefinitely. |
| G6 | Present every score as a **heuristic signal, never a verdict**. |
| G7 | State plainly what the system cannot see (`BLINDSPOTS.md`). |

---

## 5. Non-goals

| ID | Non-goal | Why |
|---|---|---|
| **N1** | **Not a takedown service.** Surface and rank; do not auto-report, do not contact registrars, do not email anyone. | Automated abuse reporting on a heuristic score generates false accusations against legitimate businesses. |
| N2 | **No active probing** of discovered domains. No HTTP fetch, no port scan, no DNS query against their nameservers, no screenshotting. | Passive observatory. **Clarification:** RDAP lookups against a *registry* are permitted — zero packets reach the suspect domain and nothing is observable by its operator. Contacting the registry is not contacting the target. |
| N3 | Not attempting full CT coverage. | Dozens of logs, millions of certs/day. A deliberate subset is the honest scope. |
| N4 | No accounts, no alerting-as-a-service in v1. | Auth and delivery are their own product. |
| N5 | No storage of full certificate bodies. | Extracted names and metadata only. |
| N6 | Not a WHOIS or registration-data product. | Domain age is an enrichment on hits, not a dataset this project republishes. |
| N7 | **No zone walking.** | `.sg` is DNSSEC-signed and NSEC enumeration is technically possible. Declined — adversarial toward the national registry, likely breaches their terms, and wrong for a project whose premise is defensive good citizenship. |
| N8 | No report-feed aggregation (URLhaus, PhishTank, OpenPhish). | Would turn a primary-source observatory into an accusation republisher. See `BLINDSPOTS.md` §5. |

---

## 6. Constraints

| ID | Constraint |
|---|---|
| C1 | **$0/month, permanently.** If a design needs a paid tier, the design is wrong. |
| C2 | Solo-maintained. Any feature needing more than ~2 hours/month of upkeep must justify itself. |
| C3 | Free-tier database is capped at **500 MB per database**. Retention is mandatory. |
| C4 | **Retention policy: trim history, keep coverage.** When the database approaches the cap, detail history is shortened rather than ingestion narrowed. Complete namespace coverage matters more than long detail history. **There is no history floor** — if volume grows, the detail window shrinks, and that is the intended trade. |
| C5 | Persist detail rows only for scored hits. All-issuance is tracked at registrable and aggregate grain. |
| C6 | All source, watchlists, allowlists and calibration results public in-repo. No private ranking logic. |

---

## 7. Scope

### P0 — the thing is live and useful

- Ingester covering 2–4 CT logs across **both** APIs, checkpointed and resumable.
- Leaf parsing including precertificates; extract SANs and CN, discard the rest.
- **Complete `.sg` issuance tracking** at registrable grain plus daily aggregates.
- Scored-hit detail rows for watchlist, scheme, and mixed-script matches.
- Normalisation chain: punycode, NFKC, confusable fold, separator strip, leet variants, affix decomposition.
- Scoring with per-brand edit-distance budgets, curated context tokens, and allowlist suppression.
- **Domain-age enrichment via RDAP**, subject to the M1 spike confirming creation dates are exposed.
- Dashboard: live table, "first seen today" list, search, score badge, issuer column, health strip.
- Committed data files: `watchlist.json`, `allowlist.json`, `keywords.json`, `schemes.json`.
- Daily write cap and dynamic retention pruning.
- Methodology page explaining the score, the blind spots, and how to request a correction.

### P1 — worth checking daily

- Timeline chart (hits per hour, stacked by category) and full issuance timeline.
- Issuer breakdown and score distribution charts.
- RSS / JSON feeds so people can subscribe without accounts.
- Domain detail page: all certs for a name, first-seen, SAN siblings.
- Precert / final-cert reconciliation so counts stop double-reporting.
- **CJK confusable research** — simplified/traditional folding and hanzi similarity, with its own calibration run before any CJK brand tokens ship.
- FTS5 spike for substring search.

### P2 — nice, if it earns its keep

- Registrable and SAN-sibling clustering.
- Historical backfill from crt.sh for a searched name.
- **Issuer-change detection** — gated on twelve months of accumulated history.
- Saved searches, webhook alerts, then email alerts.
- Public read API with documented rate limits.
- Watchlist contribution flow (PR-based, no accounts).
- Wildcard handling and short-domain view.

---

## 8. Responsible-use commitments

This is a security tool that names real domains, so these are product requirements, not a disclaimer.

1. **No verdicts.** UI copy says "possible lookalike", never "phishing", "malicious", "fraudulent", or "scam". Bands are *Informational* / *Possible* / *Notable*, enforced by a build-breaking copy lint.
2. **No automated reporting.** No registrar contact, no abuse mailboxes, no CERT feeds. (N1)
3. **No active probing.** (N2, N7)
4. **Corrections are a first-class feature.** A repo issue template is the documented route, with a stated turnaround and a permanent allowlist entry as the remedy. Entries added this way are logged visibly in `allowlist.json`.
5. **Watchlist-removal requests are honoured but logged.** Removing a brand reduces protection for that brand's customers, and the watchlist is a public file — so the change is visible in repo history rather than quiet.
6. **Aggregation, not disclosure.** Everything published is already public in CT. No vulnerability data, no registrant PII, no infrastructure fingerprinting.
7. **Calibration results are published in full, including the misses.** If the scoring is 55% precise, the dashboard says so.
8. **Blind spots are documented.** `BLINDSPOTS.md` is linked from the methodology page.

---

## 9. What this cannot see

Summarised here, detailed in [`BLINDSPOTS.md`](./BLINDSPOTS.md):

- **Wildcard-covered subdomains.** Phishing at `dbs-login.weebly.com` issues no new certificate.
- **Compromised legitimate sites** using an existing path. The subdomain variant *is* caught; the path variant is not.
- **HTTP-only campaigns.** No certificate, no entry.
- **IP-address landing pages.** Nothing to observe.
- **Brand-free redirectors.** Present in the data, will always score zero.

**The honest scope line: sgCertWatch2026 sees dedicated lookalike-domain phishing. It does not see platform-abuse or compromised-site phishing.** Both are common. This belongs on the methodology page verbatim.

---

## 10. Success criteria

Measured 30 days after P0 launch. All four, or P1 does not start.

| # | Criterion | Measurement |
|---|---|---|
| S1 | Ingester runs **7 consecutive days unattended**. | No human commits or re-runs; `ingest_runs` shows no gap > 60 min. |
| S2 | Median cert-to-dashboard latency **under 15 minutes**, from log entry availability (not `not_before`). | p50 over 7 days. Merge delay is upstream and not fully controllable — see `DESIGN.md` §3.9. |
| S3 | Manual review of the **50 highest-scored hits**: ≥60% plausibly suspicious. | Blind review against a written rubric, **stratified across `.sg` and `.com.sg`** so the sample isn't dominated by the larger namespace. Committed to `docs/calibration/`, misses included. |
| S4 | **30 consecutive days inside the free tier.** | Cloudflare row metrics and Actions minutes recorded monthly. |

---

## 11. Kill criteria — drop this if…

- **M1 (the ingester spike) takes more than 2 days.** CT parsing is fiddlier than it looks.
- **The 50-hit review comes back under 40% precision** and one tuning pass doesn't fix it. A noisy feed is worse than no feed.
- **I am not willing to babysit log-list changes and allowlist maintenance.** The `carousell`/`carousel` collision alone is a permanent recurring task, accepted deliberately.
- **I wanted this because I thought it was novel.** It is not (§2). If "SG-focused free public dashboard on a known technique, with genuinely good local tuning" is not by itself motivating, drop it. The honest cheap alternative is a 30-line local filter over a CT stream, no dashboard, no hosting, no maintenance.

---

## 12. Open questions

All rev 4 *product* questions are resolved. What remains needs code, not a decision.

| # | Question | Blocks |
|---|---|---|
| Q1 | Does SGNIC's RDAP expose domain creation dates, or are they redacted? | M1 spike — gates all `age:*` signals |
| Q2 | On large ingestion lag, grind through the backlog or skip to head and record a gap? | M1 |
| Q3 | What is the real `.sg` certificate volume per day? Every capacity number here is an estimate until measured. | M1 |
| Q4 | Does `D1.batch()` count as one query or N against the 50-per-invocation ceiling? | M3 |
| Q5 | Does D1 support FTS5 virtual tables? | M6 |
| Q6 | Does `issuer:free_dv` survive calibration, or get deleted? | M5 |

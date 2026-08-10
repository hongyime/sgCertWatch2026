# sgCertWatch2026 — Technical Design

| | |
|---|---|
| **Status** | Draft — no code written |
| **Author** | hongyime |
| **Revision** | rev 2 |
| **Last updated** | 2026-08-10 |
| **Companion docs** | [`PRD.md`](./PRD.md) · [`TASKS.md`](./TASKS.md) · [`BLINDSPOTS.md`](./BLINDSPOTS.md) |

This document assumes the PRD. It does not re-argue scope; it argues *mechanism*, and records the things that will break if built naively.

**Read §1 and §3.1 before writing any code.** Those two sections invalidate the obvious design.

### Changelog

| Rev | Change |
|---|---|
| 1 | Initial. Dual-API ingester, single `certs` table. |
| 2 | Three-table model (§5) replacing the single detail table — required by the all-issuance scope and ~3× cheaper. Expanded normalisation chain incl. affix decomposition (§4.1). `max_edit_distance` replaces `match_policy`. New signals: `brand:affix`, `idn:mixed_script`, `age:*`, `scheme:*`. RDAP enrichment (§4.6). Issuer-change schema hooks (§5.4). |

---

## 1. Constraints that shape everything

### 1.1 Verified platform limits

Checked 2026-08-09. Re-verify before implementation — these move.

| Limit | Free-tier value | Source |
|---|---|---|
| Worker CPU per HTTP request | **10 ms** | `developers.cloudflare.com/workers/platform/limits` |
| Worker CPU per Cron Trigger | **10 ms** | same |
| Worker requests | 100,000 / day | same |
| Worker subrequests | 50 external, 1,000 to CF services | CF changelog 2026-02-11 |
| **D1 queries per Worker invocation** | **50** | `developers.cloudflare.com/d1/platform/limits` |
| D1 rows written | 100,000 / day | `developers.cloudflare.com/d1/platform/pricing` |
| D1 rows read | 5,000,000 / day | same |
| **D1 max database size** | **500 MB** (5 GB is the *account* total) | `developers.cloudflare.com/d1/platform/limits` |
| D1 max bound parameters per query | **100** | same |
| GitHub Actions, public repo | Unmetered standard runners; 6 h job ceiling; 5 min cron minimum | GitHub docs |

Three of these are load-bearing and were wrong in earlier drafts:

- **Storage is 500 MB per database, not 5 GB.**
- **Every index adds a written row.** Cloudflare's pricing docs state this explicitly — an insert touching an indexed column writes one row to the table *and one per index*.
- **50 D1 queries per Worker invocation**, with 100 bound parameters per query, bounds the ingest batch size (§6.2).

### 1.2 What the limits rule out

**X.509 parsing cannot happen inside a free Worker.** ASN.1 decoding of a few hundred certificates exceeds 10 ms CPU immediately. This applies to Cron Triggers too — they get the same 10 ms on free. This is the single most likely way the project dies.

**Substring search is unaffordable.** `WHERE registrable LIKE '%dbs%'` cannot use an index and scans the table. Search must be index-shaped (§6.4).

**The all-issuance scope cannot use per-name detail rows.** At an estimated ~13,000 `.sg` name-rows/day, five rows written each, that is 65,000 rows/day before pruning — over budget on its own. Hence the three-table model (§5).

So: **parse in Actions, store through a thin Worker, keep the Worker doing nothing but I/O.**

---

## 2. Architecture

```
GitHub Actions  (cron */10, public repo = unmetered)
  ├─ fetch + cache Chrome CT log list (daily, committed)
  ├─ for each selected log:
  │    ├─ read checkpoint from Worker GET /api/state
  │    ├─ fetch entries      ← Static CT tiles OR RFC 6962 get-entries
  │    ├─ decode leaf → SANs + CN   (incl. precerts)
  │    ├─ normalise → filter → suppress allowlist → score
  │    └─ RDAP lookup for hits ≥ 30 (cached, registry-only)
  └─ POST batches → Worker /ingest  (HMAC-signed, ≤400 rows/request)

Cloudflare Worker  (free)
  ├─ POST /ingest       HMAC auth, budget check, chunked multi-row upsert
  ├─ GET  /api/state    checkpoints for the ingester
  ├─ GET  /api/*        read queries, aggressively cached
  └─ scheduled: nightly size-aware retention prune

Cloudflare D1
  └─ registrables, issuance_daily, certs, log_state, ingest_runs

Vercel (static)
  └─ Vite + React + Tailwind + Observable Plot, polls /api every 30 s
```

**Why Actions and not a Worker cron:** unmetered CPU, real Python (`cryptography`, `asn1crypto`, `idna`, `tldextract`), a 6-hour job ceiling, and a free scheduler.

**Actions gotchas, all real:** cron has a 5-minute minimum and fires late under load; scheduled workflows are **auto-disabled after 60 days with no repository activity** — mitigate with a monthly keepalive commit. The ingester is index-based, not time-based, so a late or missed run only means the next run catches up.

---

## 3. The CT ingestion layer

### 3.1 Ecosystem state, August 2026 — this invalidates the obvious design

There are now **two** CT log APIs in production, and a monitor speaking only one is blind to part of the ecosystem.

| | RFC 6962 | Static CT API ("tiled") |
|---|---|---|
| Transport | JSON over dynamic endpoints | Static files, CDN-served |
| Read | `GET /ct/v1/get-entries?start=&end=` | `GET /tile/data/<path>` |
| Head | `GET /ct/v1/get-sth` | `GET /checkpoint` (signed note) |
| Rate limits | Yes — 429s are routine | Effectively none; it's object storage |
| Log list section | `operators[].logs[]` | `operators[].tiled_logs[]` |
| Who runs them | Google (Argon, Xenon), Cloudflare (Nimbus), DigiCert | Let's Encrypt, and growing |

**Let's Encrypt shut down its RFC 6962 logs on 2026-02-28** and now writes only to Static CT logs. Let's Encrypt is the dominant issuer of free DV certificates, which is what phishing infrastructure overwhelmingly uses. **An RFC 6962-only ingester would miss the majority of the certificates this project exists to find, while appearing to work perfectly.**

RFC 6962 is not going away — Chrome accepts new RFC 6962 logs through at least 2026 shards, and Google's and Cloudflare's high-volume logs still use it.

**Design consequence: a `LogSource` abstraction with two backends is a P0 requirement.**

### 3.2 Log discovery

Fetch `https://www.gstatic.com/ct/log_list/v3/log_list.json` daily, validate against the published schema, and **commit the result to `data/log_list.cached.json`**. Chrome publishes the list without an availability SLA and explicitly recommends caching. The ingester always reads the cached copy.

Selection rules: appears under `logs[]` or `tiled_logs[]` with `state.usable` or `state.qualified`; `temporal_interval` covers today; not in `data/log_denylist.json`; capped at N logs chosen by observed `.sg` yield, including at least one Let's Encrypt shard.

### 3.3 Source abstraction

```python
class LogSource(Protocol):
    name: str
    api: Literal["rfc6962", "static"]

    def head(self) -> int:
        """Current tree size."""

    def entries(self, start: int, end: int) -> Iterator[RawLeaf]:
        """Yield leaves. MAY yield fewer than requested — the caller
        must advance its checkpoint by the count actually yielded."""
```

### 3.4 Static CT backend

- `GET <monitoring_url>/checkpoint` → signed note; line 1 origin, line 2 tree size, line 3 root hash. Signature verification deferred (§13 Q6).
- Data tiles hold 256 entries, addressed by tile index in slash-separated three-digit groups. Partial tiles carry a width suffix — **never cache a partial tile as final**, it will be replaced by a full tile later.
- Entries are length-prefixed `TileLeaf` structures concatenated in the tile body.
- Static, CDN-fronted, no rate limits. **Spike this backend first** (`TASKS.md` M1).

### 3.5 RFC 6962 backend

- `GET /ct/v1/get-sth` → `tree_size`; `GET /ct/v1/get-entries?start=N&end=N+K` → base64 `leaf_input` + `extra_data`.
- **Critical gotcha:** logs cap entries per response — commonly 32, 256, or 1000 — and return fewer than requested **without an error**. Advance the checkpoint by `len(returned)`, never by the requested range. Getting this wrong silently skips entries.
- 429 and 403 are routine. Exponential backoff, then a per-log circuit breaker.

### 3.6 Leaf decoding — where CT parsers break

`leaf_input` decodes to `MerkleTreeLeaf` → `TimestampedEntry`:

- **`x509_entry` (0)** — full `ASN.1Cert`. `cryptography.x509.load_der_x509_certificate` handles it.
- **`precert_entry` (1)** — `PreCert { issuer_key_hash, tbs_certificate }`. **`tbs_certificate` is a TBSCertificate, not a certificate.** No signature wrapper, so `load_der_x509_certificate` raises. Parse with `asn1crypto.x509.TbsCertificate` and read the SAN extension directly. This avoids fetching `extra_data` at all, cutting bytes transferred substantially.

**Do not filter out precerts.** They are logged *before* the final certificate and are the source of the latency advantage in S2. The final cert arrives later and is deduplicated (§5.3).

### 3.7 Name extraction

1. Collect `subjectAltName` `dNSName` entries plus `subject.CN` if hostname-shaped.
2. Deduplicate within the certificate.
3. Lowercase, strip trailing dot.
4. Record `is_wildcard` for `*.` prefixes; score the base name.
5. Extract eTLD+1 via `tldextract` with a **pinned PSL snapshot committed to the repo**. Never fetch the PSL at runtime — a network hiccup would silently change every registrable value.

**On the `.sg` namespace:** the PSL lists `com.sg`, `net.sg`, `org.sg`, `gov.sg`, `edu.sg` and `per.sg` as public suffixes, so eTLD+1 correctly yields `example.com.sg`. Filter F1 tests "public suffix ends in `.sg`" rather than an enumerated list, so new SGNIC namespaces and the IDN ccTLDs (`.新加坡`, `.சிங்கப்பூர்`) pick up automatically. Note `.com.sg` is the **larger** namespace — roughly 95k vs 65k for direct `.sg` in the last published figures — so calibration sampling must be stratified or it will only ever review `.com.sg`.

Because `gov.sg` is a public suffix, `go.gov.sg` lands as a registrable in its own right, which is the granularity the shortener-impersonation case needs.

### 3.8 Checkpointing and catch-up

`log_state` holds `last_index`, `tree_size`, `last_ok_at`, `consecutive_failures`. Index-based, so scheduling unreliability is harmless.

Catch-up guard: cap entries per log per run (start at 20,000). If `tree_size - last_index` exceeds 500,000, record a `lag_warning`. Grind-vs-skip is §13 Q2.

### 3.9 Latency, and what is not controllable

S2 targets p50 under 15 minutes. Controllable: cron cadence and run duration. **Uncontrollable:** RFC 6962 logs advertise a Maximum Merge Delay of up to 24 hours; most operators merge within minutes, but the guarantee is not yours. Static CT logs sequence before returning an SCT, which is generally faster.

S2 is therefore measured **from log entry availability, not certificate `not_before`**, and the dashboard must not imply otherwise.

---

## 4. Scoring engine

Pure function, no I/O, no database — which is what makes calibration possible. RDAP enrichment (§4.6) happens outside it and is passed in.

### 4.1 Normalisation chain — runs first, always, for every brand

**This is where Unicode attacks die.** Homoglyph and punycode squats are caught by *normalisation*, not by edit distance: `trսst` folds to `trust` and then matches exactly at distance 0. Edit distance is only ever about typo tolerance.

```
punycode decode  ─┐
NFKC fold         │  ALWAYS, every brand, no per-brand policy
confusable fold   │  ← every homoglyph / fullwidth / IDN attack dies here
separator strip   │
leet variants     │
affix decompose  ─┘
                   ↓
              match against brand tokens
                   ↓
        max_edit_distance ← per-brand, typo tolerance only
```

| Stage | Handles | Note |
|---|---|---|
| Punycode decode | `xn--` labels → Unicode | Sets `is_idn` |
| NFKC | Fullwidth `ｄｂｓ`, ligatures, compatibility forms | |
| Confusable fold (UTS #39) | Cyrillic `а`, Greek `ο`, `rn`→`m` | Produces an ASCII skeleton |
| Separator strip | `d-b-s`, `sing_pass` | |
| Leet variants | `0→o 1→l/i 3→e 4→a 5→s 8→b @→a $→s` | **Generate as variants, do not replace** — replacing would fold the M1 telco token into `ml` |
| Trailing noise strip | `singpass2026`, `singpass-sg` | |
| **Affix decomposition** | `dbsbank` → `dbs`+`bank`, `singpasslogin` → `singpass`+`login` | See below |

**Affix decomposition is not optional.** Separator tokenisation alone misses the most common real attack shape: `dbsbank-sg.xyz` tokenises to `["dbsbank","sg"]`, and `dbsbank ≠ dbs`. The decomposer attempts to split each token into brand + keyword or keyword + brand, using only tokens marked `affix: true` in `keywords.json`. Per-brand `allow_affix: false` disables it for tokens that are common substrings (`ica`, `mom`, `nets`, `trust`).

### 4.2 Filters — a name is persisted as a scored hit only if one holds

| ID | Filter |
|---|---|
| F1 | Public suffix ends in `.sg` **and** the name scores > 0 (bare `.sg` issuance is tracked in `registrables`, not `certs`) |
| F2 | A token matches a watchlist brand within that brand's `max_edit_distance`, and `require_context` is satisfied |
| F3 | Confusable skeleton matches a brand skeleton but the raw string does not |
| F4 | A scheme token from `schemes.json` matches |
| F5 | Any single label mixes scripts (see `idn:mixed_script`) |

Allowlist suppression runs **before** scoring: a match drops the name entirely from `certs` while still counting in `registrables` and `issuance_daily`.

### 4.3 Signals and weights

Additive, clamped 0–100. Starting values — **guesses until calibration says otherwise.**

| Signal ID | Condition | Weight |
|---|---|---|
| `scheme:<id>` | Government scheme token match | +45 |
| `scheme:seasonal` | Hit falls inside an active disbursement window | +15 |
| `brand:dl1` | Edit distance 1 within the brand's budget | +45 |
| `brand:homoglyph` | Skeleton matches a brand, raw does not | +45 |
| `brand:exact` | Brand is a whole token, registrable not allowlisted | +40 |
| `idn:mixed_script` | A single label mixes scripts (e.g. Latin + Cyrillic) | +35 |
| `brand:affix` | Token decomposes into brand + keyword | +35 |
| `brand:dl2` | Edit distance 2 within the brand's budget | +30 |
| `age:very_new` | Registered < 7 days ago | +25 |
| `combo:brand+kw` | Brand token and keyword token in the same registrable | +25 |
| `idn:punycode` | Any label was punycode-encoded | +15 |
| `tld:mismatch` | Brand hit on a TLD outside the brand's `known_tlds` | +15 |
| `age:new` | Registered < 30 days ago | +15 |
| `kw:<token>` | Suspicious keyword token | +10 each, cap +25 |
| `shape:hyphens` | ≥ 2 hyphens in the SLD | +5 |
| `shape:depth` | ≥ 4 labels | +5 |
| `issuer:free_dv` | Issued by a free DV CA | +5 |
| `age:established` | Registered > 2 years ago | **−10** |

`brand:dl1` and `brand:dl2` are mutually exclusive; take the best match only.

**On `idn:mixed_script`:** a single label mixing Latin and Cyrillic is essentially never legitimate, and UTS #39 restriction levels formalise this. It is one of the few near-verdict signals available, and it fires **independent of any brand match** — so it catches homoglyph squats of brands not on the watchlist at all.

**On `issuer:free_dv`:** a weak signal that penalises everyone using Let's Encrypt, which is most of the legitimate web. Included behind a config flag purely so calibration can measure it. **Default to deleting it after M5 unless the data defends it.**

### 4.4 Bands and copy rules

| Score | Band label | Never say |
|---|---|---|
| 0–29 | Informational | phishing, malicious, fraudulent, scam, fake |
| 30–59 | Possible lookalike | (same) |
| 60–100 | Notable lookalike | (same) |

Enforced by a build-breaking lint over UI strings (`TASKS.md` M4-04).

### 4.5 `reasons` format

Stable machine-readable strings: `["brand:dl1:dbs", "kw:login", "age:very_new", "tld:mismatch"]`. This is public API surface — it appears in the JSON feed and renders in the UI. Treat changes as breaking.

### 4.6 RDAP domain-age enrichment

Registration data closes part of the gap in `BLINDSPOTS.md` §3. Bulk `.sg` registration data does not exist — CZDS covers gTLDs only and the obligation does not extend to ccTLDs — but SGNIC operates an RDAP server, and RDAP is a *lookup*, which is all that is needed because CT already supplied the name.

| Aspect | Design |
|---|---|
| Trigger | Hits scoring ≥ 30 only. ~50–200 lookups/day. |
| Server discovery | IANA RDAP bootstrap, so any TLD resolves — not just `.sg`. |
| Caching | Permanent, keyed by registrable, stored in `registrables.registered_at`. Registration dates do not change. |
| Rate limiting | Polite backoff, daily cap, per-server. Getting blocked by the national registry would be an embarrassing outcome for a defensive project. |
| Where it runs | Actions, never the Worker. |
| N2 compliance | The query goes to the **registry**, not the suspect domain. Zero packets reach attacker infrastructure. |

**Gated on a spike (§13 Q1):** many ccTLD registries redact creation dates. One curl against `rdap.sgnic.sg` answers it. **Coverage is better off-`.sg` than on it** — gTLD RDAP reliably publishes creation dates, so `dbs-login.top` resolves cleanly even if `.sg` is redacted.

Fallback if redacted: `registrables.first_seen` — "this `.sg` name appeared in CT for the first time ever today" — is a decent newness proxy that costs nothing extra.

### 4.7 Calibration

`scripts/calibrate.py` samples N hits **stratified across `.sg` and `.com.sg`**, emits a shuffled CSV with scores hidden, takes a reviewer verdict column, and computes precision per band. Output committed to `docs/calibration/YYYY-MM-DD.md`, **misses included**. This is the instrument behind S3 and kill criterion 2 — without it both are unfalsifiable.

---

## 5. Data model

### 5.1 Three tables, three grains

The all-issuance scope makes a single detail table unaffordable (§1.2). Splitting by grain is both cheaper and a better fit for the actual queries.

| Table | Grain | Size | Retention |
|---|---|---|---|
| `registrables` | One row per registrable, **upserted in place** | Bounded by the namespace, ~250–300k | Permanent |
| `issuance_daily` | `(day, issuer, suffix) → count` | ~50 rows/day | Permanent |
| `certs` | Scored-hit detail, one row per name per cert | Bounded by daily cap | **Dynamic to fit 500 MB** |

`registrables` is the important one. It is **permanently bounded** — it can never exceed the size of the `.sg` namespace plus off-`.sg` scored hits, regardless of how long the project runs. It carries the RDAP cache, the first-seen data, and the issuer history that makes §5.4 possible later.

### 5.2 Schema

```sql
CREATE TABLE registrables (
  registrable      TEXT PRIMARY KEY,     -- eTLD+1
  suffix           TEXT NOT NULL,        -- com.sg, sg, edu.sg, top, ...
  in_sg            INTEGER NOT NULL,     -- 1 if public suffix ends in .sg
  first_seen       TEXT NOT NULL,        -- first CT observation, ISO8601
  last_seen        TEXT NOT NULL,
  cert_count       INTEGER DEFAULT 1,
  issuers_seen     TEXT,                 -- JSON set, powers §5.4
  first_issuer     TEXT,
  registered_at    TEXT,                 -- RDAP cache, NULL if unknown
  rdap_checked_at  TEXT,
  max_score        INTEGER DEFAULT 0     -- highest score ever seen
);
CREATE INDEX idx_reg_first ON registrables(first_seen DESC);
CREATE INDEX idx_reg_sfx   ON registrables(suffix, first_seen DESC);

CREATE TABLE issuance_daily (
  day     TEXT NOT NULL,
  issuer  TEXT NOT NULL,
  suffix  TEXT NOT NULL,
  count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, issuer, suffix)
);

CREATE TABLE certs (
  id           INTEGER PRIMARY KEY,
  cert_key     TEXT NOT NULL,          -- sha256(issuer_der || serial), hex
  seen_at      TEXT NOT NULL,
  not_before   TEXT,
  domain       TEXT NOT NULL,
  registrable  TEXT NOT NULL,
  issuer       TEXT,
  log_name     TEXT,
  score        INTEGER NOT NULL,
  reasons      TEXT,                   -- JSON array
  flags        INTEGER DEFAULT 0       -- 1=precert 2=wildcard 4=idn 8=mixed_script
);
CREATE UNIQUE INDEX idx_dedup ON certs(cert_key, domain);
CREATE INDEX idx_seen  ON certs(seen_at DESC);
CREATE INDEX idx_score ON certs(score DESC, seen_at DESC);
CREATE INDEX idx_creg  ON certs(registrable);

CREATE TABLE log_state (
  log_name TEXT PRIMARY KEY, api TEXT NOT NULL,
  last_index INTEGER NOT NULL DEFAULT 0, tree_size INTEGER,
  last_ok_at TEXT, consecutive_failures INTEGER DEFAULT 0
);

CREATE TABLE ingest_runs (
  id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, started_at TEXT NOT NULL,
  log_name TEXT, entries_read INTEGER, sg_seen INTEGER, matches INTEGER,
  inserted INTEGER, deduped INTEGER, lag INTEGER, status TEXT, note TEXT
);
```

Booleans are collapsed into `flags` deliberately: each extra indexed column adds write amplification, and each extra column eats the 100-bound-parameter ceiling.

### 5.3 Deduplication — design it in now

A precertificate and its final certificate share **issuer** and **serial number**, so `cert_key = sha256(issuer_der || serial)` identifies them as one logical certificate and `UNIQUE(cert_key, domain)` collapses the pair via `INSERT … ON CONFLICT DO NOTHING`.

Reconciliation logic is P1, but **the unique index must exist from the first migration** — retrofitting a unique constraint onto a live D1 table with existing duplicates is genuinely painful, and adding it upfront costs one index.

### 5.4 Issuer-change hooks — schema now, signal in 2027

`registrables.issuers_seen` and `first_issuer` are written as a side effect of upserts that happen anyway, so the option costs nothing. The *signal* — a registrable with years of one CA suddenly getting another — is P2 and explicitly gated on twelve months of accumulated history. Rationale, prior art and the cautionary literature are in `BLINDSPOTS.md` §4.

### 5.5 Retention — dynamic, coverage-first

Per constraint C4: **trim history, keep coverage. No history floor.**

The nightly pruner reads the database size, and while above the 400 MB soft cap deletes the oldest `certs` rows in capped batches until under it. `registrables` and `issuance_daily` are never pruned — together they are a small, bounded fraction of the budget, and they are the permanent record.

**Pruning is itself a write cost:** deleting a `certs` row writes 1 table row + 4 index rows. The pruner therefore runs last, checks the remaining daily write budget, and skips entirely if under 25,000 remaining.

---

## 6. API

### 6.1 Auth

`POST /ingest` requires `X-Signature: sha256=<hmac>` over `timestamp || body`, plus `X-Timestamp`; reject if older than 5 minutes. Secret lives in Actions secrets and as a Worker secret. Fork PRs cannot read Actions secrets — the correct default for a public repo.

A bearer token would be simpler but leaks permanently if it ever lands in a log line. HMAC via WebCrypto stays inside the CPU budget.

### 6.2 `POST /ingest`

```jsonc
{
  "run_id": "2026-08-10T12:00:00Z-a1b2",
  "log_name": "letsencrypt-willow2026h2",
  "cursor": 184402331,
  "registrables": [ /* upserts */ ],
  "daily": [ /* issuance_daily increments */ ],
  "certs": [ /* scored hits only */ ]
}
```

**Batch sizing is dictated by the limits:** 11 columns × 9 rows = 99 bound parameters, so 9 rows per INSERT statement; 50 D1 queries per invocation minus overhead leaves ~47 statements. **Hard cap: 400 rows per request** across all three arrays combined.

> **Verify before relying on it:** whether `D1.batch()` counts as one query or N against the 50-per-invocation ceiling is not clearly documented. Measure with the `meta` object in M3 and adjust. Assume N until proven otherwise.

Returns `429` with `Retry-After` when the daily cap is hit; the ingester stops writing but **still advances `log_state`** so it does not re-scan tomorrow.

### 6.3 Read endpoints

| Endpoint | Purpose | Tier |
|---|---|---|
| `GET /api/recent` | Scored-hit table, keyset-paginated | P0 |
| `GET /api/first-seen` | `.sg` registrables first observed today — the all-issuance browse view | P0 |
| `GET /api/search` | Prefix/exact search — see §6.4 | P0 |
| `GET /api/state` | Checkpoints for the ingester | P0 |
| `GET /api/health` | Per-log lag, last run, write-budget consumption | P0 |
| `GET /api/domain/{name}` | Certs for a name, first-seen, SAN siblings | P1 |
| `GET /api/stats` | Issuance timeline, issuer breakdown, score distribution | P1 |
| `GET /api/feed.json`, `/api/feed.xml` | Subscribable feeds | P1 |

### 6.4 Search must be index-shaped

`LIKE '%q%'` is banned (§1.2). P0 supports **prefix match** on `registrable` (`LIKE 'dbs%'`, uses the index) and **exact match** on `registrable` and `domain`. Everything else returns a "prefix search only" hint, stated plainly on the methodology page. FTS5 is the P1 fix **if** D1 supports it — verify, do not assume.

### 6.5 Caching is load-bearing

A 30-second poll with 100 concurrent viewers is ~288,000 requests/day — above the Worker free request cap and far above the read budget if each hits D1.

`Cache-Control: public, max-age=30, stale-while-revalidate=60` plus the Worker Cache API reduces origin queries to roughly 2,880/day. **Not an optimisation; without it the free tier does not hold.**

---

## 7. Dashboard

Vite + React + TypeScript + Tailwind, Observable Plot, static on Vercel.

- Polls every 30 s; **pauses when the tab is hidden** — a background tab polling forever is a large share of the request budget.
- Keyset pagination, never offset — offset reads and discards rows, costing read budget.
- **Status strip** from `/api/health` showing per-log lag. If ingestion is stale, the page says so. A security dashboard silently showing old data is worse than one that is honestly down.
- Two distinct views: **scored hits** (the security view) and **first seen today** (the all-issuance / domain-nerd view). Keeping them separate stops the interesting signal drowning in routine renewals.
- Score badge renders the band label from §4.4 and links to the methodology page.
- Empty, loading and error states are P0, not polish.

---

## 8. Cost model

### 8.1 Daily write budget

Budget: **100,000 rows written/day.** Each row costs 1 table row + 1 per index touched.

| Activity | Volume | Rows written |
|---|---|---|
| `registrables` upserts (3 indexes incl. PK) | ~3,300 | ~13,200 |
| `issuance_daily` upserts | ~50 | ~100 |
| `certs` inserts (4 indexes) | ~1,500 | ~7,500 |
| `certs` prune (steady state) | ~1,500 | ~7,500 |
| `log_state` updates | ~1,440 | ~2,880 |
| `ingest_runs` inserts | ~144 | ~288 |
| **Total** | | **~31,500 (32%)** |

**Hard caps:** 8,000 `certs` inserts/day and 10,000 `registrables` upserts/day. At both caps, roughly 82,000 rows — ~18% headroom. Caps trip a `capped` status in `ingest_runs` and surface on `/api/health`.

This is roughly **3× cheaper** than the single-table design, which is what makes the all-issuance scope affordable at all.

### 8.2 Storage

| Table | Estimate |
|---|---|
| `registrables` | ~300k rows × ~250 B ≈ **75 MB**, permanent, bounded |
| `issuance_daily` | ~2 MB/year |
| `certs` | Gets the remaining ~325 MB → at ~450 B/row and ~1,500 hits/day, roughly **16 months** of detail history before trimming starts |

### 8.3 Other resources

| Component | Free tier | Projected | Assessment |
|---|---|---|---|
| GitHub Actions | Unmetered (public) | ~144 runs/day × ~2 min | Fine |
| Worker requests | 100k/day | ~5k/day with caching | 20× headroom |
| Worker CPU | 10 ms/req | I/O only, no parsing | Fine **by design** |
| D1 rows written | 100k/day | ~32k/day | 3× headroom |
| D1 rows read | 5M/day | ~300k/day with caching | Watch if search is popular |
| D1 storage | 500 MB/db | ~400 MB steady state | Managed by dynamic prune |

**Total: $0**, provided (a) only scored hits get detail rows, (b) retention pruning runs, (c) read caching is in place. Remove any one and the free tier fails.

> Every volume number above is an estimate. `.sg` daily certificate volume is measured in M1 (§13 Q3) and these tables should be rewritten with the real figure.

---

## 9. Guardrails

1. **Daily caps** (8,000 certs / 10,000 registrables), enforced Worker-side so a runaway ingester cannot bypass them.
2. **Per-run entry cap** (20,000/log).
3. **Per-log circuit breaker** — 3 consecutive failures skips for the run, 10 disables until manually re-enabled.
4. **Keepalive workflow** — monthly no-op commit so Actions does not auto-disable scheduled workflows.
5. **Budget-aware pruner** — skips if under 25,000 remaining writes.
6. **RDAP rate limiter** — per-server backoff and a daily cap.
7. **Storage alarm** — daily check, fails CI at 450 MB.

---

## 10. Observability

`ingest_runs` is the whole story. `GET /api/health` returns per-log lag, last successful run, and write-budget consumption; the dashboard status strip reads it. No third-party monitoring — one more free tier to babysit is one too many.

---

## 11. Security, abuse, and legal

| Concern | Handling |
|---|---|
| Ingest secret leakage | HMAC not bearer; Actions secret masking; never `set -x` in the ingest step; fork PRs cannot read secrets |
| Feed used to find fresh domains to attack | Already public in CT; this aggregates rather than discloses. No probing (N2), no vulnerability data |
| Naming a legitimate business as a lookalike | Bands not verdicts (§4.4); enforced copy lint; issue-template correction route; permanent allowlist as remedy |
| A wrong allowlist entry silently suppressing a real threat | The most dangerous failure mode here. Every seed entry is `verified:false`; CI blocks release until all are verified |
| Bulk scraping | `robots.txt` discourages it; the JSON feed is the sanctioned bulk path |
| Personal data | CT contains no registrant data. RDAP results are cached as a date only, never registrant details |

---

## 12. Tradeoffs and rejected alternatives

| Option | Verdict | Why |
|---|---|---|
| Worker Cron Trigger does ingestion | **Rejected** | 10 ms CPU on free applies to cron too |
| Public `certstream` firehose | **Rejected** | Third-party SPOF, and abstracts away the RFC 6962 / Static CT split that must be handled deliberately |
| Poll crt.sh instead of logs | **Rejected as primary** | Someone else's infrastructure, rate-limited, adds latency. P2 backfill only |
| Single `certs` table for all issuance | **Rejected** | ~65k rows/day before pruning. The three-table split is ~3× cheaper |
| ML / unsupervised anomaly detection | **Rejected** | Ostertág and Stanek applied Isolation Forest to CT logs and found the most "anomalous" certificates were Microsoft's own Azure infrastructure. Anomaly detection on CT finds *unusual*, and unusual is dominated by large legitimate infrastructure |
| Zone files / CZDS for `.sg` | **Unavailable** | CZDS is gTLD-only by contract; SGNIC publishes nothing. See `BLINDSPOTS.md` §3 |
| NSEC zone walking | **Declined on principle** | See PRD N7 |
| Report feeds (URLhaus, PhishTank) | **Rejected** | Turns a primary-source observatory into an accusation republisher. `BLINDSPOTS.md` §5 |
| Durable Objects + WebSocket push | **Deferred** | Polling with cache headers is free and adequate |
| Cloudflare Pages instead of Vercel | **Viable alternative** | Would consolidate to one account. Rejected only on familiarity |
| Supabase / Neon free Postgres | **Rejected** | Free Postgres tiers pause on inactivity and have changed terms historically |
| Substring search | **Rejected** | Unindexable; blows the read budget |
| Monthly partitioned tables + `DROP TABLE` | **Deferred** | Would eliminate the prune write cost. Adopt if prune writes become binding |
| Static CT checkpoint signature verification | **Deferred** | Correct for a monitor *of record*; unnecessary for a heuristic dashboard |

---

## 13. Open technical questions

| # | Question | Blocks |
|---|---|---|
| Q1 | Does SGNIC's RDAP expose creation dates, or are they redacted? | M1 — gates all `age:*` signals |
| Q2 | On large lag, grind the backlog or skip to head and record a gap? | M1 |
| Q3 | Real `.sg` certificate volume per day? Every number in §8 is an estimate until this is measured. | M1 |
| Q4 | Does `D1.batch()` count as 1 query or N against the 50-per-invocation ceiling? | M3 |
| Q5 | Does D1 support FTS5 virtual tables? | M6 |
| Q6 | Verify Static CT checkpoint signatures, or continue to trust the transport? | P2 |
| Q7 | Does `issuer:free_dv` survive calibration? | M5 |

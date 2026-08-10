# sgCertWatch2026 — Known Blind Spots

| | |
|---|---|
| **Status** | Living document |
| **Revision** | rev 1 |
| **Last updated** | 2026-08-10 |
| **Companion docs** | [`PRD.md`](./PRD.md) · [`DESIGN.md`](./DESIGN.md) · [`TASKS.md`](./TASKS.md) |

This file exists so the project cannot quietly over-promise. Everything below is a category of phishing that sgCertWatch2026 **will not detect**, stated plainly, with the cost of closing it and the reason it was declined.

Two audiences: future-me at month four, when half-building a URL aggregator starts to feel like a good idea; and anyone deciding how much to trust the dashboard.

**The one-line version:** sgCertWatch2026 sees *dedicated lookalike-domain* phishing. It does not see *platform-abuse* or *compromised-site* phishing. Both are common.

---

## 1. Why the gaps exist

There are five places you can observe phishing infrastructure. This project observes exactly one of them, and each blind spot is simply something that happens at a different point.

| Observation point | What it sees | Cost | Would catch |
|---|---|---|---|
| **Issuance** (CT logs) | New certificates | Free, public by design | Dedicated lookalike domains |
| **Registration** (zone files, NRD feeds) | New domains | Free for gTLDs — **not available for `.sg`**, see §3 | HTTP-only, pre-certificate domains |
| **Resolution** (passive DNS) | Hostnames that actually resolve | Commercial only, expensive | Wildcard-hidden subdomains |
| **Content** (crawling) | What is actually served | Free, but violates non-goal N2 | Compromised sites, everything else |
| **Reports** (URLhaus, OpenPhish, PhishTank) | What other people found | Free, passive | Partially all of the above |

No amount of cleverness in the CT parser reaches the other four rows. The data was never in CT to begin with.

---

## 2. The four gaps

### 2.1 Wildcard certificates hide subdomains

Phishing hosted at `dbs-login.weebly.com` is covered by the platform's existing `*.weebly.com` certificate. **No new certificate is issued, so nothing enters CT.** The same applies to Firebase (`*.web.app`), Vercel (`*.vercel.app`), and most large shared-hosting platforms.

Worse for path-based hosting: something served from `sites.google.com/view/dbs-login` has no DNS record and no certificate of its own. There is nothing at the infrastructure layer to observe, by any method. That specific case is unreachable by any design this project could adopt.

**Partial mitigation, free:** platform abuse is not uniformly wildcarded. Several platforms issue per-hostname certificates for customer subdomains, and *any* attacker who attaches a custom domain generates a certificate regardless of platform. So the gap is real but not total.

**Status:** accepted, no mitigation planned. This category is large and growing.

### 2.2 Compromised legitimate sites

The attacker puts a phishing page inside an existing, legitimate site — `smallbakery.sg/wp-content/dbs/`. The certificate was issued honestly, years ago, to a real business. Nothing new hits the logs.

**Partial coverage, already built:** an attacker who adds a *subdomain* — `dbs-secure.smallbakery.sg` — needs a new certificate for that hostname, and it lands in CT with a brand token in it. The existing pipeline scores that today. It is the **path-based** case that is invisible, not the whole category.

**Possible future signal:** issuer-change detection. A registrable that has used the same CA for years suddenly receiving a certificate from a different one is a weak indicator of a change in control. See §4.

**Status:** partially covered. Subdomain case yes, path case no.

### 2.3 HTTP-only campaigns

No TLS, no certificate, no CT entry. Still common for short-lived SMS lure infrastructure that only needs to survive a few hours.

**What would close it:** a newly-registered-domain feed, which for `.sg` does not exist. See §3.

**Status:** accepted, structurally unclosable for `.sg`.

### 2.4 IP-address landing pages

A lure pointing directly at an IP has no domain and no certificate. Nothing to observe.

**Status:** accepted, unclosable.

---

## 3. The registration layer — researched, mostly closed

Registration data would close §2.3 and give early warning on §2.1, so it was investigated properly.

**Bulk `.sg` registration data is not available.** ICANN's Centralized Zone Data Service distributes zone files for gTLDs, but the contractual obligation to provide them **does not extend to any ccTLD**. SGNIC publishes no zone file. The community reference on per-TLD zone availability is blunt that most ccTLD operators deny such requests when asked.

Commercial "`.sg` zone file" products exist. They are scraped reconstructions of unclear provenance, and they are paid, so they fail constraint C1 regardless.

**Zone walking is technically possible and deliberately declined.** The `.sg` zone is DNSSEC-signed, which in principle opens NSEC enumeration. This project will not do that. It is adversarial toward the national registry, it very likely violates their terms, and being blocked or named would be a genuinely bad outcome for a project whose entire premise is defensive good citizenship. Not worth a domain list.

### What *is* available, and got adopted

SGNIC operates an **RDAP server** (`rdap.sgnic.sg`, per the IANA delegation record). RDAP cannot enumerate — you must already know the name — which is why it looked useless at first. But this project always knows the name, because CT just supplied it.

So the registration layer is not a second detection source. It is an **enrichment on hits already in hand**: look up the registrable, get its creation date, score domain age. A domain registered four days ago that just received a certificate and contains a brand token is a categorically different object from a ten-year-old domain doing the same thing.

This is implemented as the `age:*` signals in `DESIGN.md` §4.3, gated on a spike task confirming SGNIC's RDAP actually exposes creation dates — many ccTLD registries redact them.

Two notes worth carrying forward:

- **Coverage is better off-`.sg` than on it.** IANA's RDAP bootstrap resolves the correct server for any TLD, and gTLD RDAP reliably publishes creation dates. So `dbs-login.top` — the case where domain age matters most — resolves cleanly even if `.sg` turns out to be redacted.
- **This does not violate non-goal N2.** The query goes to the *registry*, not to the suspect domain. Zero packets touch attacker infrastructure. That distinction is written into N2 explicitly rather than left ambiguous.

---

## 4. Issuer-change detection — schema built, signal deferred

The idea: a registrable with a stable multi-year history of certificates from one CA suddenly gets one from a different CA. That is a weak indicator of a change in control, which is what a compromise is.

**Prior art exists, in a different shape.** Cert Spotter sells unknown-certificate alerts and CAA monitoring — but on a **declared** baseline: the domain owner tells them which CAs they use. This project would infer the baseline from **observed history**, across the whole `.sg` namespace, including the overwhelming majority of domains whose owners have never asked anyone for anything. Same underlying signal, meaningfully different product.

**Three reasons it is deferred rather than built:**

1. **It needs roughly twelve months of accumulated history** before a baseline means anything.
2. **Cost-driven CA migration is constant background noise.** Everyone moved to free DV issuers over the last decade, and they are still moving.
3. **A cautionary result from the literature.** Ostertág and Stanek applied Isolation Forest anomaly detection to CT logs and found that the most "anomalous" certificates their model surfaced were Microsoft's own Azure infrastructure. Unsupervised anomaly detection on CT finds *unusual*, and unusual is dominated by large legitimate infrastructure. Issuer-change detection is a narrow version of the same trap and must be weighted accordingly — a low-weight modifier on an otherwise-quiet domain, never a headline.

**CAA is weaker than it first appears** for this use case. A CAA violation means the CA misissued — rare and high-value, but not phishing. And an attacker who has compromised a domain controls its DNS, so they can simply rewrite the CAA record before requesting a certificate.

**Decision: build the schema now, build the signal later.** The `registrables` table carries `issuers_seen` and `first_seen` as a side effect of writes that happen anyway, so the option costs nothing to preserve and would be painful to retrofit. The signal itself is a P2 task explicitly gated on twelve months of data.

---

## 5. Report feeds — the honest way to close most of this, declined

Ingesting community report feeds (URLhaus, OpenPhish community, PhishTank) filtered to SG brand keywords would be free, passive, involve no probing, and partially cover all four gaps in §2 — because a human reported the URL regardless of how it was hosted.

**Declined for two reasons:**

**It changes what the project is.** Right now this is an observatory of a *primary* data source: it sees things at the moment they become observable. Adding report feeds makes it an aggregator of other people's detections — a far more crowded space with a much weaker claim. The novelty-gate reasoning in `PRD.md` §2 was written about the first thing and would not survive the change.

**The liability profile differs in kind.** "This certificate was issued" is a fact. "Someone reported this URL as malicious" is an accusation, and republishing accusations is a different posture from publishing public log data — precisely the posture the no-verdicts commitment in `PRD.md` §8 exists to avoid.

---

## 6. Two more limitations worth stating

**Deliberate non-coverage of the full log set.** Non-goal N3: this samples a subset of CT logs. Even within its own observation point, coverage is partial by design. Research on CT monitors has found that third-party monitors routinely return incomplete certificate sets for a given domain, so this is a general property of CT monitoring rather than a shortcut unique to this project — but it is still a limitation, and the health endpoint should make the sampled log set visible.

**Brand-free redirectors are unscoreable.** Attackers increasingly register short redirect-hop domains — `x7k2.top`, `sg-l.cc`. These *are* in the collected data, and they will score **zero**, because a domain deliberately containing no brand token cannot be caught by brand-lookalike scoring. This is not fixable within the model. A short-`.sg`-domain view is P2 domain-nerd material at best; as a *signal* it would be pure noise, because short domains are premium and mostly legitimate.

---

## 7. Review triggers

Revisit this document when any of the following happens:

- Calibration precision holds above 60% for two consecutive quarters — the scoring is working, and gap-closing becomes the highest-value next move.
- Twelve months of `registrables` history accumulate — issuer-change becomes computable.
- A free, legitimate source of `.sg` registration data appears.
- Someone asks the dashboard to be authoritative about whether a domain is malicious. The answer is in §2, and it is no.

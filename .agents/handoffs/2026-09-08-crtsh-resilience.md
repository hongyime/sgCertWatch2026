# crt.sh Resilience

User asks why crt.sh is degraded, whether URLs are correct, and for independently operating robust monitoring. Earlier push/main/deploy authorization remains; JWT rotation excluded.

Evidence:
- https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc supports identity and output=json on the root. Bare tokens use indexed text matching plus substring filtering, not the right-anchored behavior claimed in our comment. minNotBefore only constrains lint queries; do not invent a domain-search date filter.
- https://groups.google.com/g/crtsh/c/PsNhy2WVXhg is the operator's May 28, 2026 explanation of overloaded replicas, freezes and inefficient sorting.
- Two bounded local probes (root and identity=hong-yi.me with output=json, exclude=expired) returned HTML HTTP 404. Last verified successful primary Actions run 34180182808 had crt.sh HTTP 502. Provider failure is not a valid zero-result response.

Plan: remove immediate retry amplification and process-local breaker; persist next poll and failure count in existing crtsh state; enforce response-body deadline and size; retain successful observations while skipping polls; expose retry and last check accurately. Test restart, 404, 429/Retry-After, invalid body, body stalls, empty lists and recovery. Audit primary scheduler separately, then test, push, deploy and dispatch live validation.

Do not add keys, rotate JWT, use Vercel scanning, or mark unavailable crt.sh healthy to make the dashboard green.

## Verified Outcome

- Reliability release `7f853ba` is on main; Vercel auto-deployment `dpl_CYaZ3GNo5LDtPoyAHS2vWhbuFTgX` is READY on both public aliases and tied to the SHA by GitHub commit status. CI `34246781888` passes PostgreSQL 17, 30 outbox checks, 74 scheduler tests, lock contention/expiry regressions and Chromium desktop/mobile fixtures. All release security checks are green.
- Live CT `34246820421` completed at 15:50:12Z: 30,851 checked, 1,324 findings and 1,353 sightings saved; all six direct logs successful. Geomys 429 pause is persisted until 16:46:33Z, crt.sh timeout pause until 17:45:59Z. TrustAsia timeout and partial static coverage remain real upstream limitations. Duplicate dispatch `34247623022` exited `scan_not_due` without changing the successful heartbeat or contacting sources.
- Intel `34246843332` refreshed OpenPhish and retained the other three providers' schedules. Notification workflows ran successfully and published unconfigured/zero backlog; no Telegram delivery is claimed. Production `verify_live.mjs` passes both aliases at desktop/mobile sizes, including default Domains, evidence details, exports, Watchlist search, Review, Monitor, favicon, console and layout.
- No remote scheduler activation or 24-hour soak yet: scoped GitHub token and operational alert destination remain absent. All local verification processes/containers are stopped and independent reviewers closed. Next action is user credential setup, not another scanner rewrite or repeat provider probes.

Earlier deployed iterations:

- Runtime `5d7e84c` is on main and deployed (`dpl_vorTJr2MUxJWSxNvfgQkKFHCbrp4`). Final data-validation CI run `34208305512` passes; both public aliases pass desktop/mobile read flows, favicon, console and layout checks.
- Live run `34206246005`: 47,269 entries checked, 2,152 findings saved; crt.sh root JSON query succeeded in about six seconds. Direct/static timeouts did not stop saved findings.
- Live resume `34207087100`: 27,797 checked, 1,074 findings saved; six direct logs successful; static rotation advanced beyond the previous first ten logs; crt.sh made zero requests and retained last-attempt/next-poll timestamps.
- Rotated static logs exposed 429 from Geomys and IPng plus a TrustAsia timeout. Added and regression-tested persisted operator cooldowns (at least one hour, longer Retry-After respected), skipping sibling logs and preserving unsaved cursors. This last addition was not followed by another live provider scan.
- Source deadlines cover response bodies, malformed tile framing cannot advance cursors, completed checkpoints precede optional notifications, failed stages are persisted, and primary availability excludes idle backups. Tests cover 29 static scenarios and seven runner recovery scenarios, plus crt.sh and existing suites.

## Remaining Limits

## Approved Reliability Continuation

User approved all five follow-up tasks and subagent verification. Parent handles atomic lock RPCs, fenced state/checkpoint writes, runner integration, workflows, monitoring, deployment and live checks. Disjoint workers handle provider adapters/tests, scheduler folder, and notification outbox module/SQL/tests. Do not deploy before SQL grants, lock contention/expiry and outbox replay tests pass. Scheduler must dispatch GitHub Actions only and avoid duplicate work; no privileged database key in Cloudflare. Check existing Wrangler authentication; otherwise ask for account setup and a repo-scoped GitHub Actions token. Optional Telegram requires a destination before real delivery/incident verification. Start and record an actual 24-hour soak after activation; do not claim completion from unit tests alone.

- GitHub cron is active but actual scheduled runs had a median 2h51m gap in the audited sample, with a maximum 12h26m. Offset `7,22,37,52` is only mitigation. Asked user about a free Cloudflare trigger; no answer/account integration yet. Any independent trigger should dispatch the existing workflow so its concurrency guard remains effective, not start a competing scanner.
- Atomic owner-checked database leases and the durable outbox are implemented, with additive migrations applied. Final integrated local suites pass, including 74 scheduler tests; independent PostgreSQL 16.15 tests pass 15 outbox mocks, 15 SQL checks, 20-way lock contention and four blocked-expiry regressions. CI provisions PostgreSQL 17 and now includes desktop/mobile Chromium fixtures.
- Final CI-mode browser fixtures pass at 1440x900 and 390x900 with ten screenshots inspected. Release security review has no blockers; dependency audit reports zero vulnerabilities. No owned test containers/processes remain. Runtime release, hosted CI and live workflow/browser verification are next.
- External scheduler is implemented but not remotely activated. Repo-scoped Actions token and operational alert destination are still absent. Domain notification delivery needs Telegram credentials. Do not reuse the broad machine token or count simulated cadence as the required live 24-hour soak. Stored Domains findings remain authoritative even without notifications.

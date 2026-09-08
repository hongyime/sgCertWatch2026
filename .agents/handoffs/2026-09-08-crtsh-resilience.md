# crt.sh Resilience

User asks why crt.sh is degraded, whether URLs are correct, and for independently operating robust monitoring. Earlier push/main/deploy authorization remains; JWT rotation excluded.

Evidence:
- https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc supports identity and output=json on the root. Bare tokens use indexed text matching plus substring filtering, not the right-anchored behavior claimed in our comment. minNotBefore only constrains lint queries; do not invent a domain-search date filter.
- https://groups.google.com/g/crtsh/c/PsNhy2WVXhg is the operator's May 28, 2026 explanation of overloaded replicas, freezes and inefficient sorting.
- Two bounded local probes (root and identity=hong-yi.me with output=json, exclude=expired) returned HTML HTTP 404. Last verified successful primary Actions run 34180182808 had crt.sh HTTP 502. Provider failure is not a valid zero-result response.

Plan: remove immediate retry amplification and process-local breaker; persist next poll and failure count in existing crtsh state; enforce response-body deadline and size; retain successful observations while skipping polls; expose retry and last check accurately. Test restart, 404, 429/Retry-After, invalid body, body stalls, empty lists and recovery. Audit primary scheduler separately, then test, push, deploy and dispatch live validation.

Do not add keys, rotate JWT, use Vercel scanning, or mark unavailable crt.sh healthy to make the dashboard green.

## Verified Outcome

- Runtime `5d7e84c` is on main and deployed (`dpl_vorTJr2MUxJWSxNvfgQkKFHCbrp4`). Final data-validation CI run `34208305512` passes; both public aliases pass desktop/mobile read flows, favicon, console and layout checks.
- Live run `34206246005`: 47,269 entries checked, 2,152 findings saved; crt.sh root JSON query succeeded in about six seconds. Direct/static timeouts did not stop saved findings.
- Live resume `34207087100`: 27,797 checked, 1,074 findings saved; six direct logs successful; static rotation advanced beyond the previous first ten logs; crt.sh made zero requests and retained last-attempt/next-poll timestamps.
- Rotated static logs exposed 429 from Geomys and IPng plus a TrustAsia timeout. Added and regression-tested persisted operator cooldowns (at least one hour, longer Retry-After respected), skipping sibling logs and preserving unsaved cursors. This last addition was not followed by another live provider scan.
- Source deadlines cover response bodies, malformed tile framing cannot advance cursors, completed checkpoints precede optional notifications, failed stages are persisted, and primary availability excludes idle backups. Tests cover 29 static scenarios and seven runner recovery scenarios, plus crt.sh and existing suites.

## Remaining Limits

- GitHub cron is active but actual scheduled runs had a median 2h51m gap in the audited sample, with a maximum 12h26m. Offset `7,22,37,52` is only mitigation. Asked user about a free Cloudflare trigger; no answer/account integration yet. Any independent trigger should dispatch the existing workflow so its concurrency guard remains effective, not start a competing scanner.
- Database lock is advisory; GitHub workflow concurrency is the serialization boundary. Use an atomic owner-checked lock before introducing independent scanner processes.
- Optional Telegram delivery is bounded/best-effort, with no durable retry queue for unsent notifications. Stored Domains findings remain authoritative.

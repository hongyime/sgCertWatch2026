# crt.sh Resilience

User asks why crt.sh is degraded, whether URLs are correct, and for independently operating robust monitoring. Earlier push/main/deploy authorization remains; JWT rotation excluded.

Evidence:
- https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc supports identity and output=json on the root. Bare tokens use indexed text matching plus substring filtering, not the right-anchored behavior claimed in our comment. minNotBefore only constrains lint queries; do not invent a domain-search date filter.
- https://groups.google.com/g/crtsh/c/PsNhy2WVXhg is the operator's May 28, 2026 explanation of overloaded replicas, freezes and inefficient sorting.
- Two bounded local probes (root and identity=hong-yi.me with output=json, exclude=expired) returned HTML HTTP 404. Last verified successful primary Actions run 34180182808 had crt.sh HTTP 502. Provider failure is not a valid zero-result response.

Plan: remove immediate retry amplification and process-local breaker; persist next poll and failure count in existing crtsh state; enforce response-body deadline and size; retain successful observations while skipping polls; expose retry and last check accurately. Test restart, 404, 429/Retry-After, invalid body, body stalls, empty lists and recovery. Audit primary scheduler separately, then test, push, deploy and dispatch live validation.

Do not add keys, rotate JWT, use Vercel scanning, or mark unavailable crt.sh healthy to make the dashboard green.

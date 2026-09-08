# Free Intelligence Integration

User approved implementation and earlier main/deploy authorization remains active.

Scope: widen GitHub Actions CT polling; add OpenPhish (12h), URLhaus and ThreatFox (6h), and targeted urlscan search (3 domains/6h). Exclude PhishTank/Google Cloud. Store evidence independently, match exact certificate hosts, cap priority boost at 10 for CT scores >=60 and fresh strong evidence. Observed urlscan pages alone are not malicious verdicts. No automatic positive corpus updates.

Persist cooldowns before outbound calls; shared abuse.ch 429 pause at least 72h. All provider keys must remain in GitHub Actions secrets; never in committed files, public status or logs.

Parallel ownership: worker storage/API/schema; worker app/styles/index; primary adapters/runner/workflow/tests and end-to-end integration. Existing shared state modifications must be preserved. Production uses Supabase REST plus GitHub Actions ingest and capture; Vercel only serves dashboard/read APIs.

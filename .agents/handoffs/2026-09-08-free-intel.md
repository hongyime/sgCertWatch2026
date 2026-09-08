# Free Intelligence Integration

User approved implementation and earlier main/deploy authorization remains active.

Scope: widen GitHub Actions CT polling; add OpenPhish (12h), URLhaus and ThreatFox (6h), and targeted urlscan search (3 domains/6h). Exclude PhishTank/Google Cloud. Store evidence independently, match exact certificate hosts, cap priority boost at 10 for CT scores >=60 and fresh strong evidence. Observed urlscan pages alone are not malicious verdicts. No automatic positive corpus updates.

Persist cooldowns before outbound calls; shared abuse.ch 429 pause at least 72h. All provider keys must remain in GitHub Actions secrets; never in committed files, public status or logs.

Parallel ownership: worker storage/API/schema; worker app/styles/index; primary adapters/runner/workflow/tests and end-to-end integration. Existing shared state modifications must be preserved. Production uses Supabase REST plus GitHub Actions ingest and capture; Vercel only serves dashboard/read APIs.

Completed: code pushed to main and deployed; provider credentials configured only in Actions secrets. Both aliases passed desktop/mobile verification. All four intel providers passed live requests with zero matching evidence in the first candidate window; a replay skipped provider requests according to persisted next-poll times. Candidate selection is balanced between scores 60-69 and existing alerts.

Final CT budget: 6 direct logs x 128 entries, 30 static tiles/log, 90-second static fetch budget. Larger initial setting hit an 8-second database write timeout; fixed with 200-row CT write batches and 30-second background write limits. Public reads retain short deadlines. Retry run 34180182808 succeeded with 58,109 checked and 2,536 findings persisted. crt.sh backup alone returned 502; primary sources remain operational.

Final deployed code: 7ca21b6; Vercel deployment dpl_C6Hsseo9c3X1bSCKSNamXFUT1NNq. CI 34180169197 green. Verification scripts: test_intel.js, test_intel_storage.js, test_intel_ui.mjs, verify_live.mjs and verify_intel_db.mjs. The database verification uses a rolled-back transaction, leaving no synthetic evidence.

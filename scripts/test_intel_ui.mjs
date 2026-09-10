import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const root = new URL("../", import.meta.url);
const assets = new Set(["index.html", "app.js", "refresh.js", "styles.css", "favicon.svg", "watchlist.json", "keywords.json", "allowlist.json", "schemes.json"]);
const mime = { html: "text/html", js: "text/javascript", css: "text/css", json: "application/json", svg: "image/svg+xml" };
let streamFindings = false;
const pendingResponses = new Set();
const server = createServer(async (request, response) => {
  const name = new URL(request.url, "http://localhost").pathname.slice(1) || "index.html";
  if (name === "api/findings" && streamFindings) {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.write('{"findings":[');
    pendingResponses.add(response);
    response.once("close", () => pendingResponses.delete(response));
    return;
  }
  if (!assets.has(name)) return response.writeHead(404).end();
  try {
    const data = await readFile(new URL(name, root));
    response.writeHead(200, { "Content-Type": mime[name.split(".").pop()] }).end(data);
  } catch {
    response.writeHead(500).end();
  }
});

const now = Date.now();
const iso = (offset = 0) => new Date(now + offset).toISOString();
const scanId = "0e37e828-a9d9-45c0-ac50-1ca579b86c72";
const reportUrl = `https://urlscan.io/result/${scanId}/`;
const screenshotUrl = `https://urlscan.io/screenshots/${scanId}.png`;
const hostileText = '<img src="https://suspected.invalid/track" onerror="window.intelXss=1"> & "title"';
const longHost = `${"long-host-".repeat(6)}name.login.example.test`;
const evidence = [
  { source: "openphish", source_ref: "https://openphish.com/phishing_feeds.html", verdict: "phishing" },
  { source: "urlscan", source_ref: reportUrl, verdict: "observed", details: { title: hostileText, screenshot_url: screenshotUrl } },
  { source: "urlhaus", source_ref: "https://urlhaus.abuse.ch/url/123456/", verdict: "malware" },
  { source: "threatfox", source_ref: "https://threatfox.abuse.ch/ioc/123456/", verdict: "malware", details: { confidence: 90 } }
].map((item) => ({ domain: longHost, observed_at: iso(-3600000), expires_at: iso(86400000), ...item }));

function finding(registrable, score, extra = {}) {
  return {
    registrable, score, severity: score >= 90 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : "low",
    domains: [registrable], observed_at: iso(), sources: ["direct_ct"], source_count: 1,
    issuer: "Test issuer", signals: [{ type: "brand_exact", display: "Test brand", points: score }], ...extra
  };
}

const promoted = finding(longHost, 68, { domains: [longHost, `other.${longHost}`], intel_evidence: [...evidence, { ...evidence[1], domain: `other.${longHost}` }], intel_hit_count: 4, intel_priority_boost: 10, priority_score: 78 });
const ctOnly = finding("ct-only.example.test", 88);
const observedOnly = finding("observed.example.test", 68, {
  intel_evidence: [evidence[1]], intel_hit_count: 1, intel_priority_boost: 0, priority_score: 68
});
const baseline = finding("baseline.example.test", 75);
const low = finding("stored-low.example.test", 10);
const watchFindings = [promoted, baseline, ctOnly, observedOnly];
const allFindings = [...watchFindings, low];
const sourcePayload = {
  operations: { state: "completed", last_started_at: iso(-600000), last_success_at: iso(-420000),
    checked_at: iso(-420000), next_due_at: iso(300000), target_interval_minutes: 15,
    runtime_ms: 180000, duration_ms: 180000, freshness: "fresh", run_id: "test-run-123", trigger: "schedule" },
  schedule: { runner: "github-actions", cron: "7,22,37,52 * * * *", last_external_trigger_at: null },
  cursor_lag: { measured_logs: 0, lag_entries: null, max_lag_entries: null },
  health: "partial", display_sources: [
    { source: "direct_ct", ok: true, label: "Direct CT logs", checked_at: iso() },
    { source: "static_ct", ok: true, label: "Static CT logs", checked_at: iso(), scanned_entries: 100, details: { budget_exhausted: true, next_retry_at: iso(3600000) } },
    { source: "crtsh", ok: false, status: "cooldown", label: "crt.sh backup", checked_at: iso(-3600000), next_poll_at: iso(3600000),
      errors: [{ message: "crt.sh HTTP 502" }], details: { state: "cooldown", note: "Optional backup unavailable; direct and static CT polling continue independently." } }
  ],
  intel_schedule: { runner: "github-actions", cron: "7 * * * *", workflow: "intel.yml", script: "scripts/run-intel.mjs" },
  intel_sources: [
    { source: "openphish", status: "pending", ok: false, checked_at: null, last_checked_at: null, next_poll_at: null, details: { interval_hours: 12 } },
    { source: "urlscan", status: "not_configured", ok: false, checked_at: null, last_checked_at: null, next_poll_at: null, details: { interval_hours: 6 } },
    { source: "urlhaus", status: "cooldown", ok: false, checked_at: iso(-3600000), last_checked_at: iso(-3600000), next_poll_at: iso(3600000), details: { interval_hours: 6, note: hostileText } },
    { source: "threatfox", status: "stale", ok: false, checked_at: iso(-172800000), last_checked_at: iso(-172800000), next_poll_at: iso(-86400000), details: { interval_hours: 6 } }
  ]
};

async function checkLayout(page) {
  const problems = await page.evaluate(() => {
    const issues = [];
    if (document.documentElement.scrollWidth > innerWidth + 1) issues.push("Page overflows horizontally");
    const dialog = document.querySelector("dialog[open]");
    if (dialog && dialog.scrollWidth > dialog.clientWidth + 1) issues.push("Dialog overflows horizontally");
    const selectors = ".view.active .watch-card-head, .view.active .triage-toolbar, .view.active .source-row, .view.active .monitor-metrics, .view.active .monitor-metrics > div, .view.active .status-grid, .view.active .status-tile, dialog[open] .dialog-header, dialog[open] .evidence-heading, dialog[open] .evidence-links";
    for (const parent of document.querySelectorAll(selectors)) {
      const rects = [...parent.children].filter((child) => child.getClientRects().length).map((child) => child.getBoundingClientRect());
      for (let i = 0; i < rects.length; i++) {
        const a = rects[i];
        if (a.left < -1 || a.right > innerWidth + 1) issues.push(`${parent.className} child outside viewport`);
        for (const b of rects.slice(i + 1)) {
          if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1) {
            issues.push(`${parent.className} children overlap`);
          }
        }
      }
    }
    for (const element of document.querySelectorAll('.view.active .monitor-operations dd, .view.active .monitor-scheduler')) {
      if (element.scrollWidth > element.clientWidth + 1) issues.push("Monitor text overflows its container");
    }
    return issues;
  });
  assert.deepEqual(problems, []);
}

async function checkNoNotifications(page) {
  assert.equal(await page.locator('[id^="notification-"]').count(), 0);
  assert.doesNotMatch(await page.locator('[data-view-panel="monitor"]').innerText(), /notification|telegram|dead.letter|queue/i);
}

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
let browser;
const screenshots = await mkdtemp(join(tmpdir(), "sgcertwatch-intel-ui-"));
try {
  const isCi = Boolean(process.env.CI && !["false", "0"].includes(process.env.CI.toLowerCase()));
  const channel = isCi ? undefined : process.env.PLAYWRIGHT_CHANNEL || undefined;
  browser = await chromium.launch({ headless: true, channel });
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 900 } });
    const page = await context.newPage();
    await page.clock.install();
    const errors = [];
    const externalRequests = [];
    const notificationRequests = [];
    const requests = [];
    let currentFindings = allFindings;
    let currentHealth = sourcePayload;
    let failFindings = false;
    let failStatus = false;
    let failWatchlist = false;
    let statusRequests = 0;
    let holdWatch = false;
    let heldRoute;
    let notifyHeldWatch;
    const heldWatchReady = new Promise((resolve) => { notifyHeldWatch = resolve; });
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => {
      if (/notification|outbox|telegram/i.test(new URL(request.url()).pathname)) notificationRequests.push(request.url());
    });
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== base) {
        externalRequests.push(url.href);
        return route.abort();
      }
      if (url.pathname === "/api/findings") {
        requests.push(url);
        if (streamFindings) return route.continue();
        if (holdWatch && url.searchParams.get("view") === "watch") {
          heldRoute = route;
          notifyHeldWatch();
          return;
        }
        if (failFindings) return route.fulfill({ status: 503, body: "Unavailable" });
        const findings = url.searchParams.get("view") === "watch" ? watchFindings : currentFindings;
        return route.fulfill({ json: { storage_configured: true, findings } });
      }
      if (url.pathname === "/api/source-status") {
        statusRequests++;
        return failStatus ? route.fulfill({ status: 503, body: "Unavailable" }) : route.fulfill({ json: currentHealth });
      }
      if (url.pathname === "/watchlist.json" && failWatchlist) return route.fulfill({ status: 503, body: "Unavailable" });
      return route.continue();
    });
    const cards = page.locator("#finding-list [data-finding-index]");
    const dialog = page.locator("#finding-dialog");
    const waitForFeed = () => page.waitForFunction(() => document.getElementById("finding-list").getAttribute("aria-busy") === "false");
    const switchFilter = async (filter) => {
      await page.selectOption("#severity-filter", filter);
      await waitForFeed();
    };
    const displayedTime = (value) => page.evaluate((timestamp) => new Date(timestamp).toLocaleString("en-SG", {
      day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
    }), value);
    const reloadMonitor = async (payload) => {
      currentHealth = payload;
      await page.reload();
      await page.click('[data-view="monitor"]');
      await page.waitForFunction(() => document.getElementById("ct-scheduler").textContent !== "Checking");
    };

    await page.goto(base);
    await waitForFeed();
    await page.waitForFunction(() => document.getElementById("ct-scheduler").textContent !== "Checking");
    const beforeHidden = [requests.length, statusRequests];
    await page.evaluate(() => {
      window.testHidden = true;
      Object.defineProperty(document, "hidden", { configurable: true, get: () => window.testHidden });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.clock.fastForward(3600000);
    assert.deepEqual([requests.length, statusRequests], beforeHidden, "Hidden tabs make no scheduled API reads");
    const returnedFeed = page.waitForResponse((r) => r.url().includes("/api/findings?"));
    const returnedStatus = page.waitForResponse((r) => r.url().endsWith("/api/source-status"));
    await page.evaluate(() => { window.testHidden = false; document.dispatchEvent(new Event("visibilitychange")); });
    await Promise.all([returnedFeed, returnedStatus]);
    await waitForFeed();
    assert.deepEqual([requests.length, statusRequests], beforeHidden.map((n) => n + 1), "Returning refreshes both panels once");
    assert.equal(await page.locator('.view.active').getAttribute('data-view-panel'), "alerts");
    assert.equal(await page.locator('.view.active h2').first().innerText(), "Domains to watch now");
    assert.equal(await page.locator('.monitor-operations').isVisible(), false);
    assert.equal(requests[0].search, "?limit=50&view=watch");
    assert.deepEqual(await cards.locator(".watch-card-head strong").allTextContents(), [ctOnly.registrable, promoted.registrable, baseline.registrable]);
    assert.match(await cards.nth(1).innerText(), /CT MEDIUM 68/);
    assert.match(await cards.nth(1).innerText(), /CT score 68 \+ intel 10 = priority 78/);
    assert.match(await cards.nth(1).innerText(), /Promoted to Watch/);
    assert.match(await cards.nth(1).innerText(), /Intel hits: 4/);
    assert.equal(await cards.nth(1).locator(".intel-source-badge").count(), 4);
    assert.match(await cards.nth(0).innerText(), /Intel hits: 0/);
    await checkLayout(page);
    await page.screenshot({ path: join(screenshots, `domains-${width}.png`), fullPage: true });

    await cards.nth(1).focus();
    await page.keyboard.press("Enter");
    await dialog.waitFor({ state: "visible" });
    assert.equal(await dialog.locator(".severity").innerText(), "CT MEDIUM (68 PTS)");
    assert.equal(await dialog.locator(".evidence-row").count(), 5);
    assert.match(await dialog.innerText(), /Observed only; no phishing or malware verdict/);
    assert.ok((await dialog.innerText()).includes(hostileText));
    assert.equal(await dialog.locator(".evidence-links a").count(), 7);
    assert.equal(await dialog.locator("img, iframe, [onerror]").count(), 0);
    assert.deepEqual(await dialog.locator(".evidence-links a").evaluateAll((links) => links.map((link) => [link.target, link.rel, link.referrerPolicy])), Array(7).fill(["_blank", "noopener noreferrer", "no-referrer"]));
    await checkLayout(page);
    await page.screenshot({ path: join(screenshots, `evidence-${width}.png`) });
    await page.click("#close-dialog-btn");

    await switchFilter("");
    assert.equal(requests.at(-1).search, "?limit=50");
    assert.equal(await cards.count(), 5);
    await switchFilter("medium");
    assert.equal(requests.at(-1).search, "?limit=50");
    assert.equal(await cards.count(), 2);
    const observedCard = cards.filter({ hasText: observedOnly.registrable });
    assert.match(await observedCard.innerText(), /urlscan.io: observed/);
    assert.doesNotMatch(await observedCard.innerText(), /Promoted|phishing|malware/);
    await page.fill("#finding-search", "does-not-exist");
    assert.match(await page.locator("#feed-status").innerText(), /No matching stored findings/);
    await page.fill("#finding-search", "");

    // Reject redirects, spoofed hosts, credentials, ports, schemes, and payload paths.
    const rejected = [
      "javascript:alert(1)", "data:text/html,<script>window.intelXss=1</script>", "//urlscan.io/result/123/",
      reportUrl.replace("https:", "http:"), reportUrl.replace("urlscan.io", "urlscan.io.attacker.invalid"),
      reportUrl.replace("urlscan.io", "user@urlscan.io"), reportUrl.replace("urlscan.io", "urlscan.io:444"),
      `${reportUrl}?redirect=https://suspected.invalid`, `${reportUrl}#https://suspected.invalid`,
      "https://urlscan.io/redirect/https://suspected.invalid", `https://urlscan.io/result/%2f%2fsuspected.invalid/`,
      "https://suspected.invalid/screenshot.png", "https://urlscan.io\\@suspected.invalid/", `https://urlscan.io/screenshots/${scanId}.svg`,
      `${reportUrl}\n`, "https://urlscan.io/result/not-a-uuid/", 'https://urlscan.io/" onclick="window.intelXss=1'
    ];
    currentFindings = [finding("unsafe-evidence.example.test", 80, {
      intel_evidence: rejected.map((url) => ({ ...evidence[1], source_ref: url, details: { title: hostileText, screenshot_url: url } }))
        .concat([
          { ...evidence[0], source_ref: "https://openphish.com/redirect?url=https://suspected.invalid" },
          { ...evidence[2], source_ref: "https://urlhaus.abuse.ch/download/123456/" },
          { ...evidence[3], source_ref: "https://threatfox.abuse.ch.attacker.invalid/ioc/123456/" }
        ])
    })];
    await switchFilter("");
    assert.match(await cards.first().innerText(), /Intel hits: 4/, "Fallback count also counts distinct sources");
    await cards.first().click();
    assert.equal(await dialog.locator("a, img, iframe, [onerror]").count(), 0);
    assert.equal(await page.evaluate(() => window.intelXss), undefined);
    await checkLayout(page);
    await page.keyboard.press("Escape");

    await page.click('[data-view="monitor"]');
    await page.locator('[data-intel-source="threatfox"]').waitFor();
    assert.deepEqual(await page.locator("#intel-source-list strong").allTextContents(), ["pending", "unconfigured", "cooldown", "stale"]);
    assert.match(await page.locator("#intel-schedule").innerText(), /Hourly at :07 UTC.*GitHub Actions.*intel.yml/);
    assert.match(await page.locator('[data-intel-source="urlhaus"]').innerText(), /Last check:.*\nNext poll:.*\nProvider interval: 6 hr/);
    assert.match(await page.locator('[data-intel-source="openphish"]').innerText(), /Provider interval: 12 hr/);
    assert.match(await page.locator('[data-intel-source="urlscan"]').innerText(), /Next poll: Not scheduled/);
    assert.equal(await page.locator(".source-details").evaluate((el) => el.open), false);
    assert.equal(await page.locator("#source-status").innerText(), "Primary sources active");
    assert.equal(await page.locator("#ct-scheduler").innerText(), "GitHub Actions fallback; external trigger not observed");
    assert.match(await page.locator(".monitor-cadence").first().innerText(), /15-minute target, timing not guaranteed.*7,22,37,52/);
    assert.equal(await page.locator("#ct-last-start").innerText(), await displayedTime(sourcePayload.operations.last_started_at));
    assert.equal(await page.locator("#ct-last-success").innerText(), await displayedTime(sourcePayload.operations.last_success_at));
    assert.equal(await page.locator("#ct-next-due").innerText(), await displayedTime(sourcePayload.operations.next_due_at));
    assert.equal(await page.locator("#ct-runtime").innerText(), "3m 0s");
    assert.equal(await page.locator("#ct-run").innerText(), "test-run-123 / schedule");
    assert.equal(await page.locator("#ct-cursor-lag").innerText(), "Not measured");
    await checkNoNotifications(page);
    await page.locator(".source-details summary").click();
    assert.match(await page.locator("#source-list").innerText(), /crt\.sh backup\ncooldown\n.*HTTP 502/);
    assert.match(await page.locator("#source-list").innerText(), /Last check:.*\nNext attempt:/);
    assert.match(await page.locator("#source-list").innerText(), /Static CT logs\nbudget limited/);
    assert.match(await page.locator("#source-list").innerText(), /Paused logs retry after:/);
    assert.doesNotMatch(await page.locator("#source-list").innerText(), /OpenPhish|urlscan|URLhaus|ThreatFox/);
    assert.doesNotMatch(await page.locator("#intel-source-list").innerText(), /PhishTank|Google/);
    await checkLayout(page);
    await page.screenshot({ path: join(screenshots, `monitor-${width}.png`), fullPage: true });

    await page.click('[data-view="alerts"]');
    currentFindings = allFindings;
    holdWatch = true;
    await page.selectOption("#severity-filter", "watch");
    await heldWatchReady;
    assert.ok(heldRoute, "Watch request held for out-of-order response test");
    const cancelledWatch = page.waitForEvent("requestfailed", (request) => request.url().endsWith("&view=watch"));
    await switchFilter("");
    assert.match((await cancelledWatch).failure().errorText, /abort/i);
    await heldRoute.fulfill({ json: { storage_configured: true, findings: [promoted] } });
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await cards.count(), 5, "Older Watch response cannot replace All stored findings");
    holdWatch = false;

    failFindings = true;
    await switchFilter("high");
    assert.match(await page.locator("#finding-list").innerText(), /Could not load alerts/);
    assert.equal(await page.locator("#export-json-btn").isDisabled(), true);
    await page.fill("#finding-search", "ct");
    assert.match(await page.locator("#finding-list").innerText(), /Could not load alerts/);
    failFindings = false;
    await page.fill("#finding-search", "");
    await switchFilter("watch");
    assert.equal(await cards.count(), 3);

    holdWatch = true;
    const refreshReady = new Promise((resolve) => { notifyHeldWatch = resolve; });
    await page.clock.fastForward(120000);
    await refreshReady;
    await page.fill("#finding-search", "baseline");
    assert.equal(await cards.count(), 1, "Search remains usable during an automatic refresh");
    await cards.first().click();
    assert.equal(await dialog.locator("h2").innerText(), baseline.registrable);
    await page.click("#close-dialog-btn");
    await heldRoute.fulfill({ json: { storage_configured: true, findings: watchFindings } });
    await waitForFeed();
    holdWatch = false;
    await page.fill("#finding-search", "");

    for (const [runState, freshness, minutes, label] of [
      ["running", "fresh", 10, "Scan running"],
      ["running", "warning", 40, "Scan overdue (warning)"],
      ["running", "critical", 80, "Scan overdue (critical)"],
      ["completed", "warning", 40, "Scan overdue (warning)"],
      ["completed", "critical", 80, "Scan overdue (critical)"],
      ["failed", "critical", 120, "Scan failed"],
      ["running", "unknown", null, "Scan running"]
    ]) {
      const success = minutes === null ? null : iso(-minutes * 60000);
      await reloadMonitor({ ...sourcePayload,
        health: runState === "failed" ? "down" : ["warning", "critical"].includes(freshness) ? "stale"
          : freshness === "unknown" ? "pending" : "healthy",
        operations: { ...sourcePayload.operations, state: runState, freshness, last_success_at: success,
          last_started_at: iso(-60000), runtime_ms: runState === "running" ? 60000 : 180000 }
      });
      assert.equal(await page.locator("#source-status").innerText(), label);
      assert.equal(await page.locator("#ct-run-state").innerText(), runState[0].toUpperCase() + runState.slice(1));
      assert.equal(await page.locator("#ct-freshness").getAttribute("data-level"), freshness);
      assert.equal(await page.locator("#ct-last-success").innerText(), success ? await displayedTime(success) : "Not reported");
      assert.equal(await page.locator("#ct-runtime").innerText(), runState === "running" ? "1m 0s elapsed" : "3m 0s");
      if (minutes === null) assert.equal(await page.locator("#ct-freshness").innerText(), "No successful scan reported");
      await checkLayout(page);
      if (runState === "running" && freshness === "critical") {
        await page.screenshot({ path: join(screenshots, `monitor-running-stale-${width}.png`), fullPage: true });
      }
    }

    await reloadMonitor({ ...sourcePayload,
      schedule: { ...sourcePayload.schedule, last_external_trigger_at: iso(-86400000) },
      cursor_lag: { measured_logs: 2, lag_entries: 250, max_lag_entries: 250 },
      operations: { ...sourcePayload.operations, scheduler_trigger: "github", run_id: hostileText }
    });
    assert.equal(await page.locator("#ct-scheduler").innerText(), `GitHub Actions; external trigger observed ${await displayedTime(iso(-86400000))}`);
    assert.equal(await page.locator("#ct-cursor-lag").innerText(), "250 entries across 2 measured logs");
    assert.ok((await page.locator("#ct-run").innerText()).includes(hostileText));
    assert.equal(await page.locator(".monitor-operations img, .monitor-operations [onerror]").count(), 0);
    await checkLayout(page);
    await page.screenshot({ path: join(screenshots, `monitor-observed-${width}.png`), fullPage: true });

    await reloadMonitor({ ...sourcePayload, health: "healthy" });
    const monitoringWithoutNotifications = await page.locator(".monitor-operations").innerText();
    for (const notifications of [null, "malformed", {}, ...["partial", "failed", "unconfigured", "disabled"].map((state) => ({
      state, pending: 80, dead: 3, checked_at: iso(-259200000), oldest_pending_at: iso(-345600000),
      errors: [hostileText], payload: { token: "fake-secret-must-not-leak" }
    }))]) {
      await reloadMonitor({ ...sourcePayload, health: "healthy", notifications });
      await waitForFeed();
      assert.equal(await page.locator("#source-status").innerText(), "Monitoring active");
      assert.equal(await page.locator("#feed-health").innerText(), "Live database connected");
      assert.equal(await cards.count(), 3);
      assert.equal(await page.locator(".monitor-operations").innerText(), monitoringWithoutNotifications);
      assert.doesNotMatch(await page.locator("body").innerText(), /fake-secret-must-not-leak/);
      await checkNoNotifications(page);
      await checkLayout(page);
    }
    await page.screenshot({ path: join(screenshots, `monitor-legacy-notifications-${width}.png`), fullPage: true });

    currentHealth = { ...sourcePayload, health: "healthy", cursor_lag: { measured_logs: 1, lag_entries: 0 } };
    await page.clock.fastForward(60000);
    await page.locator("#ct-cursor-lag").filter({ hasText: "0 entries across 1 measured log" }).waitFor();
    assert.equal(await page.locator("#ct-cursor-lag").innerText(), "0 entries across 1 measured log");
    assert.equal(await page.locator("#source-status").innerText(), "Monitoring active");
    await checkNoNotifications(page);

    failStatus = true;
    await page.clock.fastForward(60000);
    await page.locator("#ct-scheduler").filter({ hasText: "Unavailable" }).waitFor();
    assert.equal(await page.locator("#ct-last-success").innerText(), "Not reported");
    assert.equal(await page.locator("#ct-runtime").innerText(), "Not reported");
    assert.equal(await page.locator("#ct-cursor-lag").innerText(), "Not measured");
    await checkNoNotifications(page);
    await checkLayout(page);
    failStatus = false;

    await reloadMonitor({ health: "down", display_sources: [{ source: "direct_ct", ok: true, status: "ok" }] });
    await page.locator("#source-status").filter({ hasText: "Scan failed" }).waitFor();
    await reloadMonitor({ health: "stale", display_sources: [{ source: "direct_ct", ok: false, status: "stale" }] });
    await page.locator("#source-status").filter({ hasText: "Scan overdue" }).waitFor();

    await reloadMonitor({});
    await page.locator('[data-intel-source="threatfox"]').waitFor();
    assert.deepEqual(await page.locator("#intel-source-list strong").allTextContents(), ["pending", "pending", "pending", "pending"]);
    assert.match(await page.locator("#intel-schedule").innerText(), /not reported/);
    assert.equal(await page.locator("#ct-scheduler").innerText(), "GitHub Actions fallback; external trigger not observed");
    assert.equal(await page.locator("#ct-last-start").innerText(), "Not reported");
    assert.equal(await page.locator("#ct-next-due").innerText(), "Not reported");
    assert.equal(await page.locator("#ct-freshness").innerText(), "No successful scan reported");
    await checkNoNotifications(page);
    await checkLayout(page);
    // A stalled body must expire too, then recover using the failure backoff.
    streamFindings = true;
    const streamingHeaders = page.waitForResponse((response) => response.url().includes("/api/findings?"));
    await page.reload();
    await streamingHeaders;
    await page.clock.fastForward(15000);
    await page.locator("#finding-list").filter({ hasText: "Could not load alerts" }).waitFor();
    assert.equal(await page.locator("#export-json-btn").isDisabled(), true);
    streamFindings = false;
    await page.clock.fastForward(240000);
    await waitForFeed();
    await cards.first().waitFor();
    assert.equal(await page.locator("#feed-health").innerText(), "Live database connected");

    // Static data failures must not prevent live feed or operational reads.
    failWatchlist = true;
    currentHealth = sourcePayload;
    await page.reload();
    await page.locator("#data-status").filter({ hasText: "Failed to load /watchlist.json" }).waitFor();
    await waitForFeed();
    await cards.first().waitFor();
    await page.waitForFunction(() => document.getElementById("ct-scheduler").textContent !== "Checking");
    assert.equal(await page.locator("#feed-health").innerText(), "Live database connected");
    assert.notEqual(await page.locator("#ct-last-success").innerText(), "Not reported");
    failWatchlist = false;
    assert.deepEqual(externalRequests, [], "Rendering never requests a suspected host or provider screenshot");
    assert.deepEqual(notificationRequests, [], "Monitoring never requests a notification worker or queue API");
    assert.deepEqual(errors, []);
    await context.close();
    console.log(`PASS intel UI at ${width}px: priority, filters, cancelled stale response, evidence safety, Monitor, hidden/return refresh, stalled body deadline/recovery, static-data failure isolation and layout`);
  }
  console.log(`Screenshots: ${screenshots}`);
} finally {
  await browser?.close();
  for (const response of pendingResponses) response.destroy();
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

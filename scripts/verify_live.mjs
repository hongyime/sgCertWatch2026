import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const urls = process.argv.slice(2);
if (!urls.length) urls.push("https://sgcertwatch.vercel.app", "https://sgcertwatch.hong-yi.me");
const screenshots = await mkdtemp(join(tmpdir(), "sgcertwatch-live-"));
const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
try {
  for (const base of urls) {
    const started = Date.now();
    const findingsResponse = await fetch(`${base}/api/findings?limit=50&view=watch`, { signal: AbortSignal.timeout(12000) });
    assert.equal(findingsResponse.status, 200);
    const payload = await findingsResponse.json();
    assert.equal(payload.storage_configured, true);
    assert.ok(payload.findings.every((row) => row.priority_score >= 70 && Array.isArray(row.intel_evidence)));
    const apiMs = Date.now() - started;
    const healthResponse = await fetch(`${base}/api/source-status`, { signal: AbortSignal.timeout(12000) });
    assert.equal(healthResponse.status, 200);
    const health = await healthResponse.json();
    assert.deepEqual(health.intel_sources.map((row) => row.source).sort(), ["openphish", "threatfox", "urlhaus", "urlscan"]);
    assert.equal(health.intel_schedule.runner, "github-actions");
    assert.equal(health.schedule.runner, "github-actions");
    assert.equal((await fetch(`${base}/favicon.svg`)).status, 200);
    for (const width of [1440, 390]) {
      const page = await browser.newPage({ viewport: { width, height: width === 390 ? 844 : 1000 } });
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
      await page.goto(base, { waitUntil: "networkidle" });
      await page.locator("#finding-list [data-finding-index]").first().waitFor({ timeout: 15000 });
      assert.equal(await page.locator("#severity-filter").inputValue(), "watch");
      assert.ok((await page.locator("#finding-list").innerText()).includes("Intel hits:"));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
      await page.screenshot({ path: join(screenshots, `${new URL(base).hostname}-domains-${width}.png`), fullPage: true });
      await page.locator("#finding-list [data-finding-index]").first().click();
      assert.equal(await page.locator("#finding-dialog").isVisible(), true);
      assert.ok((await page.locator("#finding-dialog").innerText()).includes("Intel evidence"));
      await page.locator("#close-dialog-btn").click();
      await page.click('[data-view="monitor"]');
      assert.equal(await page.locator("[data-intel-source]").count(), 4);
      assert.ok((await page.locator("#intel-schedule").innerText()).includes("GitHub Actions"));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
      await page.screenshot({ path: join(screenshots, `${new URL(base).hostname}-monitor-${width}.png`), fullPage: true });
      await page.click('[data-view="watch"]');
      assert.equal(await page.locator("#search").isVisible(), true);
      await page.click('[data-view="alerts"]');
      await Promise.all([
        page.waitForResponse((response) => response.url().endsWith("/api/findings?limit=50")),
        page.selectOption("#severity-filter", "")
      ]);
      assert.equal(await page.locator("#finding-list [data-finding-index]").count() > 0, true);
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log(JSON.stringify({ url: base, findings: payload.findings.length, findings_api_ms: apiMs,
      intel_hits: payload.findings.reduce((count, row) => count + row.intel_hit_count, 0),
      ct_health: health.health, sources: health.intel_sources.map(({ source, status, scanned_entries, matched }) => ({ source, status, scanned_entries, matched })) }));
  }
  console.log(`Screenshots: ${screenshots}`);
} finally {
  await browser.close();
}

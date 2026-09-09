import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("retired notification CLI cannot send or retry even with old credentials", () => {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
    globalThis.fetch = () => { throw new Error('No network permitted'); };
    process.argv = [process.execPath, process.cwd() + '/scripts/run-notifications.mjs', 'retry', 'old-job'];
    await import('./scripts/run-notifications.mjs');
  `], { encoding: "utf8", timeout: 15000, env: { ...process.env,
    TELEGRAM_BOT_TOKEN: "retired-test-token", TELEGRAM_CHAT_ID: "123",
    SUPABASE_URL: "https://unused.example.test", SUPABASE_SERVICE_ROLE_KEY: "unused-test-key" } });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).state, "retired");
});

test("retired workflow has no automatic triggers, secrets or queue runner", () => {
  const workflow = readFileSync(new URL("../.github/workflows/notifications.yml", import.meta.url), "utf8");
  assert.doesNotMatch(workflow, /schedule:|workflow_run:|secrets\.|run-notifications/);
  const ingest = readFileSync(new URL("../scripts/run-ingest.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(ingest, /TELEGRAM_|notification-outbox|notification_enqueue/);
});

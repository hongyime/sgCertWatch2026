/**
 * Reviewer UI coverage recovered from stash 588445aa and adapted to the current
 * inline sign-in form. Auth replies are synthetic; this tests browser behavior.
 * Run: node --test scripts/test_reviewer_ui.mjs
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { chromium } from "playwright";
import { start } from "./workbench-fixture.mjs";

let browser;
let fixture;

before(async () => {
  fixture = await start();
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  await fixture?.close();
});

async function openPage(t) {
  const context = await browser.newContext();
  t.after(() => context.close());
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  await page.goto(fixture.url);
  // Import completion includes app.js registering its handlers/session callback.
  await page.evaluate(async () => { await import('/app.js'); });
  await page.waitForSelector('#reviewer-signin-btn:not([hidden])');
  return page;
}

async function openForm(page) {
  await page.click('#reviewer-signin-btn');
  await page.waitForSelector('#reviewer-signin-form:not([hidden])');
}

async function submit(page, email = 'reviewer@test.local', password = 'correct-horse-battery') {
  await page.fill('#reviewer-email', email);
  await page.fill('#reviewer-password', password);
  await page.click('#reviewer-signin-form button[type=submit]');
}

async function signIn(page) {
  await openForm(page);
  await submit(page);
  await page.waitForSelector('#reviewer-signed-in:not([hidden])');
}

test('T1: sign-in is visible and sign-out is hidden initially', async (t) => {
  const page = await openPage(t);
  assert.ok(await page.locator('#reviewer-signin-btn').isVisible());
  assert.ok(await page.locator('#reviewer-signout-btn').isHidden());
  assert.ok(await page.locator('#reviewer-signin-form').isHidden());
});

test('T2: clicking Sign in opens the current inline form', async (t) => {
  const page = await openPage(t);
  await openForm(page);
  assert.ok(await page.locator('#reviewer-email').isVisible());
  assert.ok(await page.locator('#reviewer-password').isVisible());
});

test('T3: successful sign-in hides the form and shows sign-out', async (t) => {
  const page = await openPage(t);
  await signIn(page);
  assert.ok(await page.locator('#reviewer-signin-form').isHidden());
  assert.ok(await page.locator('#reviewer-signin-btn').isHidden());
  assert.ok(await page.locator('#reviewer-signout-btn').isVisible());
});

test('T4: credentials remain out of browser storage and password input clears', async (t) => {
  const page = await openPage(t);
  await signIn(page);
  const stored = await page.evaluate(() => ({
    local: { ...localStorage },
    session: { ...sessionStorage },
    cookies: document.cookie,
  }));
  assert.doesNotMatch(JSON.stringify(stored), /fixture-reviewer-token|correct-horse-battery/);
  for (const keys of [Object.keys(stored.local), Object.keys(stored.session)]) {
    assert.ok(keys.every((key) => !/token|password/i.test(key)));
  }
  assert.equal(await page.locator('#reviewer-password').inputValue(), '');
});

test('T5: sign-out restores the signed-out UI', async (t) => {
  const page = await openPage(t);
  await signIn(page);
  await page.click('#reviewer-signout-btn');
  await page.waitForSelector('#reviewer-signin-btn:not([hidden])');
  assert.ok(await page.locator('#reviewer-signout-btn').isHidden());
});

test('T6: invalid credentials keep the form open and clear the password', async (t) => {
  const page = await openPage(t);
  await openForm(page);
  await submit(page, 'bad@test.local', 'wrong-password');
  await page.waitForFunction(() => document.getElementById('reviewer-signin-error').textContent.length > 0);
  assert.match(await page.locator('#reviewer-signin-error').textContent(), /Incorrect email or password/i);
  assert.ok(await page.locator('#reviewer-signin-form').isVisible());
  assert.ok(await page.locator('#reviewer-signout-btn').isHidden());
  assert.equal(await page.locator('#reviewer-password').inputValue(), '');
});

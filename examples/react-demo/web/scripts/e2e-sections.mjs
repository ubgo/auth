// Drives /account-sections headless against the running demo (DEMO_URL, run
// after e2e.mjs by task ui:e2e): two account sections used on their own, and
// the app's own password form re-authenticating through useReauth once the
// session is older than the short fresh window with-servers.sh sets. Fails on
// the first step that does not behave; screenshots land in .shots/e2e/.

import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

const BASE = process.env.DEMO_URL ?? "http://localhost:5180"
const OUT = new URL("../.shots/e2e/", import.meta.url).pathname
const USER = { identifier: "ada@example.com", password: "correct horse battery staple" }
const NEW_PASSWORD = "a different horse battery staple"
const FRESH_WINDOW_MS = parseDuration(process.env.DEMO_FRESH_WINDOW ?? "8s")
function parseDuration(v) {
  const m = /^(\d+)(ms|s)$/.exec(v)
  if (m === null) throw new Error(`DEMO_FRESH_WINDOW=${v}: the e2e reads only ms or s`)
  return Number(m[1]) * (m[2] === "s" ? 1000 : 1)
}

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } })
// A second browser signed in as the same user, so Sessions has another device.
const other = await browser.newPage()
let step = 0
async function check(name, fn) {
  step++
  try {
    await fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    console.log(`  FAIL ${name}: ${err.message.split("\n")[0]}`)
    await page.screenshot({ path: `${OUT}sections-${String(step).padStart(2, "0")}-FAIL.png` })
    await browser.close()
    process.exit(1)
  }
  await page.screenshot({ path: `${OUT}sections-${String(step).padStart(2, "0")}-${name.replace(/\W+/g, "-")}.png` })
}
const expectVisible = (locator) => locator.waitFor({ state: "visible", timeout: 5000 })

async function signIn(p) {
  await p.goto(`${BASE}/sign-in?redirectTo=/account-sections`)
  await p.getByLabel("Email").fill(USER.identifier)
  await p.getByLabel("Password").fill(USER.password)
  await p.getByRole("button", { name: "Sign in", exact: true }).click()
  await p.waitForURL(`${BASE}/account-sections`, { timeout: 5000 })
}

await check("ProfileSection and SessionsSection render on their own", async () => {
  await signIn(page)
  await expectVisible(page.getByRole("heading", { name: "Profile", level: 2 }))
  await expectVisible(page.getByRole("heading", { name: "Sessions", level: 2 }))
  // Only the sections the page chose: no Email or Delete card from AccountSettings.
  const extra = await page.getByRole("heading", { name: /^(Email|Delete account)$/ }).count()
  if (extra !== 0) throw new Error(`${extra} sections the page did not render are on it`)
})

await check("a second browser shows up in SessionsSection", async () => {
  await signIn(other)
  await page.reload()
  await expectVisible(page.getByRole("button", { name: "Sign out of all other sessions" }))
})

await check("a stale session: the app's own form opens the kit's re-auth dialog (useReauth)", async () => {
  await page.waitForTimeout(FRESH_WINDOW_MS + 1000)
  await page.getByLabel("Current password").fill(USER.password)
  await page.getByLabel("New password").fill(NEW_PASSWORD)
  await page.getByRole("button", { name: "Change password" }).click()
  await expectVisible(page.getByRole("dialog").getByRole("heading", { name: "Confirm it's you" }))
})

await check("confirming the password reruns the change and SESSIONS_QUERY_KEY refreshes the list", async () => {
  await page.getByRole("dialog").getByLabel("Password").fill(USER.password)
  await page.getByRole("dialog").getByRole("button", { name: "Continue" }).click()
  await expectVisible(page.getByText("Password changed. Other devices are signed out."))
  await expectVisible(page.getByText("You are signed in only on this device."))
})

await browser.close()
console.log(`account-sections: all ${step} steps passed`)

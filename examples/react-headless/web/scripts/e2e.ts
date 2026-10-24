// Drives the page headless (Playwright's Chromium) against the throwaway
// servers scripts/with-servers.sh starts, and fails on the first step that
// does not behave. Each step names the hook it proves. A failed step leaves
// a screenshot in the system's temporary directory and prints its path.
//
//   ./scripts/with-servers.sh node scripts/e2e.ts      (task ui:headless)

import { tmpdir } from "node:os"
import { join } from "node:path"
import { chromium, type Locator } from "playwright"

/** The page under test: HEADLESS_URL, which with-servers.sh sets, or its default web port. */
const BASE = process.env.HEADLESS_URL ?? "http://localhost:5190"
/** The user the React demo's server seeds (examples/react-demo/seed.go). */
const USER = { identifier: "ada@example.com", password: "correct horse battery staple", name: "Ada Lovelace" }
/** The pretend provider's account the OAuth step picks (examples/react-demo/devoauth.go). */
const OAUTH_USER = "Grace Hopper"
/** The name the profile step sets, then changes back, so later steps see the seeded one. */
const RENAMED = "Ada King"
/** The page's own wording for password.invalid_credentials (LOCALIZATION in src/app.tsx). */
const LOCALIZED_INVALID = "That email and password do not match."
/** How long a step waits for the page; the servers are local, so this is generous. */
const STEP_TIMEOUT_MS = 5_000

const browser = await chromium.launch({ headless: true })
const page = await browser.newPage({ viewport: { width: 1024, height: 768 } })
let step = 0

/** Runs one step, printing `ok` or `FAIL` with its name; a failure exits non-zero. */
async function check(name: string, fn: () => Promise<void>): Promise<void> {
  step++
  try {
    await fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    const shot = join(tmpdir(), `react-headless-${String(step).padStart(2, "0")}-FAIL.png`)
    await page.screenshot({ path: shot })
    console.log(`  FAIL ${name}: ${err instanceof Error ? err.message.split("\n")[0] : String(err)} (screenshot ${shot})`)
    await browser.close()
    process.exit(1)
  }
}

const visible = (locator: Locator) => locator.waitFor({ state: "visible", timeout: STEP_TIMEOUT_MS })
const signInHeading = () => page.getByRole("heading", { name: "Sign in", level: 2 })

await check("SignedOut renders the app's own form, the server's providers and the passkey check", async () => {
  await page.goto(`${BASE}/`)
  await visible(signInHeading())
  await visible(page.getByRole("link", { name: "Continue with Demo provider" }))
  await visible(page.getByRole("heading", { name: "Email me a link" }))
  const passkeys = (await page.getByText(/passkey/).innerText()).trim()
  console.log(`       supportsPasskeys: ${JSON.stringify(passkeys)}`)
})

await check("a wrong password shows the provider's localized message (useErrorMessage)", async () => {
  await page.getByLabel("Email", { exact: true }).fill(USER.identifier)
  await page.getByLabel("Password").fill("not the password")
  await page.getByRole("button", { name: "Sign in" }).click()
  const alert = page.getByRole("alert")
  await visible(alert)
  const text = (await alert.innerText()).trim()
  if (text !== LOCALIZED_INVALID) throw new Error(`alert says ${JSON.stringify(text)}`)
  console.log(`       message: ${JSON.stringify(text)}`)
})

await check("the right password signs in and SignedIn shows useSession's user", async () => {
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in" }).click()
  await visible(page.getByRole("heading", { name: `Signed in as ${USER.name}` }))
})

await check("a profile change of the app's own shows after invalidating SESSION_QUERY_KEY", async () => {
  for (const name of [RENAMED, USER.name]) {
    await page.getByLabel("New name").fill(name)
    await page.getByRole("button", { name: "Rename" }).click()
    await visible(page.getByRole("heading", { name: `Signed in as ${name}` }))
  }
})

await check("signOut({ redirectTo: null }) stays on the page and SignedOut comes back", async () => {
  const before = page.url()
  await page.getByRole("button", { name: "Sign out", exact: true }).click()
  await visible(signInHeading())
  if (page.url() !== before) throw new Error(`navigated to ${page.url()}`)
})

await check("usePluginClient('magiclink') sends a link", async () => {
  await page.getByLabel("Email for the link").fill(USER.identifier)
  await page.getByRole("button", { name: "Send the link" }).click()
  await visible(page.getByText("Check your email for a sign-in link."))
})

await check("oauthStartURL is a page navigation that signs in through the provider", async () => {
  await page.getByRole("link", { name: "Continue with Demo provider" }).click()
  await visible(page.getByRole("heading", { name: "Demo provider" }))
  await page.getByRole("button", { name: new RegExp(OAUTH_USER) }).click()
  await page.waitForURL(`${BASE}/`, { timeout: STEP_TIMEOUT_MS })
  await visible(page.getByRole("heading", { name: `Signed in as ${OAUTH_USER}` }))
})

await check("signOut({ everywhere: true }) goes to the custom paths.afterSignOut", async () => {
  await page.getByRole("button", { name: "Sign out everywhere" }).click()
  await page.waitForURL(`${BASE}/?signed-out`, { timeout: STEP_TIMEOUT_MS })
  await visible(page.getByText("You were signed out on every device."))
  await visible(signInHeading())
})

await browser.close()
console.log(`react-headless: all ${step} steps passed`)

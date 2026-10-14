// Drives the app headless (Playwright's Chromium) against the throwaway
// servers scripts/with-servers.sh starts, and fails on the first step that
// does not behave. Every navigation the kit makes must stay client-side: a
// marker set on the page's global object after the first load must survive each step, because
// a full page load would wipe it. A failed step leaves a screenshot in the
// system's temporary directory and prints its path.
//
//   ./scripts/with-servers.sh node scripts/e2e.ts      (task ui:router)

import { tmpdir } from "node:os"
import { join } from "node:path"
import { chromium, type Locator } from "playwright"

/** The app under test: RR_URL, which with-servers.sh sets, or its default web port. */
const BASE = process.env.RR_URL ?? "http://localhost:5200"
/** The user the React demo's server seeds (examples/react-demo/seed.go). */
const USER = { identifier: "ada@example.com", password: "correct horse battery staple", name: "Ada Lovelace" }
/** How long a step waits for the page; the servers are local, so this is generous. */
const STEP_TIMEOUT_MS = 5_000
/** The window property that proves no full page load happened since it was set. */
const MARKER = "ubgoNoReload"

/** What the demo server's GET /dev/mail answers (examples/react-demo/devmail.go). */
type DevMail = { readonly messages: readonly { readonly to: string; readonly links: readonly string[] }[] }

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
    const shot = join(tmpdir(), `react-router-app-${String(step).padStart(2, "0")}-FAIL.png`)
    await page.screenshot({ path: shot })
    console.log(`  FAIL ${name}: ${err instanceof Error ? err.message.split("\n")[0] : String(err)} (screenshot ${shot})`)
    await browser.close()
    process.exit(1)
  }
}

const visible = (locator: Locator) => locator.waitFor({ state: "visible", timeout: STEP_TIMEOUT_MS })
const atPath = (path: string) => page.waitForURL((url) => `${url.pathname}${url.search}` === path, { timeout: STEP_TIMEOUT_MS })
const markSPA = () => page.evaluate((key) => Reflect.set(globalThis, key, true), MARKER)
async function stillSPA(): Promise<void> {
  if (!(await page.evaluate((key) => Reflect.get(globalThis, key) === true, MARKER))) throw new Error("the page was reloaded")
}

await check("signed out, the home page links to paths.signIn through the router's Link", async () => {
  await page.goto(`${BASE}/`)
  await visible(page.getByText("You are signed out."))
  await markSPA()
  await page.getByRole("link", { name: "Sign in" }).click()
  await atPath("/sign-in")
  await visible(page.getByRole("heading", { name: "Sign in" }))
  await stillSPA()
})

await check("the guarded /account sends a signed-out visitor to /sign-in?redirectTo=%2Faccount", async () => {
  await page.getByRole("link", { name: "Account" }).click()
  await atPath("/sign-in?redirectTo=%2Faccount")
  await stillSPA()
})

await check("signing in comes back to /account through the provider's navigate", async () => {
  await page.getByLabel("Email", { exact: true }).fill(USER.identifier)
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in" }).click()
  await atPath("/account")
  await visible(page.getByRole("heading", { name: USER.name }))
  await stillSPA()
})

await check("the header's Home link keeps the session without a reload", async () => {
  await page.getByRole("link", { name: "Home" }).click()
  await atPath("/")
  await visible(page.getByText(`Signed in as ${USER.name}.`))
  await stillSPA()
})

await check("signOut() lands on paths.afterSignOut (/sign-in) through the router", async () => {
  await page.getByRole("link", { name: "Account" }).click()
  await page.getByRole("button", { name: "Sign out" }).click()
  await atPath("/sign-in")
  await stillSPA()
  await page.getByRole("link", { name: "Account" }).click()
  await atPath("/sign-in?redirectTo=%2Faccount")
})

await check("a mailed magic link opens /magic-link, which reads the token from the router's search params", async () => {
  await page.getByLabel("Email for the link").fill(USER.identifier)
  await page.getByRole("button", { name: "Send the link" }).click()
  await visible(page.getByText("Check your email for a sign-in link."))
  const mail: DevMail = await (await page.request.get(`${BASE}/dev/mail`)).json()
  const link = mail.messages.find((m) => m.to === USER.identifier)?.links.find((l) => new URL(l).pathname === "/magic-link")
  if (link === undefined) throw new Error("no magic link in the inbox")
  console.log(`       link: ${link.replace(/token=[^&]+/, "token=…")}`)
  await page.goto(link)
  await page.getByRole("button", { name: "Sign me in" }).click()
  await atPath("/")
  await visible(page.getByText(`Signed in as ${USER.name}.`))
})

await browser.close()
console.log(`react-router-app: all ${step} steps passed`)

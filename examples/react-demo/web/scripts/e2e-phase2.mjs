// Drives the second batch of screens headless against the running demo:
// the required two-factor setup (session task) finished with a security key,
// the security-key answer on the challenge, organization domains with a
// suggestion, request and approval, and the admin page's address and
// metadata. Chromium's virtual authenticator (CDP WebAuthn) stands in for
// the key. Fails on the first step that does not behave; screenshots in
// .shots/e2e-phase2/.

import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

const BASE = process.env.DEMO_URL ?? "http://localhost:5180"
const OUT = new URL("../.shots/e2e-phase2/", import.meta.url).pathname
const PASSWORD = "correct horse battery staple"
const ADMIN = { email: "ada@example.com", name: "Ada Lovelace" }
const OTHER = { email: "linus@example.com", name: "Linus Pauling" }
const MFA = { email: "mfa@example.com", name: "Grace Required" }

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const ctxA = await browser.newContext({ viewport: { width: 1280, height: 900 } })
const ctxB = await browser.newContext({ viewport: { width: 1280, height: 900 } })
const page = await ctxA.newPage()
const other = await ctxB.newPage()
const cdp = await ctxA.newCDPSession(page)
await cdp.send("WebAuthn.enable")
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "usb", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
})

let step = 0
let shotPage = page
async function check(name, fn) {
  step++
  try {
    await fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    console.log(`  FAIL ${name}: ${err.message.split("\n")[0]}`)
    await shotPage.screenshot({ path: `${OUT}${String(step).padStart(2, "0")}-FAIL.png`, fullPage: true })
    await browser.close()
    process.exit(1)
  }
  await shotPage.screenshot({ path: `${OUT}${String(step).padStart(2, "0")}-${name.replace(/\W+/g, "-")}.png`, fullPage: true })
}
/**
 * Screenshots the page as it is now in light and dark at 1280 and 390 wide,
 * and fails when the page scrolls sideways at 390. Dark is the demo's class
 * on <html>, set directly so the step does not depend on the theme switch.
 */
async function variants(p, name) {
  const original = p.viewportSize()
  for (const dark of [false, true]) {
    await p.evaluate((on) => document.documentElement.classList.toggle("dark", on), dark)
    for (const width of [1280, 390]) {
      await p.setViewportSize({ width, height: 900 })
      await p.waitForTimeout(250)
      if (width === 390) {
        const overflow = await p.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
        if (overflow > 0) throw new Error(`${name} scrolls sideways by ${overflow}px at 390 wide${dark ? " (dark)" : ""}`)
      }
      await p.screenshot({ path: `${OUT}${name}-${dark ? "dark" : "light"}-${width}.png`, fullPage: true })
    }
  }
  await p.evaluate(() => document.documentElement.classList.remove("dark"))
  await p.setViewportSize(original)
}
const visible = (l) => l.waitFor({ state: "visible", timeout: 6000 })
const stage = (p) => p.getByRole("region", { name: "Live component" })

async function signIn(p, email, redirectTo = "/") {
  await p.goto(`${BASE}/sign-in?redirectTo=${encodeURIComponent(redirectTo)}`)
  await p.getByLabel("Email").fill(email)
  await p.getByLabel("Password").fill(PASSWORD)
  await p.getByRole("button", { name: "Sign in", exact: true }).click()
}
async function signOut(p, name) {
  await p.getByRole("banner").getByRole("button", { name: new RegExp(name) }).click()
  await p.getByRole("menuitem", { name: "Sign out" }).click()
  await p.waitForURL(/\/sign-in/, { timeout: 5000 })
}

await check("a user who must set up two-factor lands on the setup page", async () => {
  await signIn(page, MFA.email, "/account")
  await page.waitForURL(`${BASE}/setup-two-factor`, { timeout: 6000 })
  await visible(stage(page).getByText("Your account needs a second factor before you can continue."))
  await visible(stage(page).getByRole("heading", { name: "Security keys" }))
  await variants(page, "v-task-setup")
})

await check("any other page sends them back while the task is open", async () => {
  await page.goto(`${BASE}/organizations`)
  await page.waitForURL(`${BASE}/setup-two-factor`, { timeout: 6000 })
  const session = await (await page.request.get(`${BASE}/auth/session`)).json()
  if (!session.tasks?.includes("setup-mfa")) throw new Error(`session tasks ${JSON.stringify(session.tasks)}`)
})

await check("adding a security key finishes the task with codes, then goes on", async () => {
  await stage(page).getByLabel("Name").fill("Desk key")
  await stage(page).getByRole("button", { name: "Add a security key" }).click()
  // The first factor's recovery codes show once, and the page waits for them to be saved.
  await visible(stage(page).getByText("Save your recovery codes"))
  if (!page.url().endsWith("/setup-two-factor")) throw new Error(`left the page before the codes were saved: ${page.url()}`)
  await stage(page).getByRole("button", { name: "I saved them" }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 8000 })
  const session = await (await page.request.get(`${BASE}/auth/session`)).json()
  if ((session.tasks ?? []).length !== 0) throw new Error(`tasks left: ${JSON.stringify(session.tasks)}`)
})

await check("signing in again asks for the key, which finishes the sign-in", async () => {
  await signOut(page, MFA.name)
  await signIn(page, MFA.email)
  await page.waitForURL(/\/two-factor/, { timeout: 6000 })
  await visible(page.getByText("Use your security key to finish signing in."))
  await variants(page, "v-challenge-key")
  await page.getByRole("button", { name: "Use a security key" }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 8000 })
  await visible(page.getByRole("heading", { name: `Hello, ${MFA.name}` }))
})

await check("the admin adds and verifies a domain for a new organization", async () => {
  await signOut(page, MFA.name)
  await signIn(page, ADMIN.email, "/organizations")
  await page.waitForURL(`${BASE}/organizations`, { timeout: 6000 })
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitem", { name: "Create organization" }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByLabel("Name").fill("Example Corp")
  await dialog.getByRole("button", { name: "Create", exact: true }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
  await visible(stage(page).getByRole("heading", { name: "Domains" }))
  await stage(page).getByPlaceholder("example.com", { exact: true }).fill("example.com")
  await stage(page).getByRole("button", { name: "Add", exact: true }).click()
  // Ada holds a verified address there, so the demo verifies it without DNS.
  const verify = stage(page).getByRole("button", { name: "Verify", exact: true })
  if (await verify.isVisible().catch(() => false)) {
    await verify.click()
    await visible(stage(page).getByText("example.com is verified."))
  }
  await visible(stage(page).getByText("Verified", { exact: true }))
})

await check("the domain is set to suggest joining", async () => {
  await stage(page).getByRole("button", { name: /^Enrollment:/ }).click()
  await page.getByRole("menuitemradio", { name: "Suggest joining" }).click()
  await visible(stage(page).getByRole("button", { name: "Enrollment: Suggest joining" }))
  await variants(page, "v-domains")
})

await check("a user with an address there sees the suggestion and asks to join", async () => {
  shotPage = other
  await signIn(other, OTHER.email, "/invitations")
  await other.waitForURL(`${BASE}/invitations`, { timeout: 6000 })
  await visible(stage(other).getByText("Example Corp"))
  await variants(other, "v-suggestions")
  await stage(other).getByRole("button", { name: "Request to join Example Corp" }).click()
  await visible(stage(other).getByText("Requested", { exact: true }))
  shotPage = page
})

await check("the admin approves the request and the user is a member", async () => {
  await page.reload()
  await visible(stage(page).getByRole("button", { name: `Approve ${OTHER.name}'s request` }))
  await stage(page).getByRole("button", { name: `Approve ${OTHER.name}'s request` }).click()
  await visible(stage(page).getByRole("listitem").filter({ hasText: OTHER.name }).getByText("member"))
})

await check("the admin page shows the user's address and public metadata", async () => {
  await page.goto(`${BASE}/admin`)
  await page.getByLabel("Search users").fill("linus")
  await visible(page.getByText("1–1 of 1", { exact: true }))
  await visible(stage(page).getByRole("table").getByText(OTHER.email))
  await page.getByRole("link", { name: `Open ${OTHER.name}` }).click()
  await visible(stage(page).getByRole("heading", { name: "Metadata" }))
  await visible(stage(page).getByText('"plan": "pro"', { exact: false }))
  await variants(page, "v-admin-detail")
})

await check("the security keys section lists the key and removes it with a key tap as proof", async () => {
  await signOut(page, ADMIN.name)
  await signIn(page, MFA.email)
  await page.waitForURL(/\/two-factor/, { timeout: 6000 })
  await page.getByRole("button", { name: "Use a security key" }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 8000 })
  await page.goto(`${BASE}/two-factor/setup`)
  await visible(stage(page).getByText("Desk key"))
  await variants(page, "v-setup-keys")
  await stage(page).getByRole("button", { name: "Remove Desk key" }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("button", { name: "Use a security key instead" }).click()
  await visible(stage(page).getByText("Security key removed."))
  await visible(stage(page).getByText("No security keys yet."))
})

await browser.close()
console.log("phase 2 screens: every step passed")

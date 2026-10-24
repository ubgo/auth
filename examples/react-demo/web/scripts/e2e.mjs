// Drives the sign-in flows headless against the running demo (Vite on
// DEMO_URL, the Go API behind its proxy) and fails on the first step that
// does not behave. Uses the demo user the server seeds. Screenshots of
// each step land in .shots/e2e/ for a person to look at.

import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

import { AUTH_ERROR_CODES } from "../../../../clients/ts/src/error-codes.ts"

// The message the form must show: the code's declared English message, which
// the server sends and the form passes through.
const INVALID_CREDENTIALS = AUTH_ERROR_CODES["password.invalid_credentials"].message

const BASE = process.env.DEMO_URL ?? "http://localhost:5180"
const OUT = new URL("../.shots/e2e/", import.meta.url).pathname
const USER = { identifier: "ada@example.com", password: "correct horse battery staple", name: "Ada Lovelace" }

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const page = await browser.newPage({ viewport: { width: 1280, height: 800 } })
let step = 0
async function check(name, fn) {
  step++
  try {
    await fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    console.log(`  FAIL ${name}: ${err.message.split("\n")[0]}`)
    await page.screenshot({ path: `${OUT}${String(step).padStart(2, "0")}-FAIL.png` })
    await browser.close()
    process.exit(1)
  }
  await page.screenshot({ path: `${OUT}${String(step).padStart(2, "0")}-${name.replace(/\W+/g, "-")}.png` })
}
const expectVisible = (locator) => locator.waitFor({ state: "visible", timeout: 5000 })

await check("sign-in page shows every enabled method", async () => {
  await page.goto(`${BASE}/sign-in`)
  await expectVisible(page.getByRole("heading", { name: "Sign in", level: 2 }))
  await expectVisible(page.getByRole("button", { name: "Continue with Demo provider" }))
  await expectVisible(page.getByRole("button", { name: "Sign in with a passkey" }))
  await expectVisible(page.getByRole("button", { name: "Email me a link instead" }))
})

await check("empty submit shows field errors and focuses the first", async () => {
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await expectVisible(page.getByText("Enter your email."))
  await expectVisible(page.getByText("Enter your password."))
  const focused = await page.evaluate(() => document.activeElement?.getAttribute("name"))
  if (focused !== "identifier") throw new Error(`focus is on ${focused}, want identifier`)
  // Tabbing away from a still-empty field must keep its message.
  await page.keyboard.press("Tab")
  await page.keyboard.press("Tab")
  await expectVisible(page.getByText("Enter your email."))
})

await check("wrong password shows the typed error message", async () => {
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByLabel("Password").fill("not the password")
  await page.keyboard.press("Enter")
  const alert = page.getByRole("alert").filter({ hasText: /./ })
  await expectVisible(alert)
  const text = (await alert.first().innerText()).trim()
  if (text !== INVALID_CREDENTIALS) throw new Error(`alert says ${JSON.stringify(text)}`)
  console.log(`       message: ${JSON.stringify(text)}`)
})

await check("correct password signs in and useSession updates", async () => {
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 5000 })
  await expectVisible(page.getByRole("heading", { name: `Hello, ${USER.name}` }))
  await expectVisible(page.getByRole("banner").getByRole("button", { name: /Ada Lovelace/ }))
})

await check("sign out clears the session", async () => {
  await page.getByRole("banner").getByRole("button", { name: /Ada Lovelace/ }).click()
  await page.getByRole("menuitem", { name: "Sign out" }).click()
  await page.waitForURL(`${BASE}/sign-in`, { timeout: 5000 })
  await expectVisible(page.getByRole("banner").getByRole("link", { name: "Sign in" }))
  await page.goto(`${BASE}/`)
  await expectVisible(page.getByRole("heading", { name: "Signed out" }))
})

// redirectTo comes from the address bar, so anyone can write a link with
// one: the kit follows only paths on this site and lands anywhere else on
// the default path (useSafeRedirect), never on the other site.
async function signInWithRedirect(redirectTo) {
  await page.goto(`${BASE}/sign-in?redirectTo=${encodeURIComponent(redirectTo)}`)
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
}
async function signOutFromMenu() {
  await page.getByRole("banner").getByRole("button", { name: /Ada Lovelace/ }).click()
  await page.getByRole("menuitem", { name: "Sign out" }).click()
  await page.waitForURL(`${BASE}/sign-in`, { timeout: 5000 })
}

await check("redirectTo to another site lands on the default path", async () => {
  await signInWithRedirect("https://evil.example/phish")
  await page.waitForURL(`${BASE}/`, { timeout: 5000 })
  await expectVisible(page.getByRole("heading", { name: `Hello, ${USER.name}` }))
  await signOutFromMenu()
})

await check("redirectTo written as //host lands on the default path", async () => {
  await signInWithRedirect("//evil.example")
  await page.waitForURL(`${BASE}/`, { timeout: 5000 })
  await signOutFromMenu()
})

await check("redirectTo to a path on this site is followed", async () => {
  await signInWithRedirect("/account")
  await page.waitForURL(`${BASE}/account`, { timeout: 5000 })
  await signOutFromMenu()
})

await check("magic link mode sends and confirms", async () => {
  await page.goto(`${BASE}/sign-in`)
  await page.getByRole("button", { name: "Email me a link instead" }).click()
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByRole("button", { name: "Email me a sign-in link" }).click()
  await expectVisible(page.getByText("Check your email"))
})

await check("the demo inbox shows the magic link and opens it in the app", async () => {
  await page.goto(`${BASE}/inbox`)
  await expectVisible(page.getByText("Demo only"))
  await expectVisible(page.getByRole("button", { name: /Your sign-in link/ }))
  await page.getByRole("button", { name: /^Open \/magic-link/ }).click()
  await page.waitForURL(/\/magic-link\?token=/, { timeout: 5000 })
})

await check("Continue with Demo provider signs in through the pretend provider", async () => {
  await page.goto(`${BASE}/sign-in`)
  await page.getByRole("button", { name: "Continue with Demo provider" }).click()
  await expectVisible(page.getByRole("heading", { name: "Demo provider" }))
  await page.getByRole("button", { name: /Grace Hopper/ }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 5000 })
  await expectVisible(page.getByRole("heading", { name: "Hello, Grace Hopper" }))
})

// Re-authentication with a linked provider. Grace signed in through the
// pretend provider just now and has no password. with-servers.sh runs the API
// with a short fresh window (DEMO_FRESH_WINDOW), so after it passes a change
// that needs a recent sign-in asks "confirm it's you", and the dialog offers
// her linked provider, a page navigation that comes back to /account.
const FRESH_WINDOW_MS = parseDuration(process.env.DEMO_FRESH_WINDOW ?? "8s")
function parseDuration(v) {
  const m = /^(\d+)(ms|s)$/.exec(v)
  if (m === null) throw new Error(`DEMO_FRESH_WINDOW=${v}: the e2e reads only ms or s`)
  return Number(m[1]) * (m[2] === "s" ? 1000 : 1)
}
const NOT_LINKED = AUTH_ERROR_CODES["oauth.reauth_not_linked"].message
async function askToChangeEmail() {
  await page.getByLabel("New email").fill("grace.new@demo.test")
  await page.getByRole("button", { name: "Change email" }).click()
  await expectVisible(page.getByRole("dialog").getByRole("button", { name: "Continue with Demo provider" }))
}

await check("a stale session asks to confirm and offers the linked provider", async () => {
  await page.goto(`${BASE}/account`)
  await page.waitForTimeout(FRESH_WINDOW_MS + 1000)
  await askToChangeEmail()
})

await check("another account at the provider is refused back on the page", async () => {
  await page.getByRole("dialog").getByRole("button", { name: "Continue with Demo provider" }).click()
  await expectVisible(page.getByRole("heading", { name: "Demo provider" }))
  await page.getByRole("button", { name: /Alan Turing/ }).click()
  await page.waitForURL(`${BASE}/account`, { timeout: 5000 })
  await expectVisible(page.getByText(NOT_LINKED))
  await expectVisible(page.getByRole("heading", { name: "Hello, Grace Hopper" }).or(page.getByRole("banner").getByRole("button", { name: /Grace Hopper/ })))
})

await check("the linked account confirms on the same session and the change goes through", async () => {
  await askToChangeEmail()
  await page.getByRole("dialog").getByRole("button", { name: "Continue with Demo provider" }).click()
  await expectVisible(page.getByRole("heading", { name: "Demo provider" }))
  await page.getByRole("button", { name: /Grace Hopper/ }).click()
  // The marker is read and removed from the address once the page is back.
  await page.waitForURL(`${BASE}/account`, { timeout: 5000 })
  await expectVisible(page.getByText("You confirmed it's you."))
  await page.getByLabel("New email").fill("grace.new@demo.test")
  await page.getByRole("button", { name: "Change email" }).click()
  await expectVisible(page.getByText("Confirm the new address"))
})

await browser.close()
console.log(`all ${step} steps passed; screenshots in ${OUT}`)

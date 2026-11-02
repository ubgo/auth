// Drives the built site headless with Playwright, the way a visitor uses it:
// every page renders with no console error and fits a 390px phone, the
// sign-in flow works with the demo credentials and fails with a wrong
// password, the two-factor step takes the demo code, a passkey button says
// it is not available, the copy buttons copy, the theme toggle works, and
// the mock controls show only what changes the page, and a component that
// navigates after success stays on its page with a result line, and the
// Code tab and Props tables come from the registry and its sources.
// Screenshots go to SHOTS_DIR when it is set.
//
//   SHOWCASE_URL=http://127.0.0.1:4002/auth/ node scripts/check.mjs

import { mkdirSync, readFileSync } from "node:fs"
import { join, resolve } from "node:path"
import { chromium } from "playwright"

const BASE = (process.env.SHOWCASE_URL ?? "http://127.0.0.1:5230/auth/").replace(/\/?$/, "/")
const SHOTS = process.env.SHOTS_DIR
const PHONE_WIDTH = 390
const DEMO_PASSWORD = "correct horse battery staple"

const catalog = readFileSync(resolve(import.meta.dirname, "../src/catalog.tsx"), "utf8")
const pages = [...catalog.matchAll(/^ {4}name: "([a-z0-9-]+)",$/gm)].map((m) => m[1])

const failures = []
function check(ok, what) {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`)
  if (!ok) failures.push(what)
}

const browser = await chromium.launch({ headless: true })
const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, colorScheme: "light" })
await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(BASE).origin })
const page = await context.newPage()
const errors = []
page.on("console", (msg) => {
  if (msg.type() === "error") errors.push(msg.text())
})
page.on("pageerror", (err) => errors.push(String(err)))

async function open(path, width = 1280) {
  await page.setViewportSize({ width, height: 900 })
  await page.goto(BASE + path.replace(/^\//, ""))
  await page.locator("main h1").first().waitFor()
  // Let the variant's mock state settle and the component's first read answer.
  await page.waitForTimeout(700)
}

async function shot(name) {
  if (!SHOTS) return
  mkdirSync(SHOTS, { recursive: true })
  await page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true })
}

/** The line a component page shows instead of following a component's navigation. */
function stageResult() {
  return page.getByRole("status").filter({ hasText: "Your app would now go to" })
}

/** Checks the page stayed on path and its result line contains text. */
async function expectResult(path, text, what) {
  const ok = await stageResult()
    .filter({ hasText: text })
    .waitFor({ timeout: 5000 })
    .then(() => true, () => false)
  check(ok && new URL(page.url()).pathname.endsWith(`/${path}`), `${what} (on ${new URL(page.url()).pathname})`)
}

/** Clicks the result line's "Go there" and checks the browser lands on url. */
async function goThere(url, what) {
  await stageResult().getByRole("link", { name: "Go there" }).click()
  await page.waitForURL(url, { timeout: 5000 }).then(
    () => check(true, what),
    () => check(false, what),
  )
}

async function setTheme(theme) {
  await page.evaluate((t) => {
    localStorage.setItem("theme", t)
    document.documentElement.classList.toggle("dark", t === "dark")
  }, theme)
}

// Every page, desktop and phone.
for (const path of ["/", ...pages.map((p) => `/${p}`)]) {
  errors.length = 0
  await open(path)
  check(errors.length === 0, `${path} renders with no console error${errors.length ? `: ${errors.join(" | ")}` : ""}`)
  await open(path, PHONE_WIDTH)
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  check(overflow <= 0, `${path} fits ${PHONE_WIDTH}px (overflow ${overflow}px)`)
}

await open("/")
await shot("home-light")

// Sign in: wrong password, then the demo credentials.
await setTheme("light")
await open("/sign-in-form")
await shot("sign-in-light")
await page.getByLabel("Email").fill("ada@example.com")
await page.getByLabel("Password", { exact: true }).fill("wrong password")
await page.getByRole("button", { name: "Sign in", exact: true }).click()
await page.getByText("The sign-in details are not right.").waitFor({ timeout: 5000 }).then(
  () => check(true, "a wrong password shows password.invalid_credentials"),
  () => check(false, "a wrong password shows password.invalid_credentials"),
)
await shot("sign-in-error")
await page.getByLabel("Password", { exact: true }).fill(DEMO_PASSWORD)
await page.getByRole("button", { name: "Sign in", exact: true }).click()
await expectResult("sign-in-form", "Signed in as Ada Lovelace. Your app would now go to /account-settings.", "the demo credentials sign in and the page shows where the app would go")
await shot("sign-in-result")
await goThere(/\/account-settings$/, "Go there opens account settings, still signed in")
await page.waitForTimeout(800)
check((await page.getByText("ada@example.com").count()) > 0, "account settings shows Ada after Go there")
await shot("account-settings")

// Two-factor: Grace signs in, the challenge takes the demo code.
await open("/sign-in-form")
await page.getByLabel("Email").fill("grace@example.com")
await page.getByLabel("Password", { exact: true }).fill(DEMO_PASSWORD)
await page.getByRole("button", { name: "Sign in", exact: true }).click()
await expectResult("sign-in-form", "/two-factor-challenge", "an account with a second factor is sent to the two-factor step")
await goThere(/\/two-factor-challenge/, "Go there opens the two-factor step")
await page.waitForTimeout(800)
await shot("two-factor")
await page.getByLabel("Authentication code").first().click()
await page.keyboard.type("123456")
await expectResult("two-factor-challenge", "Signed in as Grace Hopper. Your app would now go to /account-settings.", "the demo code finishes the two-factor sign-in")

// Magic link: the valid link signs in on load and stays on its own page;
// "Run again" starts it over; the expired link shows its own state.
await open("/magic-link-callback")
await expectResult("magic-link-callback", "Your app would now go to /user-button.", "the magic link page stays put and shows where the app would go")
check((await page.getByText("You are signed in").count()) > 0, "the magic link page shows the component's signed-in state")
await shot("magic-link-result")
await page.getByRole("button", { name: "Run again" }).click()
await expectResult("magic-link-callback", "Your app would now go to /user-button.", "Run again signs in with the link again")
await page.getByRole("tab", { name: "Expired link" }).click()
await page.getByText("This link has expired").waitFor({ timeout: 5000 }).then(
  () => check(true, "the expired link shows its own state"),
  () => check(false, "the expired link shows its own state"),
)
check((await stageResult().count()) === 0, "the expired link shows no navigation result")

// Passkey: the mock says it cannot run the ceremony.
await open("/passkey-list")
await page.getByRole("button", { name: /add a passkey/i }).first().click()
await page.getByText(/need a real server/).first().waitFor({ timeout: 5000 }).then(
  () => check(true, "adding a passkey says the mock cannot run it"),
  () => check(false, "adding a passkey says the mock cannot run it"),
)

// Copy buttons.
await open("/sign-in-form")
await page.getByRole("button", { name: "Copy command" }).click()
const copied = await page.evaluate(() => navigator.clipboard.readText())
check(copied === "npx shadcn@latest add https://ubgo.github.io/auth/r/sign-in-form.json", `the install line copies (${copied})`)
await page.getByRole("button", { name: "Copy code" }).click()
const snippet = await page.evaluate(() => navigator.clipboard.readText())
check(snippet.includes("<SignInForm"), "the usage snippet copies")

// Theme toggle.
await setTheme("light")
await page.getByRole("button", { name: "Switch to dark theme" }).first().click()
check(await page.evaluate(() => document.documentElement.classList.contains("dark")), "the theme toggle turns dark mode on")
await page.waitForTimeout(300)
await shot("sign-in-dark")
await open("/two-factor-challenge")
await shot("two-factor-dark")
await page.getByRole("button", { name: "Switch to light theme" }).first().click()
check(await page.evaluate(() => !document.documentElement.classList.contains("dark")), "the theme toggle turns dark mode off")

// The mock controls: only those that change the page. Verify email has no
// session row; sign in's menu holds its two switches and the reset; a page
// the session changes labels the row plainly.
await open("/verify-email")
check((await page.getByRole("group", { name: "Pretend signed in as" }).count()) === 0, "verify email shows no session row")
await open("/sign-in-form")
await page.getByRole("button", { name: "Mock settings" }).click()
const menuItems = [...(await page.getByRole("menuitemcheckbox").allInnerTexts()), ...(await page.getByRole("menuitem").allInnerTexts())]
check(menuItems.join(", ") === "Slow network, OAuth providers, Reset mock", `sign in's Mock settings menu lists its switches and the reset (${menuItems.join(", ")})`)
await page.keyboard.press("Escape")
await open("/account-settings")
const sessionRow = page.getByRole("group", { name: "Pretend signed in as" })
check((await sessionRow.getByRole("button").allInnerTexts()).join(", ") === "Ada (admin), Grace (has 2FA), Nobody", "account settings offers Ada, Grace and Nobody")

// Code tab and Props: the files shadcn installs, equal to the built
// registry item, each with its own copy button; the props tables of the
// wired component and its view; no sideways page scroll on a phone.
const builtItem = JSON.parse(readFileSync(resolve(import.meta.dirname, "../public/r/verify-email.json"), "utf8"))
const wiredFile = builtItem.files.find((f) => f.target === "components/auth/verify-email.tsx")
await open("/verify-email")
await page.getByRole("tablist", { name: "Stage" }).getByRole("tab", { name: "Code" }).click()
const codeBox = page.locator('pre[aria-label="components/auth/verify-email.tsx"]')
await codeBox.waitFor({ timeout: 5000 })
const shown = await codeBox.innerText()
check(wiredFile !== undefined && shown.replace(/\n+$/, "") === wiredFile.content.replace(/\n+$/, ""), "the Code tab shows verify-email.tsx exactly as the registry item installs it")
const fileTabs = await page.getByRole("tablist", { name: "Files" }).getByRole("tab").allInnerTexts()
check(fileTabs.join(", ") === "verify-email.tsx, verify-email-view.tsx, auth-view.tsx", `the Code tab lists the installed files (${fileTabs.join(", ")})`)
await page.getByRole("button", { name: "Copy components/auth/verify-email.tsx" }).click()
const copiedFile = await page.evaluate(() => navigator.clipboard.readText())
check(wiredFile !== undefined && copiedFile === wiredFile.content, "the file's copy button copies verify-email.tsx")
await shot("code-verify-email-light")
for (const table of ["VerifyEmail props", "VerifyEmailView props"]) {
  const rows = await page.getByRole("table", { name: table }).locator("tbody tr").count()
  check(rows > 0, `the ${table} table has rows (${rows})`)
}
await page.getByRole("heading", { name: "Props" }).scrollIntoViewIfNeeded()
await shot("code-verify-email-props")
await page.setViewportSize({ width: PHONE_WIDTH, height: 900 })
await page.waitForTimeout(300)
const codeOverflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
check(codeOverflow <= 0, `verify email with Code open fits ${PHONE_WIDTH}px (overflow ${codeOverflow}px)`)
await page.setViewportSize({ width: 1280, height: 900 })

// The registry the install lines point at is served.
const res = await page.request.get(`${BASE}r/sign-in-form.json`)
check(res.ok(), "r/sign-in-form.json is served")

// A deep link survives a reload.
await page.goto(`${BASE}account-settings`)
await page.locator("main h1").first().waitFor()
check((await page.locator("main h1").first().textContent()) === "Account settings", "a deep link loads its page")

await browser.close()
if (failures.length > 0) {
  console.error(`\n${failures.length} check(s) failed`)
  process.exit(1)
}
console.log("\nall checks passed")

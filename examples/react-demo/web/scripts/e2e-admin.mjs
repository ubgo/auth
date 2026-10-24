// Drives the admin dashboard (/admin: AdminUsersTable, AdminUserDetail and
// ImpersonationBanner) headless against the running demo (Vite on DEMO_URL,
// the Go API behind its proxy), and fails on the first step that does not
// behave. Two browser contexts: Ada, the seeded admin, and Linus, the
// seeded second user, whose session the admin revokes and whom the admin
// bans, impersonates and checks. Run it with DEMO_FRESH_WINDOW=20s (the
// Taskfile does): the admin signs in again right before each group of
// changes, four sign-ins in all, under the password plugin's five per
// account per 15 minutes, and one step lets the window lapse on purpose.
// Screenshots of each step land in .shots/e2e-admin/.

import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

const BASE = process.env.DEMO_URL ?? "http://localhost:5180"
const OUT = new URL("../.shots/e2e-admin/", import.meta.url).pathname
const PASSWORD = "correct horse battery staple"
const ADMIN = { email: "ada@example.com", name: "Ada Lovelace" }
const OTHER = { email: "linus@example.com", name: "Linus Pauling" }
// seed.go: 64 directory users, 3 of them banned, plus Ada, Linus and the MFA user.
const TOTAL = 67
const BANNED = 3
// Directory users whose address holds "turing": the first 16 (seed.go directoryLast[0]).
const TURING = 16
// The fresh window the API runs with (with-servers.sh passes it on), plus a margin.
const FRESH_MS = Number.parseFloat(process.env.DEMO_FRESH_WINDOW ?? "8s") * 1000 + 1500

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const adminContext = await browser.newContext({ viewport: { width: 1280, height: 900 } })
const otherContext = await browser.newContext({ viewport: { width: 1280, height: 800 } })
const page = await adminContext.newPage()
const other = await otherContext.newPage()

let step = 0
async function check(name, fn) {
  step++
  try {
    await fn()
    console.log(`  ok   ${name}`)
  } catch (err) {
    console.log(`  FAIL ${name}: ${err.message.split("\n")[0]}`)
    await page.screenshot({ path: `${OUT}${String(step).padStart(2, "0")}-FAIL.png`, fullPage: true })
    await browser.close()
    process.exit(1)
  }
  await page.screenshot({ path: `${OUT}${String(step).padStart(2, "0")}-${name.replace(/\W+/g, "-")}.png`, fullPage: true })
}
const expectVisible = (locator) => locator.waitFor({ state: "visible", timeout: 5000 })
const range = (text) => page.getByText(text, { exact: true })
const status = (text) => page.getByRole("status").filter({ hasText: text })

/** Signs a page in through the form, landing on redirectTo. */
async function signIn(p, email, redirectTo) {
  await p.goto(`${BASE}/sign-in?redirectTo=${encodeURIComponent(redirectTo)}`)
  await p.getByLabel("Email").fill(email)
  await p.getByLabel("Password").fill(PASSWORD)
  await p.getByRole("button", { name: "Sign in", exact: true }).click()
  await p.waitForURL(`${BASE}${redirectTo}`, { timeout: 5000 })
}

/** A fresh admin session (the server's FreshSignIn), then the page reloaded on it. */
async function freshAdmin() {
  const res = await page.request.post(`${BASE}/auth/password/sign-in`, {
    data: { identifier: ADMIN.email, password: PASSWORD },
    headers: { Origin: BASE },
  })
  if (!res.ok()) throw new Error(`admin sign-in answered ${res.status()}`)
  await page.reload()
}

/** The status code Linus's own session check answers. */
async function otherSessionStatus() {
  return (await other.request.get(`${BASE}/auth/session`)).status()
}

await check("a user who is not an admin is told so, not shown the table", async () => {
  await signIn(other, OTHER.email, "/admin")
  await expectVisible(other.getByText("You do not have access to the user list."))
  if ((await other.getByRole("table").count()) !== 0) throw new Error("a table is shown to a non-admin")
})

await check("the admin sees the first page of every user", async () => {
  await signIn(page, ADMIN.email, "/admin")
  await expectVisible(range(`1–50 of ${TOTAL}`))
  const rows = await page.getByRole("table").getByRole("row").count()
  if (rows !== 51) throw new Error(`${rows} rows, want 50 and the header`)
  await expectVisible(page.getByRole("button", { name: "Page 2" }))
})

await check("the numbered pager and the arrow keys turn pages", async () => {
  await page.getByRole("button", { name: "Page 2" }).click()
  await expectVisible(range(`51–${TOTAL} of ${TOTAL}`))
  const current = await page.getByRole("button", { name: "Page 2" }).getAttribute("aria-current")
  if (current !== "page") throw new Error(`page 2 aria-current=${current}`)
  await page.locator("body").click({ position: { x: 5, y: 5 } })
  await page.keyboard.press("ArrowLeft")
  await expectVisible(range(`1–50 of ${TOTAL}`))
  await page.keyboard.press("ArrowRight")
  await expectVisible(range(`51–${TOTAL} of ${TOTAL}`))
})

await check("a smaller page size gives more pages, with first and last", async () => {
  await page.getByRole("button", { name: /^Rows per page/ }).click()
  await page.getByRole("menuitemradio", { name: "10", exact: true }).click()
  await expectVisible(range(`1–10 of ${TOTAL}`))
  await page.getByRole("button", { name: "Last page" }).click()
  await expectVisible(range(`61–${TOTAL} of ${TOTAL}`))
  await expectVisible(page.getByRole("button", { name: "Page 7" }))
  await page.getByRole("button", { name: "First page" }).click()
  await expectVisible(range(`1–10 of ${TOTAL}`))
  if (!(await page.getByRole("button", { name: "Previous page" }).isDisabled())) throw new Error("Previous is enabled on page 1")
})

await check("/ focuses the search, which finds by email fragment", async () => {
  await page.locator("body").click({ position: { x: 5, y: 5 } })
  await page.keyboard.press("/")
  const search = page.getByLabel("Search users")
  const focused = await search.evaluate((el) => el === document.activeElement)
  if (!focused) throw new Error("/ did not focus the search")
  await page.keyboard.type("turing")
  await expectVisible(range(`1–10 of ${TURING}`))
})

await check("the status filter narrows the search to banned users, Esc clears the search", async () => {
  await page.getByRole("button", { name: /^Status:/ }).click()
  await page.getByRole("menuitemradio", { name: "Banned", exact: true }).click()
  await expectVisible(range(`1–${BANNED} of ${BANNED}`))
  await page.getByLabel("Search users").press("Escape")
  // Every banned user is a Turing, so clearing the search leaves the same three.
  await expectVisible(range(`1–${BANNED} of ${BANNED}`))
  await page.getByRole("button", { name: /^Status:/ }).click()
  await page.getByRole("menuitemradio", { name: "Any status", exact: true }).click()
  await expectVisible(range(`1–10 of ${TOTAL}`))
})

await check("a name search opens the user's detail with their live session", async () => {
  await page.getByRole("button", { name: /^Search in:/ }).click()
  await page.getByRole("menuitemradio", { name: "name", exact: true }).click()
  await page.getByLabel("Search users").fill("Linus")
  await expectVisible(range("1–1 of 1"))
  await page.getByRole("link", { name: `Open ${OTHER.name}` }).click()
  await page.waitForURL(/\/admin\?user=/, { timeout: 5000 })
  await expectVisible(page.getByRole("heading", { name: OTHER.name }))
  await expectVisible(page.getByRole("region", { name: "Live component" }).getByText(OTHER.email).first())
  // The browser session, and the one the seed's sign-up left (no device).
  await expectVisible(page.getByRole("button", { name: /^Revoke the session on Chrome/ }))
})

await check("revoking the session signs the user out there", async () => {
  await freshAdmin()
  await page.getByRole("button", { name: /^Revoke the session on Chrome/ }).click()
  await expectVisible(status("Session revoked."))
  await page.getByRole("button", { name: /^Revoke the session on Chrome/ }).waitFor({ state: "detached", timeout: 5000 })
  const code = await otherSessionStatus()
  if (code !== 401) throw new Error(`the revoked session still answers ${code}`)
})

await check("a ban with a reason is shown, and refuses the user's sign-in", async () => {
  await page.getByRole("button", { name: "Ban", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByLabel("Reason (shown to them)").fill("Spamming the forum")
  await dialog.getByRole("radio", { name: "1 h" }).click()
  await dialog.getByRole("button", { name: "Ban user" }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
  await expectVisible(status("User banned."))
  await expectVisible(page.getByText("Banned: Spamming the forum"))
  const res = await other.request.post(`${BASE}/auth/password/sign-in`, {
    data: { identifier: OTHER.email, password: PASSWORD },
    headers: { Origin: BASE },
  })
  const body = await res.json()
  if (res.status() !== 403 || body.error?.code !== "admin.banned") throw new Error(`banned sign-in answered ${res.status()} ${JSON.stringify(body)}`)
})

await check("unban lifts it", async () => {
  await page.getByRole("button", { name: "Unban" }).click()
  await expectVisible(status("Ban lifted."))
  if ((await page.getByText("Banned: Spamming the forum").count()) !== 0) throw new Error("the ban notice stayed")
})

await check("once the sign-in is no longer recent, a change asks to sign in again", async () => {
  await page.waitForTimeout(FRESH_MS)
  await page.getByRole("button", { name: "Ban", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("button", { name: "Ban user" }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 }).catch(() => dialog.getByRole("button", { name: "Cancel" }).click())
  await expectVisible(page.getByText("This action needs a recent sign-in."))
  await page.getByRole("button", { name: "Sign in again" }).click()
  await page.waitForURL(/\/sign-in\?redirectTo=/, { timeout: 5000 })
  await page.getByLabel("Email").fill(ADMIN.email)
  await page.getByLabel("Password").fill(PASSWORD)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await page.waitForURL(/\/admin\?user=/, { timeout: 5000 })
  await expectVisible(page.getByRole("heading", { name: OTHER.name }))
})

await check("impersonating the user signs this browser in as them, with the banner", async () => {
  // Still fresh from signing in again just above.
  await page.getByRole("button", { name: "Impersonate" }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 5000 })
  await expectVisible(page.getByText(`You are acting as ${OTHER.name}.`, { exact: false }))
  await expectVisible(page.getByRole("banner").getByRole("button", { name: new RegExp(OTHER.name) }))
})

await check("stop impersonating brings the admin's own session back", async () => {
  await page.getByRole("button", { name: "Stop impersonating" }).click()
  await page.waitForURL(`${BASE}/admin`, { timeout: 5000 })
  await expectVisible(page.getByRole("banner").getByRole("button", { name: new RegExp(ADMIN.name) }))
  await expectVisible(range(`1–50 of ${TOTAL}`))
  if ((await page.getByText(/You are acting as/).count()) !== 0) throw new Error("the banner stayed")
})

await check("deleting a user asks first, then removes them from the table", async () => {
  await page.getByLabel("Search users").fill("Linus")
  await expectVisible(range("1–1 of 1"))
  await page.getByRole("link", { name: `Open ${OTHER.name}` }).click()
  await expectVisible(page.getByRole("heading", { name: OTHER.name }))
  await freshAdmin()
  await page.getByRole("button", { name: "More actions" }).click()
  await page.getByRole("menuitem", { name: "Delete user" }).click()
  const confirm = page.getByRole("alertdialog")
  await expectVisible(confirm.getByText(`Delete ${OTHER.name}?`))
  await confirm.getByRole("button", { name: "Delete", exact: true }).click()
  await page.waitForURL(`${BASE}/admin`, { timeout: 5000 })
  await expectVisible(range(`1–50 of ${TOTAL - 1}`))
})

await check("the admin's own row has no actions on themselves", async () => {
  await page.getByLabel("Search users").fill("Ada")
  await expectVisible(range("1–1 of 1"))
  await page.getByRole("link", { name: `Open ${ADMIN.name}` }).click()
  await expectVisible(page.getByRole("heading", { name: ADMIN.name }))
  for (const name of ["Impersonate", "Ban", "More actions"]) {
    if ((await page.getByRole("button", { name, exact: true }).count()) !== 0) throw new Error(`${name} is offered on the admin's own page`)
  }
})

await check("the table in dark mode", async () => {
  await page.goto(`${BASE}/admin`)
  await expectVisible(range(`1–50 of ${TOTAL - 1}`))
  // The demo's theme switch puts the dark class on <html>.
  await page.getByRole("tab", { name: "Dark" }).click()
  const dark = await page.evaluate(() => document.documentElement.classList.contains("dark"))
  if (!dark) throw new Error("the Dark switch did not set the dark class")
  // Let the colour transitions finish before the screenshot.
  await page.waitForTimeout(500)
})

await check("the table at a phone width scrolls inside its frame, not the page", async () => {
  await page.setViewportSize({ width: 390, height: 844 })
  await expectVisible(page.getByRole("button", { name: "Next page" }))
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  if (overflow > 0) throw new Error(`the page scrolls sideways by ${overflow}px at 390 wide`)
})

await browser.close()
console.log("admin dashboard: every step passed")

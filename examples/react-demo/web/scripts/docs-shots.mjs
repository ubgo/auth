// The screenshots the docs embed (docs/assets/screenshots), taken headless
// against a throwaway server that docs-shots.sh starts. One app per run:
//
//   node scripts/docs-shots.mjs demo      (DEMO_URL)      the React demo, every component
//   node scripts/docs-shots.mjs headless  (HEADLESS_URL)  examples/react-headless
//   node scripts/docs-shots.mjs router    (RR_URL)        examples/react-router-app
//   node scripts/docs-shots.mjs nextjs    (NEXT_URL)      examples/nextjs-app
//
// Unlike shots.mjs (every route, every theme, for eyeballing a change), this
// takes a small fixed set with each component in a real state: an error, a
// sent link, a QR code, recovery codes, an open menu. The demo run changes
// its throwaway database as it goes (a sign-up, two-factor turned on), so
// the order of the steps matters. Content is kept stable: the seeded user
// and the demo provider's personas only, and a normal Chrome user agent so
// the session list does not say "HeadlessChrome". Writes raw PNGs into
// SHOTS_OUT; docs-shots.sh compresses them into docs/assets/screenshots.

import { createHmac } from "node:crypto"
import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

const APP = process.argv[2]
const OUT = process.env.SHOTS_OUT ?? new URL("../.shots/docs/", import.meta.url).pathname
const USER = { identifier: "ada@example.com", password: "correct horse battery staple" }
const USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
const DESKTOP = { viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 }
const PHONE = { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 }
/** The stage DemoPage renders each component on; most demo shots crop to it. */
const STAGE = 'section[aria-label="Live component"]'

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const taken = []

/** A context with the theme applied before first paint (the demo reads localStorage "theme"). */
async function newContext({ theme = "light", size = DESKTOP, storageState } = {}) {
  const context = await browser.newContext({ ...size, colorScheme: theme, userAgent: USER_AGENT, storageState, reducedMotion: "reduce" })
  await context.addInitScript((t) => localStorage.setItem("theme", t), theme)
  return context
}

/**
 * The component on the stage with a margin of the stage's dotted backdrop
 * around it, in viewport coordinates: the stage itself is as tall as the side
 * column, so a crop to it is mostly empty dots.
 */
async function stageClip(page) {
  return page.locator(STAGE).first().evaluate((stage, pad) => {
    const outer = stage.getBoundingClientRect()
    let top = Infinity, left = Infinity, bottom = -Infinity, right = -Infinity
    for (const child of stage.children) {
      const r = child.getBoundingClientRect()
      if (r.width === 0 || r.height === 0) continue
      top = Math.min(top, r.top); left = Math.min(left, r.left); bottom = Math.max(bottom, r.bottom); right = Math.max(right, r.right)
    }
    const x = Math.max(outer.left, left - pad), y = Math.max(outer.top, top - pad)
    const w = Math.min(outer.right, right + pad) - x, h = Math.min(outer.bottom, bottom + pad) - y
    return { x, y, width: Math.round(w), height: Math.round(h) }
  }, 32)
}

/** Screenshot the page (viewport) or one element of it, after animations and fonts settle. */
async function shot(page, name, target) {
  await page.evaluate(() => document.fonts.ready)
  await page.waitForTimeout(400)
  const path = `${OUT}${name}.png`
  const options = { path, animations: "disabled", caret: "hide" }
  if (target === undefined) await page.screenshot(options)
  else {
    // The demo scrolls inside its main column, not the window, so a component
    // taller than the viewport is only fully painted in a taller viewport.
    const size = page.viewportSize()
    await page.setViewportSize({ width: size.width, height: 2400 })
    await page.waitForTimeout(200)
    if (target === STAGE) await page.screenshot({ ...options, clip: await stageClip(page) })
    else await page.locator(target).first().screenshot(options)
    await page.setViewportSize(size)
  }
  taken.push(name)
}

/** Waits for a locator; on a timeout saves FAIL.png of its page first, so the cause is visible. */
async function visible(locator) {
  try {
    await locator.first().waitFor({ state: "visible", timeout: 10000 })
  } catch (err) {
    await locator.page().screenshot({ path: `${OUT}FAIL.png`, fullPage: true }).catch(() => {})
    throw err
  }
}

/** The newest demo mail whose subject matches, and its first link. */
async function mailLink(base, subject) {
  for (let i = 0; i < 40; i++) {
    const res = await fetch(`${base}/dev/mail`)
    const { messages } = await res.json()
    const m = messages.find((x) => subject.test(x.subject))
    if (m) return m.links[0]
    await new Promise((r) => setTimeout(r, 250))
  }
  throw new Error(`no mail matching ${subject}`)
}

/** RFC 6238 TOTP for a base32 secret: six digits, 30-second steps, SHA-1. */
function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const ch of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0")
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const h = createHmac("sha1", key).update(counter).digest()
  const o = h[h.length - 1] & 0xf
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, "0")
}

/** Signs the demo user in through the API and returns the cookie state, so most shots cost no UI sign-in. */
async function apiSession(base) {
  const context = await browser.newContext({ userAgent: USER_AGENT, extraHTTPHeaders: { "User-Agent": USER_AGENT } })
  const res = await context.request.post(`${base}/auth/password/sign-in`, { data: USER, headers: { Origin: base } })
  if (!res.ok()) throw new Error(`sign-in failed: ${res.status()} ${await res.text()}`)
  // The seed's own sign-up left a session with no device; revoke the others
  // so the session list shows just this browser.
  const list = await (await context.request.get(`${base}/auth/sessions`, { headers: { Origin: base } })).json()
  for (const s of list.sessions.filter((x) => !x.current)) {
    await context.request.post(`${base}/auth/sessions/revoke`, { data: { id: s.id }, headers: { Origin: base } })
  }
  const state = await context.storageState()
  await context.close()
  return state
}

async function demo(base) {
  // Signed out.
  let context = await newContext()
  let page = await context.newPage()
  await page.goto(`${base}/sign-in`, { waitUntil: "networkidle" })
  await visible(page.getByRole("button", { name: "Continue with Demo provider" }))
  await shot(page, "demo-sign-in")
  await shot(page, "sign-in", STAGE)

  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByLabel("Password").fill("not the password")
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await visible(page.getByRole("alert").filter({ hasText: /./ }))
  await shot(page, "sign-in-error", STAGE)

  await page.goto(`${base}/sign-in`, { waitUntil: "networkidle" })
  await page.getByRole("button", { name: "Email me a link instead" }).click()
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByRole("button", { name: "Email me a sign-in link" }).click()
  await visible(page.getByText("Check your email"))
  await shot(page, "magic-link-sent", STAGE)

  await page.goto(`${base}/sign-up`, { waitUntil: "networkidle" })
  await visible(page.getByRole("button", { name: "Create account" }))
  await shot(page, "sign-up", STAGE)
  await page.getByLabel("Name").fill("Grace Hopper")
  await page.getByLabel("Email").fill("grace@example.com")
  await page.getByLabel("Password", { exact: true }).fill("a long demo password 42")
  const terms = page.getByRole("checkbox")
  if ((await terms.count()) > 0) await terms.first().check()
  await page.getByRole("button", { name: "Create account" }).click()
  // The demo signs a new account in straight away and mails the verification link.
  await page.waitForURL((url) => url.pathname !== "/sign-up")
  await page.goto(await mailLink(base, /verif/i), { waitUntil: "networkidle" })
  await visible(page.getByText("Email verified"))
  await shot(page, "verify-email", STAGE)
  await context.clearCookies()

  await page.goto(`${base}/forgot-password`, { waitUntil: "networkidle" })
  await page.getByLabel("Email").fill(USER.identifier)
  await shot(page, "forgot-password", STAGE)
  await page.getByRole("button", { name: "Send reset link" }).click()
  await visible(page.getByText("Check your email"))
  // The reset form with a real token, not submitted: the seeded password stays.
  await page.goto(await mailLink(base, /password/i), { waitUntil: "networkidle" })
  await visible(page.getByText("Choose a new password"))
  await page.getByLabel("New password", { exact: true }).fill("a much longer pass phrase")
  await shot(page, "reset-password", STAGE)

  await page.goto(`${base}/inbox`, { waitUntil: "networkidle" })
  await visible(page.getByText("Demo only"))
  await shot(page, "inbox")
  await context.close()

  // Phone width, signed out.
  context = await newContext({ size: PHONE })
  page = await context.newPage()
  await page.goto(`${base}/sign-in`, { waitUntil: "networkidle" })
  await visible(page.getByRole("button", { name: "Continue with Demo provider" }))
  await shot(page, "sign-in-phone")
  await context.close()

  // Signed in.
  const session = await apiSession(base)
  context = await newContext({ storageState: session })
  page = await context.newPage()
  // The home page is left out: it shows the session's id and expiry time, which change every run.
  await page.goto(`${base}/user-button`, { waitUntil: "networkidle" })
  await page.locator(STAGE).getByRole("button", { name: /Ada Lovelace/ }).first().click()
  await visible(page.getByRole("menuitem", { name: "Sign out" }))
  await shot(page, "user-button")

  await page.goto(`${base}/account`, { waitUntil: "networkidle" })
  await visible(page.getByLabel("New email"))
  await shot(page, "account-settings", STAGE)

  await page.goto(`${base}/account-sections`, { waitUntil: "networkidle" })
  await page.waitForLoadState("networkidle")
  await shot(page, "account-sections", STAGE)

  await page.goto(`${base}/passkeys`, { waitUntil: "networkidle" })
  await shot(page, "passkeys", STAGE)

  await page.goto(`${base}/sign-in`, { waitUntil: "networkidle" })
  await shot(page, "customise-panel", "aside > :nth-child(2)")

  await page.goto(`${base}/two-factor/setup`, { waitUntil: "networkidle" })
  await page.getByRole("button", { name: "Turn on" }).click()
  const password = page.getByLabel("Current password")
  if (await password.isVisible().catch(() => false)) {
    await password.fill(USER.password)
    await page.getByRole("button", { name: "Turn on" }).click()
  }
  await visible(page.getByRole("img", { name: "QR code for your authenticator app" }))
  await shot(page, "two-factor-setup", STAGE)
  // The key is shown in groups; the code box submits itself on the last digit.
  const secret = (await page.getByLabel("Or enter this key by hand").textContent()).replace(/\s+/g, "")
  await page.getByLabel("Authentication code").first().pressSequentially(totp(secret))
  await visible(page.getByText("Save your recovery codes"))
  await shot(page, "two-factor-recovery-codes", STAGE)
  await context.close()

  // Dark.
  context = await newContext({ theme: "dark", storageState: session })
  page = await context.newPage()
  await page.goto(`${base}/account`, { waitUntil: "networkidle" })
  await visible(page.getByLabel("New email"))
  await shot(page, "account-settings-dark")
  await context.close()

  // A sign-in now hands off to the challenge, because two-factor is on.
  context = await newContext()
  page = await context.newPage()
  await page.goto(`${base}/sign-in`, { waitUntil: "networkidle" })
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await page.waitForURL(/\/two-factor/)
  await visible(page.getByRole("button", { name: "Use a recovery code" }))
  await shot(page, "two-factor-challenge", STAGE)
  await context.close()
}

/**
 * One shot of a framework example's page, signed in or out. Those pages are
 * plain markup in a narrow column, so the viewport is narrow and the shot
 * ends just below the last element.
 */
async function example(base, name, path, signedIn) {
  const size = { viewport: { width: 720, height: 640 }, deviceScaleFactor: 1 }
  const context = await newContext({ size, storageState: signedIn ? await apiSession(base) : undefined })
  const page = await context.newPage()
  await page.goto(`${base}${path}`, { waitUntil: "networkidle" })
  await page.waitForTimeout(300)
  const bottom = await page.evaluate(() => Math.max(...[...document.body.querySelectorAll("*")].map((el) => el.getBoundingClientRect().bottom)))
  await page.evaluate(() => document.fonts.ready)
  await page.screenshot({ path: `${OUT}${name}.png`, animations: "disabled", caret: "hide", clip: { x: 0, y: 0, width: 720, height: Math.min(640, Math.ceil(bottom) + 32) } })
  taken.push(name)
  await context.close()
}

const RUNS = {
  demo: () => demo(process.env.DEMO_URL),
  headless: () => example(process.env.HEADLESS_URL, "react-headless", "/", false),
  router: () => example(process.env.RR_URL, "react-router-app", "/sign-in", false),
  nextjs: () => example(process.env.NEXT_URL, "nextjs-app", "/account", true),
}
if (!(APP in RUNS)) throw new Error(`usage: docs-shots.mjs ${Object.keys(RUNS).join("|")}`)
try {
  await RUNS[APP]()
} finally {
  await browser.close()
}
console.log(`${APP}: ${taken.length} screenshots in ${OUT}: ${taken.join(", ")}`)

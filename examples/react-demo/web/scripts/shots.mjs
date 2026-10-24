// Screenshots every demo route (src/demo-nav.ts) in light and dark at a
// desktop and a phone width, signed out, plus the home page signed in; then
// every route in German (Language = Deutsch) in light at 1280 and dark at 390,
// because German words are longer and overflow first. Runs
// headless against DEMO_URL; task ui:shots starts and stops the servers.

import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

import { DEMO_PATHS } from "../src/demo-nav.ts"

const BASE = process.env.DEMO_URL ?? "http://localhost:5180"
const OUT = new URL("../.shots/", import.meta.url).pathname
const WIDTHS = [1280, 390]
const THEMES = ["light", "dark"]
const USER = { identifier: "ada@example.com", password: "correct horse battery staple" }

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
// One sign-in for every signed-in shot: the server rate-limits sign-ins, and
// the session cookie is all the shots need.
const signedIn = await browser.newContext()
const res = await signedIn.request.post(`${BASE}/auth/password/sign-in`, { data: USER, headers: { Origin: BASE } })
if (!res.ok()) throw new Error(`sign-in for the signed-in shots failed: ${res.status()} ${await res.text()}`)
const session = await signedIn.storageState()
await signedIn.close()

// Pages that show their real content only to a signed-in user; each also gets a signed-in shot.
const SIGNED_IN_PATHS = ["/", "/account", "/two-factor/setup", "/passkeys", "/user-button", "/organizations", "/invitations"]

const slug = (path) => (path === "/" ? "home" : path.slice(1).replace(/\W+/g, "-"))
let count = 0

for (const theme of THEMES) {
  for (const width of WIDTHS) {
    const context = await browser.newContext({ viewport: { width, height: width < 600 ? 844 : 800 }, colorScheme: theme, deviceScaleFactor: width < 600 ? 2 : 1 })
    const page = await context.newPage()
    for (const path of DEMO_PATHS) {
      await page.goto(`${BASE}${path}`, { waitUntil: "networkidle" })
      await page.screenshot({ path: `${OUT}${theme}-${width}-${slug(path)}.png`, fullPage: true })
      count++
    }
    await context.close()
    // Signed in: the home page and the header with the session.
    const authed = await browser.newContext({ viewport: { width, height: width < 600 ? 844 : 800 }, colorScheme: theme, deviceScaleFactor: width < 600 ? 2 : 1, storageState: session })
    const home = await authed.newPage()
    for (const path of SIGNED_IN_PATHS) {
      await home.goto(`${BASE}${path}`, { waitUntil: "networkidle" })
      await home.screenshot({ path: `${OUT}${theme}-${width}-${slug(path)}-signed-in.png`, fullPage: true })
      count++
    }
    await authed.close()
  }
}
// German: the demo reads its Language switch from localStorage before first render.
const GERMAN = [
  { theme: "light", width: 1280 },
  { theme: "dark", width: 390 },
]
for (const { theme, width } of GERMAN) {
  const context = await browser.newContext({ viewport: { width, height: width < 600 ? 844 : 800 }, colorScheme: theme, deviceScaleFactor: width < 600 ? 2 : 1 })
  await context.addInitScript(() => localStorage.setItem("demo-language", "de"))
  const page = await context.newPage()
  for (const path of DEMO_PATHS) {
    await page.goto(`${BASE}${path}`, { waitUntil: "networkidle" })
    await page.screenshot({ path: `${OUT}de-${theme}-${width}-${slug(path)}.png`, fullPage: true })
    count++
  }
  await context.close()
  const authed = await browser.newContext({ viewport: { width, height: width < 600 ? 844 : 800 }, colorScheme: theme, deviceScaleFactor: width < 600 ? 2 : 1, storageState: session })
  await authed.addInitScript(() => localStorage.setItem("demo-language", "de"))
  const ap = await authed.newPage()
  for (const path of SIGNED_IN_PATHS) {
    await ap.goto(`${BASE}${path}`, { waitUntil: "networkidle" })
    await ap.screenshot({ path: `${OUT}de-${theme}-${width}-${slug(path)}-signed-in.png`, fullPage: true })
    count++
  }
  await authed.close()
}
await browser.close()
console.log(`${count} screenshots in ${OUT}`)

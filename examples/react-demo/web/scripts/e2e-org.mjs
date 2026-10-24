// Drives passkey autofill, the useSession options and the organization
// components headless against the running demo (Vite on DEMO_URL, the Go API
// behind its proxy), and fails on the first step that does not behave.
// Passkeys use Chromium's virtual authenticator (CDP WebAuthn), which answers
// a conditional (autofill) request with the stored passkey at once, the way a
// person picking it from the field's autofill list would. Screenshots of
// each step land in .shots/e2e-org/.

import { mkdirSync } from "node:fs"
import { chromium } from "playwright"

import { AUTH_ERROR_CODES } from "../../../../clients/ts/src/error-codes.ts"

const SLUG_TAKEN = AUTH_ERROR_CODES["organization.slug_taken"].message
const LAST_OWNER = AUTH_ERROR_CODES["organization.last_owner"].message

const BASE = process.env.DEMO_URL ?? "http://localhost:5180"
const OUT = new URL("../.shots/e2e-org/", import.meta.url).pathname
const USER = { identifier: "ada@example.com", password: "correct horse battery staple", name: "Ada Lovelace" }
// The Demo provider's persona whose address the organization invites (devoauth.go).
const INVITEE = { email: "grace@demo.test", name: "Grace Hopper" }

mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ headless: true })
const context = await browser.newContext({ viewport: { width: 1280, height: 800 } })
const page = await context.newPage()
const cdp = await context.newCDPSession(page)
await cdp.send("WebAuthn.enable")
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
})

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
const banner = () => page.getByRole("banner")

async function signOutFromMenu(name) {
  await banner().getByRole("button", { name: new RegExp(name) }).click()
  await page.getByRole("menuitem", { name: "Sign out" }).click()
}

await check("the identifier field offers passkeys and an empty autofill stays quiet", async () => {
  await page.goto(`${BASE}/sign-in`)
  const field = page.getByLabel("Email")
  await expectVisible(field)
  const autocomplete = await field.getAttribute("autocomplete")
  if (autocomplete !== "username webauthn") throw new Error(`autocomplete=${JSON.stringify(autocomplete)}`)
  // No passkey yet: the browser ends the conditional request without one,
  // which must not show an error or start a loop of requests.
  await page.waitForTimeout(1000)
  const alerts = await page.getByRole("alert").filter({ hasText: /./ }).count()
  if (alerts !== 0) throw new Error(`${alerts} alert(s) shown with no passkey`)
})

await check("password sign-in still works with autofill running", async () => {
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await page.waitForURL(`${BASE}/`, { timeout: 5000 })
  await expectVisible(page.getByRole("heading", { name: `Hello, ${USER.name}` }))
})

await check("the overview polls the session (useSession refetchInterval)", async () => {
  await expectVisible(page.getByText("useSession({ refetchInterval: 30 s })"))
})

await check("a passkey is added for the user", async () => {
  await page.goto(`${BASE}/passkeys`)
  await page.getByRole("button", { name: "Add a passkey" }).first().click()
  await expectVisible(page.getByText(/Added /).first())
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId })
  if (credentials.length !== 1) throw new Error(`${credentials.length} credentials on the authenticator`)
})

await check("signed out, the passkey in the field's autofill signs in with no click", async () => {
  await signOutFromMenu(USER.name)
  // The sign-in page starts the conditional request on mount; the virtual
  // authenticator picks the passkey, and the form finishes the sign-in.
  await page.waitForURL(`${BASE}/`, { timeout: 8000 })
  await expectVisible(page.getByRole("heading", { name: `Hello, ${USER.name}` }))
})

// From here on the passkey would sign Ada straight back in on /sign-in.
await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId })

await check("signed in with no organization, the switcher shows the personal account", async () => {
  await page.goto(`${BASE}/organizations`)
  await expectVisible(page.getByRole("button", { name: "Switch organization, current: Personal account" }))
  await expectVisible(page.getByText("Choose or create an organization to see its members."))
})

async function createOrganization(name, slug) {
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitem", { name: "Create organization" }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByLabel("Name").fill(name)
  const suggested = await dialog.getByLabel("Slug").inputValue()
  if (suggested !== slug) throw new Error(`slug suggested ${JSON.stringify(suggested)}, want ${JSON.stringify(slug)}`)
  await dialog.getByRole("button", { name: "Create", exact: true }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
  await expectVisible(page.getByRole("button", { name: `Switch organization, current: ${name}` }))
}

await check("create organization makes it active, with the user as its owner", async () => {
  await createOrganization("Acme Labs", "acme-labs")
  await expectVisible(page.getByText("People in Acme Labs."))
  const row = page.getByRole("listitem").filter({ hasText: USER.name })
  await expectVisible(row.getByText("You"))
  await expectVisible(row.getByText("owner"))
})

await check("a taken slug is refused under the slug field", async () => {
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitem", { name: "Create organization" }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByLabel("Name").fill("Acme Labs")
  await dialog.getByRole("button", { name: "Create", exact: true }).click()
  // The server's organization.slug_taken, shown under the slug and linked to it.
  const slug = dialog.locator('input[aria-invalid="true"]')
  await expectVisible(slug)
  const error = dialog.locator(`#${await slug.getAttribute("aria-describedby")}`)
  const text = (await error.innerText()).trim()
  if (text !== SLUG_TAKEN) throw new Error(`slug error says ${JSON.stringify(text)}`)
  await dialog.getByRole("button", { name: "Cancel" }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
})

await check("an invitation is sent, listed as pending and mailed", async () => {
  await page.getByPlaceholder("name@example.com").fill(INVITEE.email)
  await page.getByRole("button", { name: "Role: member" }).click()
  await page.getByRole("menuitemradio", { name: "admin" }).click()
  await page.getByRole("button", { name: "Invite", exact: true }).click()
  await expectVisible(page.getByRole("status").filter({ hasText: `Invitation sent to ${INVITEE.email}.` }))
  await expectVisible(page.getByRole("button", { name: `Cancel the invitation to ${INVITEE.email}` }))
  const mail = await (await page.request.get(`${BASE}/dev/mail`)).json()
  const invite = mail.messages.find((m) => m.to === INVITEE.email)
  if (invite === undefined) throw new Error("no invitation mail in the inbox")
  if (!invite.links.some((l) => l.includes("/invitations"))) throw new Error(`mail links ${JSON.stringify(invite.links)}`)
})

await check("switching between organizations and the personal account", async () => {
  await createOrganization("Beta Works", "beta-works")
  await expectVisible(page.getByText("People in Beta Works."))
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitemradio", { name: /Acme Labs/ }).click()
  await expectVisible(page.getByRole("button", { name: "Switch organization, current: Acme Labs" }))
  await expectVisible(page.getByText("People in Acme Labs."))
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitemradio", { name: /Personal account/ }).click()
  await expectVisible(page.getByText("Choose or create an organization to see its members."))
  // Back to Acme Labs, so the reload check below has an active organization.
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitemradio", { name: /Acme Labs/ }).click()
  await expectVisible(page.getByText("People in Acme Labs."))
})

await check("the active organization is the session's, so it survives a reload", async () => {
  await page.reload()
  await expectVisible(page.getByRole("button", { name: "Switch organization, current: Acme Labs" }))
})

await check("the invitee sees the invitation and accepts it", async () => {
  await signOutFromMenu(USER.name)
  await page.waitForURL(/\/sign-in/, { timeout: 5000 })
  await page.goto(`${BASE}/sign-in?redirectTo=/invitations`)
  await page.getByRole("button", { name: "Continue with Demo provider" }).click()
  await page.getByRole("button", { name: new RegExp(INVITEE.name) }).click()
  await page.waitForURL(`${BASE}/invitations`, { timeout: 5000 })
  await page.getByRole("button", { name: "Accept the invitation to Acme Labs" }).click()
  await expectVisible(page.getByRole("status").filter({ hasText: "You joined Acme Labs." }))
  await expectVisible(page.getByText("No invitations waiting for you."))
})

await check("the new member is in the organization's member list", async () => {
  await page.goto(`${BASE}/organizations`)
  // Accepting does not change the session's active organization.
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitemradio", { name: /Acme Labs/ }).click()
  const row = page.getByRole("listitem").filter({ hasText: INVITEE.name })
  await expectVisible(row.getByText("admin"))
  await expectVisible(page.getByRole("listitem").filter({ hasText: USER.name }).getByText("owner"))
})

const memberRow = (name) => page.getByRole("listitem").filter({ hasText: name })
const memberMenu = (name) => page.getByRole("button", { name: `Actions for ${name}` })

await check("the owner, signed back in, changes the new member's role", async () => {
  await signOutFromMenu(INVITEE.name)
  await page.waitForURL(/\/sign-in/, { timeout: 5000 })
  await page.goto(`${BASE}/sign-in?redirectTo=/organizations`)
  await page.getByLabel("Email").fill(USER.identifier)
  await page.getByLabel("Password").fill(USER.password)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await page.waitForURL(`${BASE}/organizations`, { timeout: 5000 })
  await page.getByRole("button", { name: /^Switch organization/ }).click()
  await page.getByRole("menuitemradio", { name: /Acme Labs/ }).click()
  await expectVisible(memberRow(INVITEE.name).getByText("admin"))
  await memberMenu(INVITEE.name).click()
  await page.getByRole("menuitemradio", { name: "member" }).click()
  await expectVisible(memberRow(INVITEE.name).getByRole("status").filter({ hasText: `${INVITEE.name} is now member.` }))
  await expectVisible(memberRow(INVITEE.name).getByText("member", { exact: true }))
})

await check("the last owner cannot demote themself, and the row says why", async () => {
  await memberMenu(USER.name).click()
  await page.getByRole("menuitemradio", { name: "admin" }).click()
  const alert = memberRow(USER.name).getByRole("alert")
  await expectVisible(alert)
  const text = (await alert.innerText()).trim()
  if (text !== LAST_OWNER) throw new Error(`row error says ${JSON.stringify(text)}`)
  // The error is linked to the row's menu button.
  const described = await memberMenu(USER.name).getAttribute("aria-describedby")
  if (described !== (await alert.getAttribute("id"))) throw new Error(`menu aria-describedby=${JSON.stringify(described)}`)
  await expectVisible(memberRow(USER.name).getByText("owner", { exact: true }))
})

await check("the last owner cannot leave either: confirmed, then refused", async () => {
  await memberMenu(USER.name).click()
  await page.getByRole("menuitem", { name: "Leave organization" }).click()
  const dialog = page.getByRole("alertdialog")
  await expectVisible(dialog.getByRole("heading", { name: "Leave Acme Labs?" }))
  await dialog.getByRole("button", { name: "Leave", exact: true }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
  const alert = memberRow(USER.name).getByRole("alert")
  await expectVisible(alert)
  const text = (await alert.innerText()).trim()
  if (text !== LAST_OWNER) throw new Error(`row error says ${JSON.stringify(text)}`)
  await expectVisible(page.getByText("People in Acme Labs."))
})

await check("removing a member asks first, and Keep changes nothing", async () => {
  await memberMenu(INVITEE.name).click()
  await page.getByRole("menuitem", { name: "Remove from organization" }).click()
  const dialog = page.getByRole("alertdialog")
  await expectVisible(dialog.getByRole("heading", { name: `Remove ${INVITEE.name}?` }))
  await dialog.getByRole("button", { name: "Keep" }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
  await expectVisible(memberRow(INVITEE.name))
})

await check("a confirmed removal takes the member off the list", async () => {
  await memberMenu(INVITEE.name).click()
  await page.getByRole("menuitem", { name: "Remove from organization" }).click()
  const dialog = page.getByRole("alertdialog")
  await dialog.getByRole("button", { name: "Remove", exact: true }).click()
  await dialog.waitFor({ state: "hidden", timeout: 5000 })
  await memberRow(INVITEE.name).waitFor({ state: "detached", timeout: 5000 })
  await expectVisible(memberRow(USER.name).getByText("owner", { exact: true }))
})

await browser.close()
console.log(`all ${step} steps passed; screenshots in ${OUT}`)

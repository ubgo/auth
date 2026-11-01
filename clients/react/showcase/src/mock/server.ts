// The mock server: a fetch that answers every route the registry components
// call, in the wire shapes of the generated client. Each handler is
// registered against the operation object of the client itself (on(op, …)),
// so its input and output are the client's own generated types: a handler
// that answered the wrong shape would not compile. Refusals carry real codes
// with the status and message of AUTH_ERROR_CODES. A route not listed here
// answers 404 with auth.resource_not_found, the way an unmounted route would.

import {
  AUTH_ERROR_CODES,
  admin,
  coreOps,
  email,
  magiclink,
  metadata,
  oauth,
  organization,
  passkey,
  password,
  terms,
  twofactor,
  type AdminUserSummary,
  type AuthErrorCode,
  type AuthSessionView,
  type AuthUserView,
  type Op,
  type OrganizationMemberView,
  type OrganizationOrgWithRole,
  type TwofactorStatus,
} from "@ubgo/auth-client"
import { DEMO_CODE, DEMO_PASSWORD, DEMO_RECOVERY_CODE, DEMO_TOKEN, type MockOrg, type MockUser, nextId, nowISO, save, send, state } from "./state.ts"

/** The base the showcase's client is created with; the mock strips it. */
export const MOCK_BASE_URL = "/auth"

/** The message every passkey and security-key ceremony answers with. */
export const NO_PASSKEYS_MESSAGE = "Passkeys and security keys need a real server and a browser prompt, so this mock cannot run them. Try them in the real demo."

/** Pauses that make the pending states visible: a normal call, and one with "slow network" on. */
const LATENCY_MS = 250
const SLOW_LATENCY_MS = 2500
/** The session lifetime the mock reports. */
const SESSION_DAYS = 30
const DAY = 86_400_000

/** A refusal: the code's status and message, or a custom message for the same code. */
class Refusal {
  constructor(
    readonly code: AuthErrorCode,
    readonly message?: string,
  ) {}
}

function refuse(code: AuthErrorCode, message?: string): never {
  throw new Refusal(code, message)
}

type Handler = (input: unknown) => unknown

const routes = new Map<string, Handler>()

/** Registers the handler of one operation, typed by the operation itself. */
function on<In, Out>(op: Op<In, Out>, handler: (input: In) => Out): void {
  // The wire input arrives as parsed JSON (or the query string's values), the
  // same boundary the Go server decodes into the request struct; the
  // handlers read only fields the operation declares.
  routes.set(`${op.method} ${op.path}`, (input) => handler(input as In))
}

const OK = { ok: true }

// ---------------------------------------------------------------- helpers

function me(): MockUser {
  const session = state.session
  if (session === null || session.pending) refuse("auth.signed_out")
  const user = state.users.find((u) => u.id === session.userId)
  if (user === undefined) refuse("auth.signed_out")
  return user
}

function pendingUser(): MockUser {
  const session = state.session
  if (session === null || !session.pending) refuse("auth.signed_out")
  const user = state.users.find((u) => u.id === session.userId)
  if (user === undefined) refuse("auth.signed_out")
  return user
}

function view(user: MockUser): AuthUserView {
  return { id: user.id, name: user.name, image: user.image }
}

function primaryEmail(user: MockUser): string {
  return user.emails.find((e) => e.primary)?.email ?? user.emails[0]?.email ?? ""
}

function findByIdentifier(identifier: string): MockUser | undefined {
  const wanted = identifier.trim().toLowerCase()
  return state.users.find((u) => u.emails.some((e) => e.email.toLowerCase() === wanted))
}

function startSession(user: MockUser, pending: boolean): void {
  state.session = { id: nextId("ses"), userId: user.id, pending, createdAt: nowISO(), impersonator: null }
  user.lastActiveAt = nowISO()
}

function expiresAt(): string {
  return new Date(Date.now() + SESSION_DAYS * DAY).toISOString()
}

function checkPassword(user: MockUser, given: string | undefined): void {
  if (given !== user.password) refuse("password.invalid_credentials")
}

function checkCode(code: string): void {
  const trimmed = code.trim().toUpperCase()
  if (trimmed !== DEMO_CODE && trimmed !== DEMO_RECOVERY_CODE) refuse("twofactor.code_invalid")
}

function checkToken(token: string): void {
  if (token !== DEMO_TOKEN) refuse("auth.token_invalid")
}

function recoveryCodes(): string[] {
  return [DEMO_RECOVERY_CODE, "MNOP-QRST-UVWX", "YZ12-3456-7890", "QWER-TYUI-OPAS", "DFGH-JKLZ-XCVB", "NMQW-ERTY-UIOP"]
}

function sessionsOf(user: MockUser): AuthSessionView[] {
  const current = state.session
  const list: AuthSessionView[] = [
    {
      id: current?.id ?? "ses_current",
      current: true,
      impersonated: current?.impersonator !== null && current?.impersonator !== undefined,
      ip: "203.0.113.24",
      userAgent: navigator.userAgent,
      createdAt: current?.createdAt ?? nowISO(),
      lastSeenAt: nowISO(),
    },
  ]
  if (user.id === "usr_ada") {
    list.push({
      id: "ses_phone",
      current: false,
      impersonated: false,
      ip: "198.51.100.7",
      userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      createdAt: new Date(Date.now() - 3 * DAY).toISOString(),
      lastSeenAt: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    })
  }
  return list
}

function twoFactorStatus(user: MockUser): TwofactorStatus {
  const factors: TwofactorStatus["factors"] = user.twoFactor ? [{ method: "totp", primary: true, createdAt: user.createdAt, lastUsedAt: null }] : []
  for (const key of user.id === state.session?.userId ? state.securityKeys : []) {
    factors.push({ method: "security_key", id: key.id, name: key.name, createdAt: key.createdAt, lastUsedAt: key.lastUsedAt })
  }
  const enabled = factors.length > 0
  return {
    enabled,
    ...(user.twoFactor ? { method: "totp" } : {}),
    methods: ["totp", "delivered", "security_key"],
    trustDevices: true,
    factors,
  }
}

function orgOf(orgId: string | undefined): MockOrg {
  const id = orgId ?? state.activeOrgId
  const found = state.orgs.find((o) => o.org.id === id)
  if (found === undefined) refuse("auth.resource_not_found")
  return found
}

function roleIn(org: MockOrg, user: MockUser): string {
  const member = org.members.find((m) => m.userId === user.id)
  if (member === undefined) refuse("organization.forbidden")
  return member.role
}

function summary(user: MockUser): AdminUserSummary {
  return {
    id: user.id,
    name: user.name,
    createdAt: user.createdAt,
    admin: user.admin,
    banned: user.banned,
    email: primaryEmail(user),
    roles: user.roles,
    lastActiveAt: user.lastActiveAt,
  }
}

function adminTarget(userId: string): MockUser {
  const caller = me()
  if (!caller.admin) refuse("admin.forbidden")
  const target = state.users.find((u) => u.id === userId)
  if (target === undefined) refuse("auth.user_not_found")
  return target
}

function passkeysUnavailable(): never {
  refuse("auth.internal", NO_PASSKEYS_MESSAGE)
}

// ------------------------------------------------------------------- core

on(coreOps.session, () => {
  const user = me()
  return { user: view(user), expiresAt: expiresAt(), tasks: [] }
})
on(coreOps.sessionRefresh, () => ({ user: view(me()), expiresAt: expiresAt() }))
on(coreOps.sessions, () => ({ sessions: sessionsOf(me()) }))
on(coreOps.sessionsRevoke, () => {
  me()
  return OK
})
on(coreOps.signOut, () => {
  if (state.session === null) refuse("auth.signed_out")
  state.session = null
  return OK
})
on(coreOps.signOutAll, () => {
  me()
  state.session = null
  return OK
})
on(coreOps.profile, (input) => {
  const user = me()
  if (typeof input.name === "string") user.name = input.name
  if (typeof input.image === "string") user.image = input.image
  return view(user)
})
on(coreOps.accountDelete, () => {
  me()
  send("Mail to confirm deleting the account (use the token demo-token).")
  return { deleted: false, confirmationSent: true }
})
on(coreOps.accountDeleteConfirm, (input) => {
  checkToken(input.token)
  return OK
})
on(coreOps.deviceSessions, () => {
  const user = me()
  return { sessions: [{ id: state.session?.id ?? "ses_current", user: view(user), active: true, expiresAt: expiresAt() }] }
})

// --------------------------------------------------------------- password

on(password().ops.signIn, (input) => {
  const user = findByIdentifier(input.identifier)
  // An unknown account and a wrong password answer the same, as the server does.
  if (user === undefined) refuse("password.invalid_credentials")
  checkPassword(user, input.password)
  if (user.banned) refuse("admin.banned")
  startSession(user, user.twoFactor)
  return { user: view(user), verificationRequired: false, secondFactorRequired: user.twoFactor }
})
on(password().ops.signUp, (input) => {
  if (findByIdentifier(input.identifier) !== undefined) refuse("auth.identity_taken")
  if (input.password.length < 8) refuse("password.too_short")
  const user: MockUser = {
    id: nextId("usr"),
    name: input.name ?? input.identifier.split("@")[0] ?? "",
    image: "",
    emails: [{ email: input.identifier.trim(), verified: true, primary: true }],
    password: input.password,
    twoFactor: false,
    admin: false,
    banned: false,
    banReason: "",
    roles: [],
    createdAt: nowISO(),
    lastActiveAt: nowISO(),
  }
  state.users.push(user)
  startSession(user, false)
  return { user: view(user), verificationRequired: false, secondFactorRequired: false }
})
on(password().ops.forgot, (input) => {
  send(`Reset link for ${input.identifier} (the reset page accepts the token demo-token).`)
  return { status: "sent" }
})
on(password().ops.reset, (input) => {
  checkToken(input.token)
  if (input.password.length < 8) refuse("password.too_short")
  return OK
})
on(password().ops.change, (input) => {
  const user = me()
  checkPassword(user, input.current)
  if (input.new.length < 8) refuse("password.too_short")
  user.password = input.new
  return OK
})
on(password().ops.verify, (input) => {
  checkPassword(me(), input.password)
  return OK
})
on(password().ops.reauthenticate, (input) => {
  checkPassword(me(), input.password)
  return { fresh: true, freshUntil: new Date(Date.now() + 600_000).toISOString(), secondFactorRequired: false }
})

// ------------------------------------------------------------------ email

on(email().ops.list, () => ({ addresses: me().emails }))
on(email().ops.add, (input) => {
  const user = me()
  if (findByIdentifier(input.email) !== undefined) refuse("auth.identity_taken")
  user.emails.push({ email: input.email, verified: false, primary: false })
  send(`Verification code ${DEMO_CODE} for ${input.email}.`)
  return OK
})
on(email().ops.change, (input) => {
  me()
  if (findByIdentifier(input.email) !== undefined) refuse("auth.identity_taken")
  send(`Confirm the change to ${input.email} (the confirm page accepts the token demo-token, or code ${DEMO_CODE}).`)
  return OK
})
on(email().ops.confirmChange, (input) => {
  checkToken(input.token)
  return { email: "new-address@example.com", signedIn: state.session !== null && !state.session.pending }
})
on(email().ops.confirmChangeCode, (input) => {
  checkCode(input.code)
  const user = me()
  const primary = user.emails.find((e) => e.primary)
  if (primary !== undefined) primary.email = input.email
  return { email: input.email, signedIn: true }
})
on(email().ops.undoChange, (input) => {
  checkToken(input.token)
  return OK
})
on(email().ops.makePrimary, (input) => {
  const user = me()
  for (const e of user.emails) e.primary = e.email === input.email
  return OK
})
on(email().ops.remove, (input) => {
  const user = me()
  user.emails = user.emails.filter((e) => e.email !== input.email || e.primary)
  return OK
})
on(email().ops.resend, (input) => {
  send(`Verification link for ${input.email} (the verify page accepts the token demo-token, or code ${DEMO_CODE}).`)
  return OK
})
on(email().ops.sendCode, (input) => {
  send(`Code ${DEMO_CODE} for ${input.email}.`)
  return OK
})
on(email().ops.verify, (input) => {
  checkToken(input.token)
  return { email: "ada@example.com", signedIn: false }
})
on(email().ops.verifyCode, (input) => {
  checkCode(input.code)
  const user = state.users.find((u) => u.emails.some((e) => e.email === input.email))
  const address = user?.emails.find((e) => e.email === input.email)
  if (address !== undefined) address.verified = true
  return { email: input.email, signedIn: false }
})
on(email().ops.checkCode, (input) => {
  checkCode(input.code)
  return OK
})

// -------------------------------------------------------------- magiclink

on(magiclink().ops.send, (input) => {
  send(`Sign-in link for ${input.identifier} (the callback page accepts the token demo-token).`)
  return OK
})
on(magiclink().ops.signIn, (input) => {
  checkToken(input.token)
  const user = state.users[0]
  if (user === undefined) refuse("auth.user_not_found")
  startSession(user, false)
  return { user: view(user), created: false, secondFactorRequired: false }
})

// -------------------------------------------------------------- twofactor

on(twofactor().ops.status, () => {
  const session = state.session
  const user = session !== null && session.pending ? pendingUser() : me()
  return twoFactorStatus(user)
})
on(twofactor().ops.verify, (input) => {
  pendingUser()
  checkCode(input.code)
  if (state.session !== null) state.session.pending = false
  return OK
})
on(twofactor().ops.send, () => {
  pendingUser()
  send(`Your sign-in code is ${DEMO_CODE}.`)
  return OK
})
on(twofactor().ops.enroll, (input) => {
  me()
  return {
    method: input.method ?? "totp",
    secret: "JBSWY3DPEHPK3PXP",
    url: "otpauth://totp/Showcase:ada%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Showcase&digits=6&period=30",
    enabled: false,
  }
})
on(twofactor().ops.confirm, (input) => {
  const user = me()
  checkCode(input.code)
  user.twoFactor = true
  return { codes: recoveryCodes() }
})
on(twofactor().ops.check, (input) => {
  me()
  checkCode(input.code)
  return OK
})
on(twofactor().ops.disable, (input) => {
  const user = me()
  if (input.password !== undefined) checkPassword(user, input.password)
  else checkCode(input.code)
  user.twoFactor = false
  state.securityKeys = []
  return OK
})
on(twofactor().ops.removeFactor, (input) => {
  const user = me()
  if (input.method === "totp") user.twoFactor = false
  else state.securityKeys = state.securityKeys.filter((k) => k.id !== input.id)
  return { enabled: user.twoFactor || state.securityKeys.length > 0 }
})
on(twofactor().ops.recoveryCodes, () => {
  me()
  return { codes: recoveryCodes() }
})
on(twofactor().ops.viewRecoveryCodes, (input) => {
  const user = me()
  if (input.password !== undefined) checkPassword(user, input.password)
  return { codes: recoveryCodes() }
})
on(twofactor().ops.totpUri, () => {
  me()
  return { totpURI: "otpauth://totp/Showcase:ada%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Showcase" }
})
on(twofactor().ops.devices, () => {
  me()
  return { devices: [] }
})
on(twofactor().ops.forgetDevice, () => {
  me()
  return OK
})
on(twofactor().ops.reauthenticate, (input) => {
  me()
  checkCode(input.code)
  return { fresh: true, freshUntil: new Date(Date.now() + 600_000).toISOString(), secondFactorRequired: false }
})
on(twofactor().ops.securityKeyChallenge, () => passkeysUnavailable())
on(twofactor().ops.securityKeyRegisterBegin, () => passkeysUnavailable())
on(twofactor().ops.securityKeyRegisterFinish, () => passkeysUnavailable())

// ---------------------------------------------------------------- passkey

on(passkey().ops.list, () => {
  me()
  return { passkeys: state.passkeys }
})
on(passkey().ops.rename, (input) => {
  me()
  const key = state.passkeys.find((p) => p.id === input.id)
  if (key === undefined) refuse("passkey.not_found")
  key.name = input.name
  return OK
})
on(passkey().ops.remove, (input) => {
  me()
  state.passkeys = state.passkeys.filter((p) => p.id !== input.id)
  return OK
})
on(passkey().ops.loginBegin, () => passkeysUnavailable())
on(passkey().ops.loginFinish, () => passkeysUnavailable())
on(passkey().ops.registerBegin, () => passkeysUnavailable())
on(passkey().ops.registerFinish, () => passkeysUnavailable())
on(passkey().ops.reauthenticateBegin, () => passkeysUnavailable())
on(passkey().ops.reauthenticateFinish, () => passkeysUnavailable())
on(passkey().ops.signUpBegin, () => passkeysUnavailable())
on(passkey().ops.signUpFinish, () => passkeysUnavailable())

// ------------------------------------------------------------------ oauth

on(oauth().ops.providers, () => ({
  providers: state.settings.oauth
    ? [
        { id: "github", name: "GitHub" },
        { id: "google", name: "Google" },
      ]
    : [],
}))
on(oauth().ops.accounts, () => {
  me()
  return { accounts: state.linked }
})
on(oauth().ops.unlink, (input) => {
  me()
  state.linked = state.linked.filter((a) => a.provider !== input.provider)
  return OK
})
on(oauth().ops.reauthenticate, (input) => {
  me()
  return { url: `${import.meta.env.BASE_URL}oauth/${input.provider}/start?reauth=1` }
})

// ------------------------------------------------------------------ terms

on(terms().ops.accept, () => OK)

// --------------------------------------------------------------- metadata

on(metadata().ops.get, () => {
  me()
  return { public: { plan: "pro" }, unsafe: { theme: "system" } }
})
on(metadata().ops.update, (input) => {
  me()
  return { public: { plan: "pro" }, unsafe: input.unsafe }
})
on(metadata().ops.adminGet, (input) => {
  adminTarget(input.userId)
  return { public: { plan: "pro" }, private: { stripeCustomer: "cus_demo" }, unsafe: { theme: "system" } }
})

// ----------------------------------------------------------- organization

const org = organization().ops

on(org.list, () => {
  const user = me()
  const orgs: OrganizationOrgWithRole[] = state.orgs
    .filter((o) => o.members.some((m) => m.userId === user.id))
    .map((o) => ({ ...o.org, role: roleIn(o, user) }))
  return { orgs }
})
on(org.active, () => {
  me()
  const active = state.orgs.find((o) => o.org.id === state.activeOrgId)
  return { activeOrganizationId: state.activeOrgId, activeTeamId: null, organization: active?.org ?? null }
})
on(org.setActive, (input) => {
  const user = me()
  if (input.orgId === undefined && input.orgSlug === undefined) {
    state.activeOrgId = null
    return { activeOrganizationId: null, activeTeamId: null, organization: null }
  }
  const found = state.orgs.find((o) => o.org.id === input.orgId || o.org.slug === input.orgSlug)
  if (found === undefined) refuse("auth.resource_not_found")
  roleIn(found, user)
  state.activeOrgId = found.org.id
  return { activeOrganizationId: found.org.id, activeTeamId: null, organization: found.org }
})
on(org.create, (input) => {
  const user = me()
  if (state.orgs.some((o) => o.org.slug === input.slug)) refuse("organization.slug_taken")
  const created: MockOrg = {
    org: { id: nextId("org"), slug: input.slug, name: input.name, logo: input.logo ?? null, createdAt: nowISO() },
    members: [{ userId: user.id, role: "owner", joinedAt: nowISO() }],
    invitations: [],
    domains: [],
  }
  state.orgs.push(created)
  if (input.keepCurrentActiveOrganization !== true) state.activeOrgId = created.org.id
  return created.org
})
on(org.checkSlug, (input) => ({ slug: input.slug, available: !state.orgs.some((o) => o.org.slug === input.slug) }))
on(org.members, (input) => {
  me()
  const found = orgOf(input.orgId)
  const members: OrganizationMemberView[] = found.members.flatMap((m) => {
    const user = state.users.find((u) => u.id === m.userId)
    return user === undefined ? [] : [{ user: view(user), role: m.role, joinedAt: m.joinedAt }]
  })
  return { members, total: members.length, page: 1, limit: 50 }
})
on(org.listInvitations, (input) => {
  me()
  return { invitations: orgOf(input.orgId).invitations }
})
on(org.invite, (input) => {
  const user = me()
  const found = orgOf(input.orgId)
  const address = input.email ?? input.identifier ?? ""
  if (found.invitations.some((i) => i.email === address && !input.resend)) refuse("auth.identity_taken")
  found.invitations.push({
    id: nextId("inv"),
    orgId: found.org.id,
    email: address,
    kind: "email",
    identifier: address,
    role: input.role,
    status: "pending",
    inviterId: user.id,
    teamId: null,
    expiresAt: new Date(Date.now() + 7 * DAY).toISOString(),
    createdAt: nowISO(),
  })
  send(`Invitation to ${found.org.name} for ${address}.`)
  return OK
})
on(org.cancel, (input) => {
  me()
  for (const o of state.orgs) o.invitations = o.invitations.filter((i) => i.id !== input.inviteId)
  return OK
})
on(org.removeMember, (input) => {
  me()
  const found = orgOf(input.orgId)
  found.members = found.members.filter((m) => m.userId !== input.userId)
  return OK
})
on(org.setRole, (input) => {
  me()
  const member = orgOf(input.orgId).members.find((m) => m.userId === input.userId)
  if (member === undefined) refuse("auth.user_not_found")
  member.role = input.role
  return OK
})
on(org.hasPermission, (input) => {
  const user = me()
  const role = roleIn(orgOf(input.orgId), user)
  return { success: role === "owner" || role === "admin" }
})
on(org.role, (input) => {
  const user = me()
  return { role: roleIn(orgOf(input.orgId), user) }
})
on(org.invites, () => {
  me()
  return { invites: state.received }
})
on(org.accept, (input) => {
  const user = me()
  const invite = state.received.find((i) => i.id === input.inviteId)
  if (invite === undefined) refuse("auth.token_invalid")
  state.received = state.received.filter((i) => i.id !== input.inviteId)
  const joined: MockOrg = {
    org: { id: invite.orgId, slug: invite.orgName.toLowerCase().replace(/[^a-z0-9]+/g, "-"), name: invite.orgName, logo: null, createdAt: nowISO() },
    members: [{ userId: user.id, role: invite.role, joinedAt: nowISO() }],
    invitations: [],
    domains: [],
  }
  state.orgs.push(joined)
  return joined.org
})
on(org.reject, (input) => {
  me()
  state.received = state.received.filter((i) => i.id !== input.inviteId)
  return OK
})
on(org.listDomains, (input) => {
  me()
  return { domains: orgOf(input.orgId).domains }
})
on(org.addDomain, (input) => {
  me()
  const found = orgOf(input.orgId)
  if (found.domains.some((d) => d.domain === input.domain)) refuse("organization.domain_taken")
  const domain = {
    id: nextId("dom"),
    orgId: found.org.id,
    domain: input.domain,
    enrollmentMode: input.enrollmentMode ?? "request",
    role: input.role ?? "member",
    verified: false,
    verifiedAt: null,
    recordName: `_ubgo-auth.${input.domain}`,
    recordValue: `ubgo-auth-verification=${Math.random().toString(16).slice(2, 8)}`,
    createdAt: nowISO(),
  }
  found.domains.push(domain)
  return domain
})
on(org.verifyDomain, (input) => {
  me()
  const domain = state.orgs.flatMap((o) => o.domains).find((d) => d.id === input.domainId)
  if (domain === undefined) refuse("organization.domain_not_found")
  domain.verified = true
  domain.verifiedAt = nowISO()
  return domain
})
on(org.updateDomain, (input) => {
  me()
  const domain = state.orgs.flatMap((o) => o.domains).find((d) => d.id === input.domainId)
  if (domain === undefined) refuse("organization.domain_not_found")
  if (typeof input.enrollmentMode === "string") domain.enrollmentMode = input.enrollmentMode
  if (typeof input.role === "string") domain.role = input.role
  return domain
})
on(org.removeDomain, (input) => {
  me()
  for (const o of state.orgs) o.domains = o.domains.filter((d) => d.id !== input.domainId)
  return OK
})
on(org.listMembershipRequests, () => {
  me()
  const linus = state.users.find((u) => u.id === "usr_linus")
  return {
    requests:
      linus === undefined
        ? []
        : [{ id: "req_1", orgId: "org_acme", domainId: "dom_1", domain: "acme.test", user: view(linus), status: "pending", createdAt: nowISO() }],
  }
})
on(org.approveMembershipRequest, () => {
  me()
  return OK
})
on(org.rejectMembershipRequest, () => {
  me()
  return OK
})
on(org.domainSuggestions, () => {
  me()
  return { suggestions: state.suggestions }
})
on(org.acceptSuggestion, (input) => {
  const user = me()
  const suggestion = state.suggestions.find((s) => s.domainId === input.domainId)
  if (suggestion === undefined) refuse("organization.domain_not_found")
  suggestion.requested = true
  return {
    id: nextId("req"),
    orgId: suggestion.orgId,
    domainId: suggestion.domainId,
    domain: suggestion.domain,
    user: view(user),
    status: "pending",
    createdAt: nowISO(),
  }
})

// ------------------------------------------------------------------ admin

const adm = admin().ops

on(adm.hasPermission, () => ({ success: me().admin }))
function usersPage(query: string | undefined, page: string | undefined, limit: string | undefined, banned: string | undefined, isAdmin: string | undefined) {
  const caller = me()
  if (!caller.admin) refuse("admin.forbidden")
  const needle = (query ?? "").trim().toLowerCase()
  const matched = state.users.filter(
    (u) =>
      (needle === "" || u.name.toLowerCase().includes(needle) || primaryEmail(u).toLowerCase().includes(needle)) &&
      (banned === undefined || String(u.banned) === banned) &&
      (isAdmin === undefined || String(u.admin) === isAdmin),
  )
  const size = Math.max(1, Number(limit ?? "10") || 10)
  const current = Math.max(1, Number(page ?? "1") || 1)
  const offset = (current - 1) * size
  return { users: matched.slice(offset, offset + size).map(summary), total: matched.length, page: current, limit: size, offset }
}
on(adm.users, (input) => usersPage(input.query, input.page, input.limit, input.banned, input.admin))
on(adm.searchUsers, (input) => usersPage(input.value, input.page, input.limit, input.banned, input.admin))
on(adm.user, (input) => {
  const target = adminTarget(input.userId)
  return {
    user: summary(target),
    banReason: target.banReason,
    identities: target.emails.map((e) => ({ kind: "email", value: e.email, verified: e.verified, primary: e.primary })),
    sessions: target.id === "usr_ada" ? 2 : 1,
  }
})
on(adm.sessions, (input) => ({ sessions: sessionsOf(adminTarget(input.userId)) }))
on(adm.twoFactor, (input) => {
  const target = adminTarget(input.userId)
  return { enrolled: target.twoFactor, enabled: target.twoFactor, method: target.twoFactor ? "totp" : "" }
})
on(adm.ban, (input) => {
  const target = adminTarget(input.userId)
  if (target.id === state.session?.userId) refuse("admin.self_target")
  target.banned = true
  target.banReason = input.reason ?? ""
  return OK
})
on(adm.unban, (input) => {
  const target = adminTarget(input.userId)
  target.banned = false
  target.banReason = ""
  return OK
})
on(adm.setRole, (input) => {
  const target = adminTarget(input.userId)
  target.roles = input.role ?? []
  return OK
})
on(adm.setAdmin, (input) => {
  const target = adminTarget(input.userId)
  target.admin = input.admin
  return OK
})
on(adm.setPassword, (input) => {
  const target = adminTarget(input.userId)
  if (input.password.length < 8) refuse("password.too_short")
  target.password = input.password
  return OK
})
on(adm.setEmail, (input) => {
  const target = adminTarget(input.userId)
  const primary = target.emails.find((e) => e.primary)
  if (primary !== undefined) primary.email = input.email
  return OK
})
on(adm.updateUser, (input) => {
  const target = adminTarget(input.userId)
  if (typeof input.name === "string") target.name = input.name
  return OK
})
on(adm.revokeSession, (input) => {
  adminTarget(input.userId)
  return OK
})
on(adm.revokeSessions, (input) => {
  adminTarget(input.userId)
  return OK
})
on(adm.removeUser, (input) => {
  const target = adminTarget(input.userId)
  if (target.id === state.session?.userId) refuse("admin.self_target")
  state.users = state.users.filter((u) => u.id !== target.id)
  return OK
})
on(adm.enableTwoFactor, (input) => {
  adminTarget(input.userId).twoFactor = true
  return OK
})
on(adm.disableTwoFactor, (input) => {
  adminTarget(input.userId).twoFactor = false
  return OK
})
on(adm.resetTwoFactor, (input) => {
  adminTarget(input.userId).twoFactor = false
  return OK
})
on(adm.impersonate, (input) => {
  const caller = me()
  const target = adminTarget(input.userId)
  if (target.id === caller.id) refuse("admin.self_target")
  state.session = { id: nextId("ses"), userId: target.id, pending: false, createdAt: nowISO(), impersonator: caller.id }
  return { user: view(target), expiresAt: new Date(Date.now() + 3_600_000).toISOString() }
})
on(adm.stopImpersonating, () => {
  const session = state.session
  if (session === null || session.impersonator === null) refuse("admin.not_impersonating")
  state.session = { id: nextId("ses"), userId: session.impersonator, pending: false, createdAt: nowISO(), impersonator: null }
  return { ok: true, restored: true }
})

// ------------------------------------------------------------------ fetch

/** Every route the mock answers, as "METHOD /path", for the showcase's own check. */
export function mockRoutes(): string[] {
  return [...routes.keys()].sort()
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })
}

function errorBody(code: AuthErrorCode, message?: string): Response {
  const declared = AUTH_ERROR_CODES[code]
  return json(declared.status, { error: { code, message: message ?? declared.message } })
}

function inputOf(url: URL, init: RequestInit | undefined): unknown {
  if ((init?.method ?? "GET") === "GET") return Object.fromEntries(url.searchParams)
  if (typeof init?.body !== "string" || init.body === "") return {}
  const parsed: unknown = JSON.parse(init.body)
  return parsed
}

function wait(ms: number, signal: AbortSignal | null | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener("abort", () => {
      clearTimeout(timer)
      reject(new DOMException("The request was aborted.", "AbortError"))
    })
  })
}

/**
 * The fetch the showcase's client is created with: answers from the routes
 * above after a short pause, and never touches the network.
 */
export const mockFetch: typeof globalThis.fetch = async (resource, init) => {
  const url = new URL(resource instanceof Request ? resource.url : String(resource), window.location.origin)
  await wait(state.settings.slow ? SLOW_LATENCY_MS : LATENCY_MS, init?.signal)
  const path = url.pathname.startsWith(MOCK_BASE_URL) ? url.pathname.slice(MOCK_BASE_URL.length) : url.pathname
  const handler = routes.get(`${init?.method ?? "GET"} ${path}`)
  if (handler === undefined) return errorBody("auth.resource_not_found", `The mock has no route ${path}.`)
  try {
    const body = handler(inputOf(url, init))
    save()
    return json(200, body)
  } catch (thrown) {
    if (thrown instanceof Refusal) {
      save()
      return errorBody(thrown.code, thrown.message)
    }
    throw thrown
  }
}

/** The demo password, re-exported for the pages that show the credentials. */
export { DEMO_PASSWORD }

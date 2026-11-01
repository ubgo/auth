// The mock server's data: a few users, their sessions, passkeys, linked
// accounts and organizations, kept in memory and mirrored to sessionStorage
// so a full page load (an OAuth button's redirect) keeps who is signed in.
// Everything here is invented; nothing leaves the browser.

import type {
  EmailAddress,
  OauthAccount,
  OrganizationDomainSuggestion,
  OrganizationInvitation,
  OrganizationInvite,
  OrganizationOrg,
  OrganizationOrgDomain,
  PasskeyPasskey,
  TwofactorSecurityKey,
} from "@ubgo/auth-client"

/** The password every demo account accepts, shown on the page. */
export const DEMO_PASSWORD = "correct horse battery staple"
/** The account without a second factor. */
export const DEMO_EMAIL = "ada@example.com"
/** The account with an authenticator app on, so sign-in asks for a code. */
export const DEMO_2FA_EMAIL = "grace@example.com"
/** The one code the mock accepts for every second factor and emailed code. */
export const DEMO_CODE = "123456"
/** The one recovery code the mock accepts. */
export const DEMO_RECOVERY_CODE = "ABCD-EFGH-IJKL"
/** The token every mailed-link page accepts; any other token is expired. */
export const DEMO_TOKEN = "demo-token"

/** A mock account: what the server would hold across several tables. */
export interface MockUser {
  id: string
  name: string
  image: string
  emails: EmailAddress[]
  password: string
  twoFactor: boolean
  admin: boolean
  banned: boolean
  banReason: string
  roles: string[]
  createdAt: string
  lastActiveAt: string | null
}

/** The browser's session: a pending one waits for the second factor. */
export interface MockSession {
  id: string
  userId: string
  pending: boolean
  createdAt: string
  /** The admin who started this session by impersonating, if any. */
  impersonator: string | null
}

/** One organization with its rows. */
export interface MockOrg {
  org: OrganizationOrg
  members: { userId: string; role: string; joinedAt: string }[]
  invitations: OrganizationInvitation[]
  domains: OrganizationOrgDomain[]
}

/** Switches the showcase's stage controls set. */
export interface MockSettings {
  /** Answer every call after a long pause, to show the pending states. */
  slow: boolean
  /** Whether the server lists OAuth providers, which turns the OAuth buttons on. */
  oauth: boolean
}

export interface MockState {
  users: MockUser[]
  session: MockSession | null
  passkeys: PasskeyPasskey[]
  securityKeys: TwofactorSecurityKey[]
  linked: OauthAccount[]
  orgs: MockOrg[]
  activeOrgId: string | null
  received: OrganizationInvite[]
  suggestions: OrganizationDomainSuggestion[]
  /** The last message the mock "sent", shown in a toast so mailed flows can be followed. */
  outbox: string[]
  settings: MockSettings
  seq: number
}

const STORAGE_KEY = "ubgo-auth-showcase.mock"
const DAY = 86_400_000

function daysAgo(days: number): string {
  return new Date(Date.now() - days * DAY).toISOString()
}

/** A fresh copy of the seeded data. */
export function seed(): MockState {
  const ada = "usr_ada"
  const grace = "usr_grace"
  const linus = "usr_linus"
  const margaret = "usr_margaret"
  const user = (id: string, name: string, email: string, extra: Partial<MockUser>): MockUser => ({
    id,
    name,
    image: "",
    emails: [{ email, verified: true, primary: true }],
    password: DEMO_PASSWORD,
    twoFactor: false,
    admin: false,
    banned: false,
    banReason: "",
    roles: [],
    createdAt: daysAgo(120),
    lastActiveAt: daysAgo(1),
    ...extra,
  })
  const acme: MockOrg = {
    org: { id: "org_acme", slug: "acme", name: "Acme Inc.", logo: null, createdAt: daysAgo(90) },
    members: [
      { userId: ada, role: "owner", joinedAt: daysAgo(90) },
      { userId: grace, role: "admin", joinedAt: daysAgo(60) },
      { userId: linus, role: "member", joinedAt: daysAgo(12) },
    ],
    invitations: [
      {
        id: "inv_1",
        orgId: "org_acme",
        email: "alan@example.com",
        kind: "email",
        identifier: "alan@example.com",
        role: "member",
        status: "pending",
        inviterId: ada,
        teamId: null,
        expiresAt: new Date(Date.now() + 6 * DAY).toISOString(),
        createdAt: daysAgo(1),
      },
    ],
    domains: [
      {
        id: "dom_1",
        orgId: "org_acme",
        domain: "acme.test",
        enrollmentMode: "request",
        role: "member",
        verified: true,
        verifiedAt: daysAgo(30),
        recordName: "_ubgo-auth.acme.test",
        recordValue: "ubgo-auth-verification=8f2c1d",
        createdAt: daysAgo(31),
      },
    ],
  }
  const labs: MockOrg = {
    org: { id: "org_labs", slug: "analytical-labs", name: "Analytical Labs", logo: null, createdAt: daysAgo(40) },
    members: [{ userId: ada, role: "member", joinedAt: daysAgo(40) }],
    invitations: [],
    domains: [],
  }
  return {
    users: [
      user(ada, "Ada Lovelace", DEMO_EMAIL, { admin: true, roles: ["admin"] }),
      user(grace, "Grace Hopper", DEMO_2FA_EMAIL, { twoFactor: true }),
      user(linus, "Linus Pauling", "linus@example.com", {}),
      user(margaret, "Margaret Hamilton", "margaret@example.com", { banned: true, banReason: "Spam reports", lastActiveAt: daysAgo(20) }),
    ],
    session: null,
    passkeys: [
      {
        id: "pk_1",
        name: "MacBook Touch ID",
        createdAt: daysAgo(30),
        lastUsedAt: daysAgo(2),
        aaguid: "adce0002-35bc-c60a-648b-0b25f1f05503",
        backedUp: true,
        transports: ["internal", "hybrid"],
      },
    ],
    securityKeys: [],
    linked: [{ id: "acc_1", provider: "github", email: DEMO_EMAIL, createdAt: daysAgo(50), scopes: ["read:user", "user:email"] }],
    orgs: [acme, labs],
    activeOrgId: "org_acme",
    received: [
      {
        id: "inv_9",
        orgId: "org_globex",
        orgName: "Globex Corporation",
        email: DEMO_EMAIL,
        kind: "email",
        identifier: DEMO_EMAIL,
        role: "member",
        expiresAt: new Date(Date.now() + 5 * DAY).toISOString(),
      },
    ],
    suggestions: [
      { domainId: "dom_77", orgId: "org_initech", orgName: "Initech", orgSlug: "initech", domain: "example.com", requested: false },
    ],
    outbox: [],
    settings: { slow: false, oauth: true },
    seq: 100,
  }
}

function load(): MockState {
  try {
    const saved = sessionStorage.getItem(STORAGE_KEY)
    if (saved !== null) {
      // Written by save() below from this same type; a shape from an older
      // build is caught by the version check and replaced.
      const parsed: unknown = JSON.parse(saved)
      if (isState(parsed)) return parsed
    }
  } catch {
    // Storage blocked (a private window): start from the seed.
  }
  return seed()
}

function isState(value: unknown): value is MockState {
  return typeof value === "object" && value !== null && "users" in value && "settings" in value && "seq" in value && "securityKeys" in value
}

/** The live state. Handlers mutate it, then call save(). */
export const state: MockState = load()

const listeners = new Set<() => void>()

/** Persists the state and tells the showcase's controls it changed. */
export function save(): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  } catch {
    // Storage blocked: the state still lives for this page.
  }
  for (const listener of listeners) listener()
}

/** Puts the seed back: signed out, every demo row restored. */
export function reset(): void {
  Object.assign(state, seed())
  save()
}

/** Subscribes to changes, for useSyncExternalStore. */
export function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** A new id with a prefix, unique within this state. */
export function nextId(prefix: string): string {
  state.seq += 1
  return `${prefix}_${state.seq}`
}

/** Records a message the mock pretends to have sent. */
export function send(message: string): void {
  state.outbox = [message, ...state.outbox].slice(0, 5)
}

export function nowISO(): string {
  return new Date().toISOString()
}

/** Who the stage starts as: signed out, signed in, or halfway through a two-factor sign-in. */
export type MockSessionKind = "signed-out" | "ada" | "grace" | "grace-pending"

/** Puts the browser's session in one of the demo states. */
export function setSession(kind: MockSessionKind): void {
  if (kind === "signed-out") {
    state.session = null
  } else {
    const userId = kind === "ada" ? "usr_ada" : "usr_grace"
    state.session = { id: nextId("ses"), userId, pending: kind === "grace-pending", createdAt: nowISO(), impersonator: null }
  }
  save()
}

/** The session's state as one of the demo kinds, for the stage's switcher; "other" for a new account or an impersonation. */
export function sessionKind(): MockSessionKind | "other" {
  const session = state.session
  if (session === null) return "signed-out"
  if (session.impersonator !== null) return "other"
  if (session.userId === "usr_ada") return "ada"
  if (session.userId === "usr_grace") return session.pending ? "grace-pending" : "grace"
  return "other"
}

/** Ada (an admin) impersonating Linus, the state the impersonation banner shows in. */
export function setImpersonation(): void {
  state.session = { id: nextId("ses"), userId: "usr_linus", pending: false, createdAt: nowISO(), impersonator: "usr_ada" }
  save()
}

/** Changes the stage's switches. */
export function setSettings(next: Partial<MockSettings>): void {
  state.settings = { ...state.settings, ...next }
  save()
}

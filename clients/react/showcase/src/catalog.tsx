// One entry per registry component: what the page shows on its stage, the
// states worth clicking through, and the snippet an app copies. The names
// are the registry item names, which are also the page paths and the
// r/<name>.json files.

import { useState, type ReactNode } from "react"
import { AccountSettings } from "@/components/auth/account-settings"
import { AdminUserDetail } from "@/components/auth/admin-user-detail"
import { AdminUsersTable } from "@/components/auth/admin-users-table"
import { ConfirmEmailChange } from "@/components/auth/confirm-email-change"
import { DomainSuggestions } from "@/components/auth/domain-suggestions"
import { ForgotPasswordForm } from "@/components/auth/forgot-password-form"
import { ImpersonationBanner } from "@/components/auth/impersonation-banner"
import { MagicLinkCallback } from "@/components/auth/magic-link-callback"
import { OrganizationDomains } from "@/components/auth/organization-domains"
import { OrganizationInvitations } from "@/components/auth/organization-invitations"
import { OrganizationMembers } from "@/components/auth/organization-members"
import { OrganizationSwitcher } from "@/components/auth/organization-switcher"
import { AddPasskey, PasskeyList } from "@/components/auth/passkey-list"
import { PasswordStrength } from "@/components/auth/password-strength"
import { ResetPasswordForm } from "@/components/auth/reset-password-form"
import { SecurityKeys } from "@/components/auth/security-keys"
import { SignInForm } from "@/components/auth/sign-in-form"
import { SignUpForm } from "@/components/auth/sign-up-form"
import { TaskSetupMFA } from "@/components/auth/task-setup-mfa"
import { TwoFactorChallenge } from "@/components/auth/two-factor-challenge"
import { TwoFactorSetup } from "@/components/auth/two-factor-setup"
import { UserButton } from "@/components/auth/user-button"
import { VerifyEmail } from "@/components/auth/verify-email"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { DEMO_TOKEN, setImpersonation, setSession, setSettings, type MockSessionKind } from "@/mock/state"

/** Where the site is published; the install lines point here. */
export const SITE_URL = "https://ubgo.github.io/auth"
export const REPO_URL = "https://github.com/ubgo/auth"
/** How to run the real demo, with the Go server. */
export const REAL_DEMO_URL = `${REPO_URL}/tree/main/examples/react-demo#readme`
export const CLIENT_DOCS_URL = `${REPO_URL}/tree/main/docs/client`

/** A token the mock refuses, for the "expired link" states. */
const EXPIRED_TOKEN = "expired-token"

export type Group = "Sign in" | "Recovery" | "Second factor" | "Account" | "Organizations" | "Admin"
export const GROUPS: readonly Group[] = ["Sign in", "Recovery", "Second factor", "Account", "Organizations", "Admin"]

/** One state of a component on the stage. */
export interface Variant {
  readonly id: string
  readonly label: string
  /** Puts the mock in the state this variant needs (who is signed in, the switches). */
  readonly prepare: () => void
  readonly render: (query: URLSearchParams) => ReactNode
}

/** One "pretend signed in as" choice on a page, with what it changes there (the button's tooltip). */
export interface SessionChoice {
  readonly kind: MockSessionKind
  readonly note: string
}

/**
 * The mock controls that change what a page shows. Only these appear above
 * its stage, so no control does nothing: a page the session does not affect
 * has no session row, and one with no controls at all has no mock bar.
 * Measured by switching each control on every page and comparing the stage.
 */
export interface MockControls {
  /** The sessions worth trying here, in order; omitted when the session changes nothing. */
  readonly sessions?: readonly SessionChoice[]
  /** The component calls the mock, so a slow network shows its pending state. */
  readonly slow?: boolean
  /** The component lists OAuth providers, so switching them off changes it. */
  readonly oauth?: boolean
}

export interface Entry {
  /** The registry item name: the page path and r/<name>.json. */
  readonly name: string
  readonly title: string
  readonly group: Group
  readonly description: string
  /** "wide" for tables and settings pages, "narrow" for a card. */
  readonly width: "narrow" | "wide"
  /** The mock controls shown above the stage. */
  readonly mock: MockControls
  readonly variants: readonly Variant[]
  /** Steps a visitor can follow on the stage. */
  readonly tryThis: readonly string[]
  readonly usage: string
}

/** The install line of one registry item. */
export function installCommand(name: string): string {
  return `npx shadcn@latest add ${SITE_URL}/r/${name}.json`
}

/** A variant preparer: who is signed in, with the switches at their defaults unless given. */
function as(kind: MockSessionKind, settings: { slow?: boolean; oauth?: boolean } = {}): () => void {
  return () => {
    setSettings({ slow: settings.slow ?? false, oauth: settings.oauth ?? true })
    setSession(kind)
  }
}

function impersonating(): void {
  setSettings({ slow: false, oauth: true })
  setImpersonation()
}

function PasswordStrengthDemo({ initial }: { initial: string }) {
  const [value, setValue] = useState(initial)
  return (
    <div className="grid w-full gap-1.5 rounded-xl border bg-card p-4">
      <Label htmlFor="pw-demo">Password</Label>
      <Input id="pw-demo" type="text" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Type a password" autoComplete="off" />
      <PasswordStrength value={value} />
    </div>
  )
}

export const CATALOG: readonly Entry[] = [
  {
    name: "sign-in-form",
    title: "Sign in form",
    group: "Sign in",
    description: "Password, magic link, passkey and OAuth sign-in in one card. Each method shows only when its plugin is in the client, and a second factor sends the user to the two-factor step.",
    width: "narrow",
    mock: { slow: true, oauth: true },
    variants: [
      { id: "default", label: "Default", prepare: as("signed-out"), render: () => <SignInForm headingLevel={2} autoFocus={false} /> },
      { id: "no-oauth", label: "Without OAuth", prepare: as("signed-out", { oauth: false }), render: () => <SignInForm headingLevel={2} autoFocus={false} /> },
      { id: "magic-link", label: "Magic link mode", prepare: as("signed-out"), render: () => <SignInForm headingLevel={2} defaultMode="magiclink" autoFocus={false} /> },
      { id: "pending", label: "Slow network", prepare: as("signed-out", { slow: true }), render: () => <SignInForm headingLevel={2} autoFocus={false} /> },
    ],
    tryThis: [
      "Sign in as ada@example.com with the demo password: the page says where your app would go next, and “Go there” opens account settings.",
      "Type a wrong password: the server's password.invalid_credentials message shows above the form.",
      "Sign in as grace@example.com: her account has an authenticator app, so the next stop is the two-factor step (“Go there”, then code 123456).",
      "Pick “Slow network” to see the pending button, or press a passkey or OAuth button to see what the mock answers.",
    ],
    usage: `import { SignInForm } from "@/components/auth/sign-in-form"

export function SignInPage() {
  return <SignInForm redirectTo="/dashboard" />
}`,
  },
  {
    name: "sign-up-form",
    title: "Sign up form",
    group: "Sign in",
    description: "Creates an account with a password (and a name, username or terms checkbox when configured), with a live strength meter and the OAuth buttons.",
    width: "narrow",
    mock: { slow: true, oauth: true },
    variants: [
      { id: "default", label: "Default", prepare: as("signed-out"), render: () => <SignUpForm headingLevel={2} autoFocus={false} /> },
      {
        id: "terms",
        label: "With terms",
        prepare: as("signed-out"),
        render: () => <SignUpForm headingLevel={2} autoFocus={false} nameField="optional" terms={{ version: "2026-01", href: "#terms" }} />,
      },
      { id: "no-oauth", label: "Without OAuth", prepare: as("signed-out", { oauth: false }), render: () => <SignUpForm headingLevel={2} autoFocus={false} /> },
    ],
    tryThis: ["Sign up with any new address and a password of eight or more characters: you are signed in.", "Use ada@example.com: the server answers auth.identity_taken.", "Watch the strength meter while typing the password."],
    usage: `import { SignUpForm } from "@/components/auth/sign-up-form"

export function SignUpPage() {
  return <SignUpForm nameField="required" redirectTo="/welcome" />
}`,
  },
  {
    name: "password-strength",
    title: "Password strength",
    group: "Sign in",
    description: "The meter the sign-up and reset forms show under the password field. Pure: it scores the value in the browser and calls no server.",
    width: "narrow",
    mock: {},
    variants: [
      { id: "empty", label: "Empty", prepare: as("signed-out"), render: () => <PasswordStrengthDemo initial="" /> },
      { id: "weak", label: "Weak", prepare: as("signed-out"), render: () => <PasswordStrengthDemo initial="password1" /> },
      { id: "strong", label: "Strong", prepare: as("signed-out"), render: () => <PasswordStrengthDemo initial="correct horse battery staple" /> },
    ],
    tryThis: ["Type in the field and watch the bar and the hint change."],
    usage: `import { PasswordStrength } from "@/components/auth/password-strength"

<PasswordStrength value={password} minLength={8} />`,
  },
  {
    name: "magic-link-callback",
    title: "Magic link callback",
    group: "Sign in",
    description: "The page a mailed sign-in link opens: it reads the token, signs in, and redirects, or explains an expired link.",
    width: "narrow",
    mock: { slow: true },
    variants: [
      { id: "valid", label: "Valid link", prepare: as("signed-out"), render: () => <MagicLinkCallback headingLevel={2} token={DEMO_TOKEN} redirectTo="/user-button" /> },
      { id: "expired", label: "Expired link", prepare: as("signed-out"), render: () => <MagicLinkCallback headingLevel={2} token={EXPIRED_TOKEN} /> },
    ],
    tryThis: ["“Valid link” signs Ada in; the page says your app would go to the user button page, “Go there” opens it, and “Run again” uses the link again.", "“Expired link” shows the auth.token_invalid state with a way back to sign in."],
    usage: `import { MagicLinkCallback } from "@/components/auth/magic-link-callback"

// Route: /magic-link?token=… (the token is read from the URL)
export function MagicLinkPage() {
  return <MagicLinkCallback redirectTo="/dashboard" />
}`,
  },
  {
    name: "forgot-password-form",
    title: "Forgot password form",
    group: "Recovery",
    description: "Asks for the address and sends a reset link. The answer is the same for a known and an unknown account, so it never tells who has one.",
    width: "narrow",
    mock: { slow: true },
    variants: [
      { id: "default", label: "Default", prepare: as("signed-out"), render: () => <ForgotPasswordForm headingLevel={2} autoFocus={false} /> },
      { id: "prefilled", label: "Prefilled", prepare: as("signed-out"), render: () => <ForgotPasswordForm headingLevel={2} autoFocus={false} defaultIdentifier="ada@example.com" /> },
      { id: "pending", label: "Slow network", prepare: as("signed-out", { slow: true }), render: () => <ForgotPasswordForm headingLevel={2} autoFocus={false} defaultIdentifier="ada@example.com" /> },
    ],
    tryThis: ["Send a link for any address: the confirmation screen shows, and the mock outbox below the stage lists the link."],
    usage: `import { ForgotPasswordForm } from "@/components/auth/forgot-password-form"

export function ForgotPasswordPage() {
  return <ForgotPasswordForm resetPageURL="https://app.example.com/reset-password" />
}`,
  },
  {
    name: "reset-password-form",
    title: "Reset password form",
    group: "Recovery",
    description: "The page a reset link opens: a new password with the strength meter, then sign in. An expired link gets its own state.",
    width: "narrow",
    mock: { slow: true },
    variants: [
      { id: "valid", label: "Valid link", prepare: as("signed-out"), render: () => <ResetPasswordForm headingLevel={2} token={DEMO_TOKEN} autoFocus={false} /> },
      { id: "confirm", label: "With confirm field", prepare: as("signed-out"), render: () => <ResetPasswordForm headingLevel={2} token={DEMO_TOKEN} confirmPassword autoFocus={false} /> },
      { id: "expired", label: "Expired link", prepare: as("signed-out"), render: () => <ResetPasswordForm headingLevel={2} token={EXPIRED_TOKEN} autoFocus={false} /> },
    ],
    tryThis: ["Choose a new password of eight or more characters and submit.", "On “Expired link”, submit to see auth.token_invalid."],
    usage: `import { ResetPasswordForm } from "@/components/auth/reset-password-form"

// Route: /reset-password?token=…
export function ResetPasswordPage() {
  return <ResetPasswordForm confirmPassword />
}`,
  },
  {
    name: "verify-email",
    title: "Verify email",
    group: "Recovery",
    description: "Verifies an address from a mailed link, or with a typed code, and offers to send another.",
    width: "narrow",
    mock: { slow: true },
    variants: [
      { id: "link", label: "From a link", prepare: as("signed-out"), render: () => <VerifyEmail headingLevel={2} token={DEMO_TOKEN} /> },
      { id: "expired", label: "Expired link", prepare: as("signed-out"), render: () => <VerifyEmail headingLevel={2} token={EXPIRED_TOKEN} /> },
      { id: "code", label: "Enter a code", prepare: as("signed-out"), render: () => <VerifyEmail headingLevel={2} /> },
    ],
    tryThis: ["“From a link” verifies at once.", "“Enter a code” takes any address and the code 123456."],
    usage: `import { VerifyEmail } from "@/components/auth/verify-email"

// Route: /verify-email?token=…
export function VerifyEmailPage() {
  return <VerifyEmail />
}`,
  },
  {
    name: "two-factor-challenge",
    title: "Two-factor challenge",
    group: "Second factor",
    description: "The second step of a sign-in: an authenticator or delivered code, a recovery code, or a security key, with “trust this device”.",
    width: "narrow",
    mock: { sessions: [{ kind: "grace-pending", note: "Grace typed her password and still owes a code: 123456 finishes signing in." }, { kind: "signed-out", note: "No sign-in is waiting for a code: the page says the sign-in expired." }], slow: true },
    variants: [
      { id: "code", label: "Code", prepare: as("grace-pending"), render: () => <TwoFactorChallenge headingLevel={2} autoFocus={false} redirectTo="/account-settings" /> },
      { id: "eight", label: "Eight digits", prepare: as("grace-pending"), render: () => <TwoFactorChallenge headingLevel={2} digits={8} autoFocus={false} autoSubmit={false} /> },
      { id: "expired", label: "Session expired", prepare: as("signed-out"), render: () => <TwoFactorChallenge headingLevel={2} autoFocus={false} /> },
    ],
    tryThis: ["Type 123456: Grace's sign-in finishes, and the page says your app would open account settings.", "Type any other code to see twofactor.code_invalid under the field.", "Switch to a recovery code and use ABCD-EFGH-IJKL."],
    usage: `import { TwoFactorChallenge } from "@/components/auth/two-factor-challenge"

// The sign-in form navigates here when the account has a second factor.
export function TwoFactorPage() {
  return <TwoFactorChallenge redirectTo="/dashboard" />
}`,
  },
  {
    name: "two-factor-setup",
    title: "Two-factor setup",
    group: "Second factor",
    description: "Turns on an authenticator app: QR code and secret, a confirming code, then recovery codes to save. Also lists and removes factors.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Ada has no second factor yet: you can turn on an authenticator app." }, { kind: "grace", note: "Grace already has an authenticator app: it shows as on." }, { kind: "signed-out", note: "Signed out: the page asks you to sign in first." }], slow: true },
    variants: [
      { id: "off", label: "Not enabled", prepare: as("ada"), render: () => <TwoFactorSetup headingLevel={2} /> },
      { id: "on", label: "Enabled", prepare: as("grace"), render: () => <TwoFactorSetup headingLevel={2} /> },
      { id: "password", label: "Password required", prepare: as("ada"), render: () => <TwoFactorSetup headingLevel={2} requirePassword /> },
    ],
    tryThis: ["Start the setup, then confirm with 123456: the recovery codes appear.", "On “Enabled”, the factor list shows Grace's authenticator."],
    usage: `import { TwoFactorSetup } from "@/components/auth/two-factor-setup"

<TwoFactorSetup requirePassword />`,
  },
  {
    name: "task-setup-mfa",
    title: "Required two-factor setup",
    group: "Second factor",
    description: "The page a session with an open setup-mfa task is sent to: the setup, then on to where the user was going.",
    width: "narrow",
    mock: { slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <TaskSetupMFA headingLevel={2} /> }],
    tryThis: ["Set up the authenticator and confirm with 123456."],
    usage: `import { TaskSetupMFA } from "@/components/auth/task-setup-mfa"

// Route: paths.setupTwoFactor (/setup-two-factor by default)
export function SetupTwoFactorPage() {
  return <TaskSetupMFA />
}`,
  },
  {
    name: "security-keys",
    title: "Security keys",
    group: "Second factor",
    description: "Hardware security keys as a second factor: the list, add and remove. Registering one needs a browser ceremony against a real server.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Ada's security keys: add one or remove one." }, { kind: "signed-out", note: "Signed out: there are no keys to list." }], slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <SecurityKeys headingLevel={2} /> }],
    tryThis: ["Press add: the mock explains that security keys need a real server."],
    usage: `import { SecurityKeys } from "@/components/auth/security-keys"

<SecurityKeys />`,
  },
  {
    name: "passkey-list",
    title: "Passkeys",
    group: "Second factor",
    description: "The signed-in user's passkeys: rename, remove and add. AddPasskey is the same button on its own.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Ada's passkeys: add one or remove one." }, { kind: "signed-out", note: "Signed out: there are no passkeys to list." }], slow: true },
    variants: [
      { id: "list", label: "List", prepare: as("ada"), render: () => <PasskeyList headingLevel={2} /> },
      { id: "add", label: "Add button only", prepare: as("ada"), render: () => <AddPasskey /> },
    ],
    tryThis: ["Rename the MacBook passkey from its menu.", "Press add: the mock explains that passkeys need a real server and a browser prompt."],
    usage: `import { PasskeyList } from "@/components/auth/passkey-list"

<PasskeyList authenticatorAttachment="platform" />`,
  },
  {
    name: "user-button",
    title: "User button",
    group: "Account",
    description: "The avatar menu for a header: name, address, account link and sign-out; a sign-in button when signed out.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Ada's avatar and menu." }, { kind: "grace", note: "Grace's avatar and menu." }, { kind: "signed-out", note: "Signed out: a sign-in link instead of the avatar." }], slow: true },
    variants: [
      { id: "signed-in", label: "Signed in", prepare: as("ada"), render: () => <UserButton accountHref="/account-settings" /> },
      { id: "with-name", label: "With name", prepare: as("ada"), render: () => <UserButton showName accountHref="/account-settings" /> },
      { id: "signed-out", label: "Signed out", prepare: as("signed-out"), render: () => <UserButton /> },
    ],
    tryThis: ["Open the menu and sign out: the page says your app would go to the sign-in form.", "“Signed out” shows the sign-in button instead."],
    usage: `import { UserButton } from "@/components/auth/user-button"

<header className="flex items-center justify-between">
  <Logo />
  <UserButton showName accountHref="/account" />
</header>`,
  },
  {
    name: "account-settings",
    title: "Account settings",
    group: "Account",
    description: "Profile, email, password, two-factor, passkeys, sessions, linked accounts and delete account on one page. Each section is also exported alone.",
    width: "wide",
    mock: { sessions: [{ kind: "ada", note: "Ada's account: no second factor yet." }, { kind: "grace", note: "Grace's account: her authenticator app shows as on." }, { kind: "signed-out", note: "Signed out: the page asks you to sign in first." }], slow: true, oauth: true },
    variants: [
      { id: "all", label: "All sections", prepare: as("ada"), render: () => <AccountSettings headingLevel={2} /> },
      { id: "some", label: "Profile and password", prepare: as("ada"), render: () => <AccountSettings headingLevel={2} sections={["profile", "password"]} /> },
      { id: "code", label: "Email change by code", prepare: as("ada"), render: () => <AccountSettings headingLevel={2} sections={["email"]} confirmEmailChangeBy="code" /> },
    ],
    tryThis: ["Change the name and save.", "Change the password: the current one is the demo password; a wrong one is refused.", "Revoke the iPhone session, unlink GitHub, or start deleting the account."],
    usage: `import { AccountSettings } from "@/components/auth/account-settings"

export function AccountPage() {
  return <AccountSettings />
}

// Or one section on its own:
import { PasswordSection } from "@/components/auth/account-settings"
<PasswordSection revokeOthersDefault />`,
  },
  {
    name: "confirm-email-change",
    title: "Confirm email change",
    group: "Account",
    description: "The pages the two mails of an address change open: confirm the new address, or undo the change from the old one.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Signed in: after the link, the page offers the account page." }, { kind: "signed-out", note: "Signed out: after the link, the page offers sign-in." }], slow: true },
    variants: [
      { id: "confirm", label: "Confirm", prepare: as("ada"), render: () => <ConfirmEmailChange headingLevel={2} token={DEMO_TOKEN} /> },
      { id: "undo", label: "Undo", prepare: as("ada"), render: () => <ConfirmEmailChange headingLevel={2} action="undo" token={DEMO_TOKEN} /> },
      { id: "expired", label: "Expired link", prepare: as("ada"), render: () => <ConfirmEmailChange headingLevel={2} token={EXPIRED_TOKEN} /> },
    ],
    tryThis: ["Each state runs as soon as it opens; “Expired link” shows the token error."],
    usage: `import { ConfirmEmailChange } from "@/components/auth/confirm-email-change"

// Route: /confirm-email-change?token=…  and  /undo-email-change?token=…
<ConfirmEmailChange />
<ConfirmEmailChange action="undo" />`,
  },
  {
    name: "organization-switcher",
    title: "Organization switcher",
    group: "Organizations",
    description: "Picks the session's active organization, or a personal account, and creates a new one.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Ada's organizations, to switch between." }, { kind: "signed-out", note: "Signed out: there are no organizations to show." }], slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <OrganizationSwitcher /> }],
    tryThis: ["Switch to Analytical Labs.", "Create an organization: the slug is checked as you type."],
    usage: `import { OrganizationSwitcher } from "@/components/auth/organization-switcher"

<OrganizationSwitcher />`,
  },
  {
    name: "organization-members",
    title: "Organization members",
    group: "Organizations",
    description: "The active organization's members with their roles, pending invitations, and an invite form; actions follow the caller's role.",
    width: "wide",
    mock: { sessions: [{ kind: "ada", note: "Ada owns Acme Inc.: she can change roles and remove members." }, { kind: "grace", note: "Grace is an admin of Acme Inc.: she sees what an admin may do." }, { kind: "signed-out", note: "Signed out: the member list does not load." }], slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <OrganizationMembers headingLevel={2} /> }],
    tryThis: ["Invite someone as a member: the invitation appears under pending.", "Change Linus's role, or remove him."],
    usage: `import { OrganizationMembers } from "@/components/auth/organization-members"

<OrganizationMembers inviteRoles={["member", "admin"]} />`,
  },
  {
    name: "organization-invitations",
    title: "Organization invitations",
    group: "Organizations",
    description: "The invitations the signed-in user has received, to accept or decline.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Signed in: the invitations for Ada's organization." }, { kind: "signed-out", note: "Signed out: the invitations do not load." }], slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <OrganizationInvitations headingLevel={2} /> }],
    tryThis: ["Accept the Globex invitation: it joins the switcher's list."],
    usage: `import { OrganizationInvitations } from "@/components/auth/organization-invitations"

<OrganizationInvitations />`,
  },
  {
    name: "organization-domains",
    title: "Organization domains",
    group: "Organizations",
    description: "An organization's email domains: add one, publish the DNS record, verify it, and choose how people with that address join.",
    width: "wide",
    mock: { sessions: [{ kind: "ada", note: "Ada owns Acme Inc.: she can add and verify domains." }, { kind: "signed-out", note: "Signed out: the domains do not load." }], slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <OrganizationDomains headingLevel={2} /> }],
    tryThis: ["Add a domain: its DNS record shows; verify it from the menu.", "Approve or decline Linus's request to join."],
    usage: `import { OrganizationDomains } from "@/components/auth/organization-domains"

<OrganizationDomains defaultEnrollmentMode="request" />`,
  },
  {
    name: "domain-suggestions",
    title: "Domain suggestions",
    group: "Organizations",
    description: "Organizations a user could ask to join because their verified address is on that organization's domain.",
    width: "narrow",
    mock: { sessions: [{ kind: "ada", note: "Signed in as Ada: organizations her address's domain can join." }, { kind: "signed-out", note: "Signed out: there is nothing to suggest." }], slow: true },
    variants: [{ id: "default", label: "Default", prepare: as("ada"), render: () => <DomainSuggestions headingLevel={2} /> }],
    tryThis: ["Ask to join Initech: the button turns into “requested”."],
    usage: `import { DomainSuggestions } from "@/components/auth/domain-suggestions"

<DomainSuggestions />`,
  },
  {
    name: "admin-users-table",
    title: "Admin users table",
    group: "Admin",
    description: "Every user a page at a time, with search, filters, sort and pagination, for an administrator.",
    width: "wide",
    mock: { sessions: [{ kind: "ada", note: "Ada is an admin: the full user list." }, { kind: "grace", note: "Grace is not an admin: the table says she may not see it." }, { kind: "signed-out", note: "Signed out: the admin pages refuse." }], slow: true },
    variants: [
      { id: "default", label: "Admin", prepare: as("ada"), render: () => <AdminUsersTable headingLevel={2} userHref={(id) => `/admin-user-detail?user=${encodeURIComponent(id)}`} /> },
      { id: "forbidden", label: "Not an admin", prepare: as("grace"), render: () => <AdminUsersTable headingLevel={2} /> },
    ],
    tryThis: ["Search for “ha”, filter by banned, or open a user.", "“Not an admin” shows the admin.forbidden state."],
    usage: `import { AdminUsersTable } from "@/components/auth/admin-users-table"

<AdminUsersTable userHref={(id) => \`/admin/users/\${id}\`} />`,
  },
  {
    name: "admin-user-detail",
    title: "Admin user detail",
    group: "Admin",
    description: "One user for an administrator: identities, sessions, second factor, and the actions (ban, role, password, impersonate, delete).",
    width: "wide",
    mock: { sessions: [{ kind: "ada", note: "Ada is an admin: the user's details and actions." }, { kind: "grace", note: "Grace is not an admin: the page says she may not see it." }, { kind: "signed-out", note: "Signed out: the admin pages refuse." }], slow: true },
    variants: [
      { id: "default", label: "Linus", prepare: as("ada"), render: (query) => <AdminUserDetail headingLevel={2} userId={query.get("user") ?? "usr_linus"} backHref="/admin-users-table" /> },
      { id: "banned", label: "Banned user", prepare: as("ada"), render: () => <AdminUserDetail headingLevel={2} userId="usr_margaret" backHref="/admin-users-table" /> },
    ],
    tryThis: ["Ban Linus with a reason, then unban him.", "Impersonate him: the session switches, and the impersonation banner page lets you stop."],
    usage: `import { AdminUserDetail } from "@/components/auth/admin-user-detail"

<AdminUserDetail userId={params.userId} backHref="/admin/users" />`,
  },
  {
    name: "impersonation-banner",
    title: "Impersonation banner",
    group: "Admin",
    description: "A bar across the top of the app while an administrator is signed in as someone else, with a button to stop.",
    width: "wide",
    mock: { slow: true },
    variants: [
      { id: "on", label: "Impersonating", prepare: impersonating, render: () => <ImpersonationBanner adminHref="/admin-users-table" /> },
      { id: "off", label: "Normal session", prepare: as("ada"), render: () => <ImpersonationBanner /> },
    ],
    tryThis: ["Press stop: the session goes back to Ada.", "With a normal session the banner renders nothing."],
    usage: `import { ImpersonationBanner } from "@/components/auth/impersonation-banner"

// At the top of the app layout; renders nothing for a normal session.
<ImpersonationBanner adminHref="/admin/users" />`,
  },
]

export function entryNamed(name: string): Entry | undefined {
  return CATALOG.find((e) => e.name === name)
}

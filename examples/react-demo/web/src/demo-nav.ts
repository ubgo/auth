// Every demo route: its path, its sidebar label and its group. router.tsx
// maps each path to a page (and fails to compile for a path not listed
// here); scripts/shots.mjs screenshots each one, which is why this file has
// no JSX. Integrator-owned: a component agent sends its entry.

export type DemoNavItem = {
  readonly path: string
  readonly label: string
  readonly group: "Start" | "Sign in" | "Recovery" | "Second factor" | "Account" | "Organizations" | "Admin" | "Demo tools"
  /** A page a mailed link opens; reached from the Inbox, so it is not in the sidebar. */
  readonly hidden?: boolean
}

export const DEMO_NAV = [
  { path: "/", label: "Overview", group: "Start" },
  { path: "/sign-in", label: "Sign in", group: "Sign in" },
  { path: "/sign-up", label: "Sign up", group: "Sign in" },
  { path: "/magic-link", label: "Magic link callback", group: "Sign in" },
  { path: "/forgot-password", label: "Forgot password", group: "Recovery" },
  { path: "/reset-password", label: "Reset password", group: "Recovery" },
  { path: "/verify-email", label: "Verify email", group: "Recovery" },
  { path: "/two-factor", label: "Two-factor challenge", group: "Second factor" },
  { path: "/two-factor/setup", label: "Two-factor setup", group: "Second factor" },
  { path: "/passkeys", label: "Passkeys", group: "Second factor" },
  { path: "/setup-two-factor", label: "Required setup", group: "Second factor" },
  { path: "/account", label: "Account settings", group: "Account" },
  { path: "/account-sections", label: "Account sections", group: "Account" },
  { path: "/user-button", label: "User button", group: "Account" },
  { path: "/confirm-email-change", label: "Confirm email change", group: "Account", hidden: true },
  { path: "/undo-email-change", label: "Undo email change", group: "Account", hidden: true },
  { path: "/organizations", label: "Switcher and members", group: "Organizations" },
  { path: "/invitations", label: "Invitations", group: "Organizations" },
  { path: "/admin", label: "Users", group: "Admin" },
  { path: "/inbox", label: "Inbox", group: "Demo tools" },
] as const satisfies readonly DemoNavItem[]

export type DemoPath = (typeof DEMO_NAV)[number]["path"]

/** Every path, for scripts/shots.mjs. */
export const DEMO_PATHS: readonly DemoPath[] = DEMO_NAV.map((item) => item.path)

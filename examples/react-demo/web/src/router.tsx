// The demo's routes. Integrator-owned: a component agent writes its page in
// routes/<name>.tsx and sends the integrator its line here (and its entry in
// demo-nav.ts). Every path must be in DEMO_NAV, or page() does not compile.

import { createRootRoute, createRoute, createRouter } from "@tanstack/react-router"
import type { JSX } from "react"

import { DemoShell } from "@/components/demo-shell"
import type { DemoPath } from "@/demo-nav"
import { HomePage } from "@/routes/home"
import { InboxPage } from "@/routes/inbox"
import { AccountPage } from "@/routes/account"
import { AdminPage } from "@/routes/admin"
import { AccountSectionsPage } from "@/routes/account-sections"
import { ConfirmEmailChangePage } from "@/routes/confirm-email-change"
import { ForgotPasswordPage } from "@/routes/forgot-password"
import { InvitationsPage } from "@/routes/invitations"
import { MagicLinkPage } from "@/routes/magic-link"
import { OrganizationsPage } from "@/routes/organizations"
import { PasskeysPage } from "@/routes/passkeys"
import { ResetPasswordPage } from "@/routes/reset-password"
import { SetupTwoFactorPage } from "@/routes/setup-two-factor"
import { SignInPage } from "@/routes/sign-in"
import { SignUpPage } from "@/routes/sign-up"
import { TwoFactorPage } from "@/routes/two-factor"
import { TwoFactorSetupPage } from "@/routes/two-factor-setup"
import { UndoEmailChangePage } from "@/routes/undo-email-change"
import { UserButtonPage } from "@/routes/user-button"
import { VerifyEmailPage } from "@/routes/verify-email"

const rootRoute = createRootRoute({ component: DemoShell })

function page(path: DemoPath, component: () => JSX.Element) {
  return createRoute({ getParentRoute: () => rootRoute, path, component })
}

// ds:def id=routes-72e2hh2j owner=@khanakia stability=stable
const routes = [
  page("/", HomePage),
  page("/sign-in", SignInPage),
  page("/sign-up", SignUpPage),
  page("/magic-link", MagicLinkPage),
  page("/forgot-password", ForgotPasswordPage),
  page("/reset-password", ResetPasswordPage),
  page("/verify-email", VerifyEmailPage),
  page("/two-factor", TwoFactorPage),
  page("/two-factor/setup", TwoFactorSetupPage),
  page("/passkeys", PasskeysPage),
  page("/setup-two-factor", SetupTwoFactorPage),
  page("/account", AccountPage),
  page("/account-sections", AccountSectionsPage),
  page("/user-button", UserButtonPage),
  page("/confirm-email-change", ConfirmEmailChangePage),
  page("/undo-email-change", UndoEmailChangePage),
  page("/organizations", OrganizationsPage),
  page("/invitations", InvitationsPage),
  page("/admin", AdminPage),
  page("/inbox", InboxPage),
]

export const router = createRouter({ routeTree: rootRoute.addChildren(routes) })

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}

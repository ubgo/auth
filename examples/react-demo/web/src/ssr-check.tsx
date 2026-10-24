// Renders every registry component to HTML the way a server-rendering app
// (Next, TanStack Start, Remix) does on its first request, where there is no
// window, no document and no location. scripts/ssr.mjs loads this module
// through Vite and fails when any component throws while rendering; task
// ui:check runs it. Not part of the demo's bundle: index.html never imports
// it.
//
// A component may read the address bar only inside an effect, an event
// handler, or behind `typeof window === "undefined"`. ReauthDialog once read
// window.location in its render body, which crashed every server render of
// a page holding AccountSettings.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { AuthProvider } from "@ubgo/auth-react"
import type { ReactElement } from "react"
import { renderToString } from "react-dom/server"

import { auth } from "./auth.ts"
import { AccountSettings, ACCOUNT_SETTINGS_TEXT, ReauthDialog } from "./components/auth/account-settings.tsx"
import { AdminUserDetail } from "./components/auth/admin-user-detail.tsx"
import { AdminUsersTable } from "./components/auth/admin-users-table.tsx"
import { ConfirmEmailChange } from "./components/auth/confirm-email-change.tsx"
import { DomainSuggestions } from "./components/auth/domain-suggestions.tsx"
import { ForgotPasswordForm } from "./components/auth/forgot-password-form.tsx"
import { ImpersonationBanner } from "./components/auth/impersonation-banner.tsx"
import { MagicLinkCallback } from "./components/auth/magic-link-callback.tsx"
import { OrganizationDomains } from "./components/auth/organization-domains.tsx"
import { OrganizationInvitations } from "./components/auth/organization-invitations.tsx"
import { OrganizationMembers } from "./components/auth/organization-members.tsx"
import { OrganizationSwitcher } from "./components/auth/organization-switcher.tsx"
import { PasskeyList } from "./components/auth/passkey-list.tsx"
import { ResetPasswordForm } from "./components/auth/reset-password-form.tsx"
import { SecurityKeys } from "./components/auth/security-keys.tsx"
import { SignInForm } from "./components/auth/sign-in-form.tsx"
import { SignUpForm } from "./components/auth/sign-up-form.tsx"
import { TaskSetupMFA } from "./components/auth/task-setup-mfa.tsx"
import { TwoFactorChallenge } from "./components/auth/two-factor-challenge.tsx"
import { TwoFactorSetup } from "./components/auth/two-factor-setup.tsx"
import { UserButton } from "./components/auth/user-button.tsx"
import { VerifyEmail } from "./components/auth/verify-email.tsx"

/** One component to render, by the name a failure reports. */
type Case = { readonly name: string; readonly element: ReactElement }

/** Does nothing: the dialog is rendered closed, so no handler runs. */
function ignore(): void {}

const CASES: readonly Case[] = [
  { name: "SignInForm", element: <SignInForm redirectTo="/account" /> },
  { name: "SignUpForm", element: <SignUpForm /> },
  { name: "ForgotPasswordForm", element: <ForgotPasswordForm /> },
  { name: "ResetPasswordForm", element: <ResetPasswordForm /> },
  { name: "VerifyEmail", element: <VerifyEmail /> },
  { name: "MagicLinkCallback", element: <MagicLinkCallback /> },
  { name: "ConfirmEmailChange", element: <ConfirmEmailChange /> },
  { name: "TwoFactorChallenge", element: <TwoFactorChallenge /> },
  { name: "TwoFactorSetup", element: <TwoFactorSetup /> },
  { name: "PasskeyList", element: <PasskeyList /> },
  { name: "UserButton", element: <UserButton /> },
  { name: "OrganizationSwitcher", element: <OrganizationSwitcher /> },
  { name: "OrganizationMembers", element: <OrganizationMembers /> },
  { name: "OrganizationInvitations", element: <OrganizationInvitations /> },
  { name: "AccountSettings", element: <AccountSettings /> },
  { name: "AdminUsersTable", element: <AdminUsersTable /> },
  { name: "AdminUserDetail", element: <AdminUserDetail userId="usr_ssr" /> },
  { name: "ImpersonationBanner", element: <ImpersonationBanner /> },
  { name: "TaskSetupMFA", element: <TaskSetupMFA /> },
  { name: "SecurityKeys", element: <SecurityKeys /> },
  { name: "OrganizationDomains", element: <OrganizationDomains /> },
  { name: "DomainSuggestions", element: <DomainSuggestions /> },
  { name: "ReauthDialog", element: <ReauthDialog t={ACCOUNT_SETTINGS_TEXT} open={false} onOpenChange={ignore} onDone={ignore} /> },
]

/** Renders each case in its own provider and cache; resolves to one line per component that threw. */
export function renderAll(): readonly string[] {
  const failures: string[] = []
  for (const c of CASES) {
    try {
      // The demo's own shape (main.tsx): the app's QueryClientProvider,
      // which the components' mutations read, with AuthProvider inside it.
      renderToString(
        <QueryClientProvider client={new QueryClient()}>
          <AuthProvider client={auth}>{c.element}</AuthProvider>
        </QueryClientProvider>,
      )
    } catch (err) {
      failures.push(`${c.name}: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  return failures
}

/** How many components renderAll renders, for the summary line. */
export const CASE_COUNT = CASES.length

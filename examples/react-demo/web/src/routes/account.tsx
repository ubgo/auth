// /account: AccountSettings for the signed-in user, every section the demo's
// plugins allow. Signed out, the page says so and links to sign-in, coming
// back here afterwards.

import { SignedIn, SignedOut } from "@ubgo/auth-react"

import { AccountSettings, type AccountSettingsSlot } from "@/components/auth/account-settings"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<AccountSettingsSlot, string>> = {
  root: "max-w-3xl",
  section: "rounded-2xl shadow-sm",
  submit: "rounded-full",
  action: "rounded-full",
  badge: "rounded-md",
}

const CUSTOM_CODE = `<AccountSettings
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function AccountPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Account settings"
      description="Profile, email, password, two-factor, passkeys, sessions, connected accounts and deletion. Each section shows only when its plugin is on, and each is exported on its own."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href="/sign-in?redirectTo=/account">Sign in</RouterLink> as the demo user.
        </>,
        <>Change your name and save: the avatar in the user button follows.</>,
        <>
          Change the email: the confirmation link lands in the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Sign in from a second browser, then sign that session out under Sessions.</>,
        <>Change the password with "Sign out of other devices" ticked.</>,
        <>
          After ten minutes, a protected change asks for your password again instead of failing.
        </>,
        <>
          <b>Delete account</b> asks you to type <code>delete</code>, then signs you out.
        </>,
      ]}
    >
      <SignedIn>
        <AccountSettings classNames={custom ? CUSTOM : undefined} hideHeader headingLevel={2} />
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in?redirectTo=/account" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          to manage your account.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

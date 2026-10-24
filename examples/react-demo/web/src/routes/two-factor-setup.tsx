// /two-factor/setup: TwoFactorSetup for the signed-in user. Signed out, the
// page says so and links to sign-in, coming back here afterwards.

import { SignedIn, SignedOut } from "@ubgo/auth-react"

import { TwoFactorSetup, type TwoFactorSetupSlot } from "@/components/auth/two-factor-setup"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<TwoFactorSetupSlot, string>> = {
  root: "max-w-lg rounded-2xl shadow-lg",
  qr: "rounded-xl",
  primaryButton: "rounded-full",
  secondaryButton: "rounded-full",
}

const CUSTOM_CODE = `<TwoFactorSetup
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function TwoFactorSetupPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Two-factor setup"
      description="Turn the authenticator-app factor on and off: QR code and key, a first code, then recovery codes shown once with copy and download."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href="/sign-in?redirectTo=/two-factor/setup">Sign in</RouterLink> first; changing the factor needs a recent sign-in.
        </>,
        <>
          <b>Turn on</b>, scan the code with any authenticator app (or copy the key), and type the six digits.
        </>,
        <>Copy or download the recovery codes, tick that you saved them, then Done.</>,
        <>
          Sign out and in again: the <RouterLink href="/two-factor">challenge</RouterLink> asks for a code.
        </>,
        <>
          <b>New recovery codes</b> and <b>Turn off</b> each ask for a current code first.
        </>,
      ]}
    >
      <SignedIn>
        <TwoFactorSetup headingLevel={2} classNames={custom ? CUSTOM : undefined} />
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in?redirectTo=/two-factor/setup" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          to manage two-factor authentication.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

// /two-factor: TwoFactorChallenge, where a sign-in with a pending second
// factor lands. redirectTo comes from the query string, which SignInForm
// carries along when it hands off.

import { TwoFactorChallenge, type TwoFactorChallengeSlot } from "@/components/auth/two-factor-challenge"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<TwoFactorChallengeSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
  otpSlot: "size-11 text-lg",
  submit: "rounded-full",
}

const CUSTOM_CODE = `<TwoFactorChallenge
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function TwoFactorPage() {
  const { custom } = useDemoCustomise()
  const redirectTo = new URLSearchParams(window.location.search).get("redirectTo") ?? undefined
  return (
    <DemoPage
      title="Two-factor challenge"
      description="The second step of a sign-in: a code from the authenticator app, or a recovery code. It asks the server which kind and whether this device can be trusted."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          Turn on two-factor in <RouterLink href="/two-factor/setup">Two-factor setup</RouterLink>, sign out, then <RouterLink href="/sign-in">sign in</RouterLink>: the form hands off to this page.
        </>,
        <>Type or paste the six digits: it submits on the last one. A wrong code clears the boxes and says why.</>,
        <>
          <b>Use a recovery code</b> takes one of the codes you saved; each works once.
        </>,
        <>Open this page signed out, or wait ten minutes: it says the sign-in timed out and offers the way back.</>,
      ]}
    >
      <TwoFactorChallenge redirectTo={redirectTo} headingLevel={2} classNames={custom ? CUSTOM : undefined} />
    </DemoPage>
  )
}

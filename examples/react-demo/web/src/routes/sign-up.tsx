// /sign-up: SignUpForm with the demo server's plugins, the terms checkbox
// (the server runs terms.Current("2026-09")) and the verify-your-email mail.

import { SignUpForm, type SignUpFormSlot } from "@/components/auth/sign-up-form"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"
import { DEMO_USER } from "@/demo-user"

/** The version the demo server's terms plugin is set to; sent with the sign-up. */
const TERMS_VERSION = "2026-09"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<SignUpFormSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
  submit: "rounded-full",
  providerButton: "rounded-full",
  strength: "gap-1.5",
}

const CUSTOM_CODE = `<SignUpForm
  terms={{
    version: "${TERMS_VERSION}",
    href: "/terms",
    privacyHref: "/privacy",
  }}
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function SignUpPage() {
  const { custom } = useDemoCustomise()
  const redirectTo = new URLSearchParams(window.location.search).get("redirectTo") ?? undefined
  return (
    <DemoPage
      title="Sign up"
      description="Password sign-up with fields from the client's plugins, a strength hint, the terms checkbox and the verify-your-email mail."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>Submit empty: every field says what it needs, and focus lands on the first. Each error clears as you fix it.</>,
        <>Type a password and watch the meter; it is a hint, the server's policy decides.</>,
        <>
          Create an account with a new address: you land signed in, and a verification mail waits in the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>
          Sign up again with <code>{DEMO_USER.email}</code>: it answers like any other address and mails the owner instead, so nobody learns who has an account.
        </>,
        <>Switch Language to Deutsch and Appearance to Custom in the panel below.</>,
      ]}
    >
      <SignUpForm
        redirectTo={redirectTo}
        terms={{ version: TERMS_VERSION, href: "/terms", privacyHref: "/privacy" }}
        classNames={custom ? CUSTOM : undefined}
        headingLevel={2}
      />
    </DemoPage>
  )
}

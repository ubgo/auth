// /verify-email: the page the verification link opens. VerifyEmail reads
// ?token= from the address itself; without one it offers a new link.

import { VerifyEmail, type VerifyEmailSlot } from "@/components/auth/verify-email"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<VerifyEmailSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
  submit: "rounded-full",
  action: "rounded-full",
}

const CUSTOM_CODE = `<VerifyEmail
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function VerifyEmailPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Verify email"
      description="The page a verification link opens: it spends the token in exactly one call, and offers a new link when it expired."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          Create an account on <RouterLink href="/sign-up">Sign up</RouterLink>, then open the verification link from the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Reload the verified page: the link is spent, so the card offers to mail a new one.</>,
        <>Opened here without a link, the card is the "send a new link" form; it answers the same for every address.</>,
        <>Switch Language to Deutsch and Appearance to Custom in the panel below.</>,
      ]}
    >
      <VerifyEmail classNames={custom ? CUSTOM : undefined} headingLevel={2} />
    </DemoPage>
  )
}

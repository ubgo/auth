// /forgot-password: ForgotPasswordForm. The mailed link opens /reset-password.

import { ForgotPasswordForm, type ForgotPasswordFormSlot } from "@/components/auth/forgot-password-form"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"
import { DEMO_USER } from "@/demo-user"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<ForgotPasswordFormSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
  submit: "rounded-full",
  secondary: "rounded-full",
}

const CUSTOM_CODE = `<ForgotPasswordForm
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function ForgotPasswordPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Forgot password"
      description="Step one of a reset: mails a link to the account's verified address, and never says whether the account exists."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          Send a link for <code>{DEMO_USER.email}</code>, then open it from the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Try an address with no account: the answer reads the same, and no mail arrives.</>,
        <>Use <b>Send it again</b> and <b>Use a different email</b> on the "Check your email" step.</>,
        <>Switch Language to Deutsch and Appearance to Custom in the panel below.</>,
      ]}
    >
      <ForgotPasswordForm classNames={custom ? CUSTOM : undefined} headingLevel={2} />
    </DemoPage>
  )
}

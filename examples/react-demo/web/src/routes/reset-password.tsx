// /reset-password: the page the reset link opens. ResetPasswordForm reads
// ?token= from the address itself.

import { ResetPasswordForm, type ResetPasswordFormSlot } from "@/components/auth/reset-password-form"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<ResetPasswordFormSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
  submit: "rounded-full",
  action: "rounded-full",
}

const CUSTOM_CODE = `<ResetPasswordForm
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function ResetPasswordPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Reset password"
      description="The page a reset link opens: the new password twice, with a strength hint. A used or expired link asks for a new one."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          Ask for a link on <RouterLink href="/forgot-password">Forgot password</RouterLink> and open it from the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Type two different passwords, then a short one: each error sits under its field.</>,
        <>Reset it, then open the same link again: the card asks for a new link instead of showing a form that can only fail.</>,
        <>Opened here without a link, the page says it needs one.</>,
        <>Switch Language to Deutsch and Appearance to Custom in the panel below.</>,
      ]}
    >
      <ResetPasswordForm classNames={custom ? CUSTOM : undefined} headingLevel={2} />
    </DemoPage>
  )
}

// /confirm-email-change: the page an email-change link opens (the link
// printed in the Inbox after a change under Account settings). Opened
// without ?token=, it says to use the link.

import { ConfirmEmailChange } from "@/components/auth/confirm-email-change"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"

export function ConfirmEmailChangePage() {
  return (
    <DemoPage
      title="Confirm email change"
      description="Opened from the link mailed to the new address: posts the token once and makes the new address the account's."
      tryThis={[
        <>
          Change your email under <RouterLink href="/account">Account settings</RouterLink>.
        </>,
        <>
          Open the confirmation link from the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Open the same link again: it has been used, so the page says it expired.</>,
      ]}
    >
      <ConfirmEmailChange headingLevel={2} />
    </DemoPage>
  )
}

// /undo-email-change: the page the undo link opens. That link goes to the
// old address after an email change; it restores the old address and signs
// out every session.

import { ConfirmEmailChange } from "@/components/auth/confirm-email-change"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"

export function UndoEmailChangePage() {
  return (
    <DemoPage
      title="Undo email change"
      description="Opened from the link mailed to the old address after a change: puts the old address back and signs out everywhere."
      tryThis={[
        <>
          Change your email under <RouterLink href="/account">Account settings</RouterLink> and confirm it from the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Open the undo link the Inbox shows for the old address: the old address is back and every session is signed out.</>,
      ]}
    >
      <ConfirmEmailChange action="undo" headingLevel={2} />
    </DemoPage>
  )
}

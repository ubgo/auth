// /invitations: OrganizationInvitations, the page an invitation mail links
// to (the organization plugin's default invite page). The server lists only
// invitations addressed to the signed-in user's verified addresses.

import { SignedIn, SignedOut } from "@ubgo/auth-react"

import { DomainSuggestions } from "@/components/auth/domain-suggestions"
import { OrganizationInvitations, type OrganizationInvitationsSlot } from "@/components/auth/organization-invitations"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<OrganizationInvitationsSlot, string>> = {
  root: "max-w-lg rounded-2xl shadow-lg",
  accept: "rounded-full",
  decline: "rounded-full",
}

const CUSTOM_CODE = `<OrganizationInvitations
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function InvitationsPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Invitations"
      description="Invitations waiting for the signed-in user, with Accept and Decline; where an invitation mail's link lands."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          On <RouterLink href="/organizations">Organizations</RouterLink>, invite <code>grace@demo.test</code>, the address of the Demo provider's Grace Hopper.
        </>,
        <>
          Sign out, then <RouterLink href="/sign-in?redirectTo=/invitations">sign in</RouterLink> with <b>Continue with Demo provider</b> as Grace Hopper.
        </>,
        <>
          The invitation is listed here (the <RouterLink href="/inbox">Inbox</RouterLink> mail links to this page). Accept joins the organization; Decline removes the invitation.
        </>,
      ]}
    >
      <SignedIn>
        <div className="flex w-full max-w-md flex-col gap-3">
          <OrganizationInvitations classNames={custom ? CUSTOM : undefined} headingLevel={2} />
          <DomainSuggestions headingLevel={2} />
        </div>
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in?redirectTo=/invitations" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          to see the invitations waiting for you.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

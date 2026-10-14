// /organizations: OrganizationSwitcher over OrganizationMembers, both reading
// the session's active organization, so switching in the menu changes the
// member list below. Signed out, a link to sign in.

import { SignedIn, SignedOut } from "@ubgo/auth-react"

import { OrganizationDomains } from "@/components/auth/organization-domains"
import { OrganizationMembers, type OrganizationMembersSlot } from "@/components/auth/organization-members"
import { OrganizationSwitcher, type OrganizationSwitcherSlot } from "@/components/auth/organization-switcher"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"
import { DEMO_USER, SECOND_USER } from "@/demo-user"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM_SWITCHER: Partial<Record<OrganizationSwitcherSlot, string>> = {
  trigger: "rounded-full",
  logo: "rounded-full",
  content: "w-72 rounded-xl",
}
const CUSTOM_MEMBERS: Partial<Record<OrganizationMembersSlot, string>> = {
  root: "max-w-2xl rounded-2xl shadow-lg",
  badge: "rounded-full",
  submit: "rounded-full",
}

const CUSTOM_CODE = `<OrganizationSwitcher
  classNames={${JSON.stringify(CUSTOM_SWITCHER, null, 2).replace(/\n/g, "\n  ")}}
/>
<OrganizationMembers
  classNames={${JSON.stringify(CUSTOM_MEMBERS, null, 2).replace(/\n/g, "\n  ")}}
/>`

// ds:def id=organizationspage-hcwvmukj owner=@khanakia stability=stable
export function OrganizationsPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Organizations"
      description="The active organization lives on the session: the switcher sets it, and the member list, its invitations, the invite form and its verified domains follow it."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href="/sign-in?redirectTo=/organizations">Sign in</RouterLink> as <code>{DEMO_USER.email}</code>, open the switcher and choose <b>Create organization</b>: it becomes active, with you as its owner.
        </>,
        <>
          Invite <code>grace@demo.test</code> as an admin: the invitation is listed as pending and its mail is in the <RouterLink href="/inbox">Inbox</RouterLink>.
        </>,
        <>Create a second organization, then switch between the two and back to your personal account.</>,
        <>
          Once Grace has accepted, open the <b>…</b> menu on her row to change her role or remove her; on your own row, try making yourself an admin or leaving: the last owner is refused.
        </>,
        <>Under Domains, add <code>example.com</code> (verified at once: you hold an address there), set it to <b>Suggest joining</b>, let <code>{SECOND_USER.email}</code> request to join from Invitations, then approve here.</>,
        <>Switch Language to Deutsch and Appearance to Custom in the panel below.</>,
      ]}
    >
      <SignedIn>
        <div className="flex w-full max-w-xl flex-col items-start gap-3">
          <OrganizationSwitcher classNames={custom ? CUSTOM_SWITCHER : undefined} />
          <OrganizationMembers classNames={custom ? CUSTOM_MEMBERS : undefined} headingLevel={2} />
          <OrganizationDomains headingLevel={2} />
        </div>
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in?redirectTo=/organizations" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          to manage organizations.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

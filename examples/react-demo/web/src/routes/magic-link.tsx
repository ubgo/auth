// /magic-link: the page a magic link opens. MagicLinkCallback reads ?token=
// from the address, signs in once and moves on to redirectTo or home.

import { MagicLinkCallback, type MagicLinkCallbackSlot } from "@/components/auth/magic-link-callback"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"
import { DEMO_USER } from "@/demo-user"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<MagicLinkCallbackSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
  action: "rounded-full",
}

const CUSTOM_CODE = `<MagicLinkCallback
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function MagicLinkPage() {
  const { custom } = useDemoCustomise()
  const redirectTo = new URLSearchParams(window.location.search).get("redirectTo") ?? undefined
  return (
    <DemoPage
      title="Magic link callback"
      description="The page a magic link opens: it signs in with the token once, then moves on, or hands off to the second factor."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          On <RouterLink href="/sign-in">Sign in</RouterLink>, choose <b>Email me a link instead</b> for <code>{DEMO_USER.email}</code>, then open the link from the{" "}
          <RouterLink href="/inbox">Inbox</RouterLink>: you land home, signed in.
        </>,
        <>Sign out and open the same link again: it works once, so the card sends you back to sign in.</>,
        <>With two-factor on, the link hands off to the challenge instead of finishing.</>,
        <>Switch Language to Deutsch and Appearance to Custom in the panel below.</>,
      ]}
    >
      <MagicLinkCallback redirectTo={redirectTo} classNames={custom ? CUSTOM : undefined} headingLevel={2} />
    </DemoPage>
  )
}

// /passkeys: PasskeyList (with its AddPasskey button) for the signed-in
// user. Signed out, the page says so and links to sign-in.

import { SignedIn, SignedOut } from "@ubgo/auth-react"

import { PasskeyList, type PasskeyListSlot } from "@/components/auth/passkey-list"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<PasskeyListSlot, string>> = {
  root: "max-w-xl rounded-2xl shadow-lg",
  list: "rounded-xl",
  itemIcon: "rounded-full",
  addButton: "rounded-full",
}

const CUSTOM_CODE = `<PasskeyList
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function PasskeysPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Passkeys"
      description="The signed-in user's passkeys: add one with the browser's prompt, rename it, remove it. AddPasskey also works on its own."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href="/sign-in?redirectTo=/passkeys">Sign in</RouterLink> first; adding and removing need a recent sign-in.
        </>,
        <>
          <b>Add a passkey</b> and confirm with Touch ID, Windows Hello or a security key. It is named after this browser and system.
        </>,
        <>Rename it from the row's menu, then sign out and use Sign in with a passkey.</>,
        <>Remove it: the confirm dialog shows the server's refusal if it was your only way in.</>,
      ]}
    >
      <SignedIn>
        <PasskeyList headingLevel={2} classNames={custom ? CUSTOM : undefined} />
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in?redirectTo=/passkeys" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          to manage passkeys.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

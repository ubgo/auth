// /setup-two-factor: TaskSetupMFA, where a session the server will not let
// work until it has a second factor lands (the setup-mfa session task). The
// demo server requires it of mfa@example.com only (admin.go mustEnrol), and
// SessionTaskRedirect in the shell sends that user here from any page.

import { SignedIn, SignedOut } from "@ubgo/auth-react"

import { TaskSetupMFA, type TaskSetupMfaSlot } from "@/components/auth/task-setup-mfa"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"
import { MFA_USER } from "@/demo-user"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<TaskSetupMfaSlot, string>> = {
  root: "max-w-md rounded-2xl shadow-lg",
  title: "text-xl",
}

const CUSTOM_CODE = `<TaskSetupMFA
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

export function SetupTwoFactorPage() {
  const { custom } = useDemoCustomise()
  return (
    <DemoPage
      title="Required two-factor setup"
      description="A session that must set up a second factor before it works: every other page is refused until it is done, then the server issues an ordinary session."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href="/sign-in">Sign in</RouterLink> as <code>{MFA_USER.email}</code> with the demo password: you land here, whatever page you asked for.
        </>,
        <>Open another page from the sidebar: you are sent back, because the server answers every other call with auth.session_task_pending.</>,
        <>Scan the QR code with an authenticator app, enter the code, and save the recovery codes: you go on to the overview, signed in normally.</>,
        <>Sign out and in again: the server now asks for the code, as for any account with two-factor on.</>,
      ]}
    >
      <SignedIn>
        <TaskSetupMFA classNames={custom ? CUSTOM : undefined} headingLevel={2} />
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          as <code>{MFA_USER.email}</code> to see the required setup.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

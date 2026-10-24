// /account-sections: two account sections used on their own (ProfileSection,
// SessionsSection) beside a password form the app writes itself, which reuses
// the kit's re-authentication: when password.change answers
// auth.fresh_session_required, useReauth opens the "Confirm it's you" dialog
// and runs the change again once the session is fresh. After the change the
// form invalidates SESSIONS_QUERY_KEY, so SessionsSection drops the devices
// the change signed out.

import { SignedIn, SignedOut, useAuth, useErrorMessage, useLocalization, usePluginClient } from "@ubgo/auth-react"
import { useState, type FormEvent } from "react"

import {
  ACCOUNT_SETTINGS_TEXT,
  ProfileSection,
  SESSIONS_QUERY_KEY,
  SessionsSection,
  useReauth,
} from "@/components/auth/account-settings"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"

/** The code a guarded operation answers when the session is older than the fresh window. */
const FRESH_SESSION_REQUIRED = "auth.fresh_session_required"

/** The app's own password form: plain state, the kit's dialog only for re-authentication. */
function OwnPasswordForm() {
  const t = useLocalization("accountSettings", ACCOUNT_SETTINGS_TEXT)
  const reauth = useReauth(t)
  const password = usePluginClient("password")
  const { queryClient } = useAuth()
  const messageFor = useErrorMessage()
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState("")
  const [status, setStatus] = useState<string | null>(null)

  if (password === null) return null

  // ds:def id=change-twfep354
  async function change() {
    if (password === null) return
    const { error } = await password.change({ current, new: next, revokeOtherSessions: true })
    if (error?.code === FRESH_SESSION_REQUIRED) {
      // The dialog confirms the session the user already has, then runs this again.
      reauth.request(() => void change())
      return
    }
    if (error !== null) {
      setStatus(messageFor(error))
      return
    }
    setCurrent("")
    setNext("")
    setStatus("Password changed. Other devices are signed out.")
    await queryClient.invalidateQueries({ queryKey: SESSIONS_QUERY_KEY })
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    setStatus(null)
    void change()
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Your own password form</h2>
        </CardTitle>
        <CardDescription>Written by the app, not the kit. Signs out every other device.</CardDescription>
      </CardHeader>
      <CardContent>
        <form id="own-password" onSubmit={submit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="own-current">Current password</FieldLabel>
              <Input id="own-current" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
            </Field>
            <Field>
              <FieldLabel htmlFor="own-next">New password</FieldLabel>
              <Input id="own-next" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
            </Field>
          </FieldGroup>
        </form>
      </CardContent>
      <CardFooter className="gap-2">
        {status !== null && (
          <p role="status" className="text-[13px] text-muted-foreground">
            {status}
          </p>
        )}
        <Button type="submit" form="own-password" className="ml-auto">
          Change password
        </Button>
      </CardFooter>
      {reauth.element}
    </Card>
  )
}

export function AccountSectionsPage() {
  return (
    <DemoPage
      title="Account sections"
      description="ProfileSection and SessionsSection on their own, beside a password form the app writes itself that reuses the kit's re-authentication dialog (useReauth) and refreshes SessionsSection through SESSIONS_QUERY_KEY."
      tryThis={[
        <>
          <RouterLink href="/sign-in?redirectTo=/account-sections">Sign in</RouterLink> as the demo user, and again from a second browser: Sessions lists both.
        </>,
        <>Wait out the fresh window, then change the password in your own form: "Confirm it's you" opens, and after your password the change runs by itself.</>,
        <>Sessions then shows only this device, because the form invalidated its query.</>,
      ]}
    >
      <SignedIn>
        <div className="flex w-full max-w-3xl flex-col gap-4">
          <ProfileSection />
          <OwnPasswordForm />
          <SessionsSection />
        </div>
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href="/sign-in?redirectTo=/account-sections" className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          to see the sections.
        </p>
      </SignedOut>
    </DemoPage>
  )
}

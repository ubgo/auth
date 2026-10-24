import { redirect } from "next/navigation"

import { serverUser } from "@/lib/server-session"

import { SignOutButton } from "../auth-ui"

/**
 * A page checked on the server before it is sent: the hooks cannot read the
 * session there, so serverUser asks the Go server with the browser's cookie.
 * A signed-out visitor gets a redirect, never this page's HTML.
 */
// ds:def id=nextjs-accountpage-c2tnrmtc
export default async function AccountPage() {
  const user = await serverUser()
  if (user === null) redirect(`/sign-in?redirectTo=${encodeURIComponent("/account")}`)
  return (
    <section aria-labelledby="account">
      <h1 id="account">{user.name}</h1>
      <p className="muted">Read on the server from GET /auth/session, before this page was sent.</p>
      <SignOutButton />
    </section>
  )
}

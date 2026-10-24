"use client"

// The client components the pages render: they use the kit's hooks, so they
// are client components, and Next renders them on the server too. There the
// session is pending (useSession does not fetch on the server), so the HTML
// holds SignedIn's fallback until the browser reads the session.

import type { AuthError } from "@ubgo/auth-client"
import { SignedIn, SignedOut, safeRedirect, useAuth, useErrorMessage, usePluginClient, useSession, useSessionActions } from "@ubgo/auth-react"
import { useState, type FormEvent } from "react"

/** Links between pages go through the provider's Link, the one the kit's components use. */
export function Header() {
  const { Link, paths } = useAuth()
  const { user } = useSession()
  return (
    <nav aria-label="Main">
      <Link href="/">Home</Link> · <Link href={paths.account}>Account</Link>
      <SignedIn>
        <span className="muted"> · {user?.name}</span>
      </SignedIn>
    </nav>
  )
}

/** The home page's session line, read in the browser through useSession. */
export function HomeStatus() {
  const { user } = useSession()
  const { Link, paths } = useAuth()
  return (
    <>
      <SignedIn fallback={<p className="muted">Checking your session…</p>}>
        <p role="status">Signed in as {user?.name}.</p>
      </SignedIn>
      <SignedOut>
        <p role="status">
          You are signed out. <Link href={paths.signIn}>Sign in</Link>
        </p>
      </SignedOut>
    </>
  )
}

/** signOut() navigates to paths.afterSignOut through router.push. */
export function SignOutButton() {
  const { signOut } = useSessionActions()
  const message = useErrorMessage()
  const [error, setError] = useState<AuthError | null>(null)
  return (
    <>
      <button type="button" onClick={async () => setError(await signOut())}>
        Sign out
      </button>
      {error && <p role="alert">{message(error)}</p>}
    </>
  )
}

/**
 * Email and password, then on to redirectTo (checked by safeRedirect) or
 * paths.afterSignIn. redirectTo comes from the server page's searchParams,
 * so the server's HTML and the browser's first render agree.
 */
export function SignInForm({ redirectTo }: { readonly redirectTo: string | undefined }) {
  const passwordClient = usePluginClient("password")
  const { refreshSession } = useSessionActions()
  const { navigate, paths } = useAuth()
  const message = useErrorMessage()
  const [identifier, setIdentifier] = useState("")
  const [secret, setSecret] = useState("")
  const [error, setError] = useState<AuthError | null>(null)
  if (passwordClient === null) return null

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const { data, error } = await passwordClient.signIn({ identifier, password: secret })
    setError(error)
    if (error) return
    if (data.secondFactorRequired) return navigate(paths.twoFactor)
    await refreshSession()
    // The address bar is anyone's to write: only a path on this site is followed.
    navigate(safeRedirect(redirectTo, paths.afterSignIn))
  }

  return (
    <section aria-labelledby="sign-in">
      <h1 id="sign-in">Sign in</h1>
      <form onSubmit={submit}>
        <label>
          Email
          <input name="identifier" type="email" autoComplete="username" value={identifier} onChange={(e) => setIdentifier(e.target.value)} required />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" value={secret} onChange={(e) => setSecret(e.target.value)} required />
        </label>
        <button type="submit">Sign in</button>
        {error && <p role="alert">{message(error)}</p>}
      </form>
    </section>
  )
}

export function SendMagicLink() {
  const magic = usePluginClient("magiclink")
  const message = useErrorMessage()
  const [address, setAddress] = useState("")
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<AuthError | null>(null)
  if (magic === null) return null

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const { error } = await magic.send({ identifier: address })
    setError(error)
    setSent(error === null)
  }

  return (
    <section aria-labelledby="magic-link">
      <h2 id="magic-link">Email me a link</h2>
      {sent ? (
        <p role="status">Check your email for a sign-in link.</p>
      ) : (
        <form onSubmit={submit}>
          <label>
            Email for the link
            <input name="magic-identifier" type="email" value={address} onChange={(e) => setAddress(e.target.value)} required />
          </label>
          <button type="submit">Send the link</button>
          {error && <p role="alert">{message(error)}</p>}
        </form>
      )}
    </section>
  )
}

/** The page a magic link opens. The token is spent by one click, so a mail scanner that opens the link signs nobody in. */
export function MagicLinkFinish({ token }: { readonly token: string }) {
  const magic = usePluginClient("magiclink")
  const { refreshSession } = useSessionActions()
  const { navigate, paths } = useAuth()
  const message = useErrorMessage()
  const [error, setError] = useState<AuthError | null>(null)
  if (magic === null) return null
  if (token === "") return <p role="alert">This link has no token.</p>

  const finish = async () => {
    const { data, error } = await magic.signIn({ token })
    setError(error)
    if (error) return
    await refreshSession()
    navigate(data.secondFactorRequired ? paths.twoFactor : paths.afterSignIn)
  }

  return (
    <section aria-labelledby="magic">
      <h1 id="magic">Finish signing in</h1>
      <button type="button" onClick={finish}>
        Sign me in
      </button>
      {error && <p role="alert">{message(error)}</p>}
    </section>
  )
}

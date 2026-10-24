// The pages: a home page, a sign-in page of the app's own markup, a page
// only a signed-in user sees (RequireUser), and the page a magic link opens.
// Each navigates through the provider (useAuth().navigate), which root.tsx
// wired to the router.

import type { AuthError } from "@ubgo/auth-client"
import { SignedIn, SignedOut, safeRedirect, useAuth, useErrorMessage, usePluginClient, useSession, useSessionActions } from "@ubgo/auth-react"
import { useState, type FormEvent, type ReactNode } from "react"
import { Navigate, useLocation, useSearchParams } from "react-router"

/** The query parameter the guard puts the page it came from in, and the sign-in page reads. */
const REDIRECT_PARAM = "redirectTo"

export function HomePage() {
  const { user } = useSession()
  const { Link, paths } = useAuth()
  return (
    <>
      <h1>React Router</h1>
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

/**
 * A page only a signed-in user sees. The session is read in the browser, so
 * this guard decides after the first session read; a page whose HTML must
 * not be sent to a signed-out visitor needs a check on the server instead.
 */
// ds:def id=rr-requireuser-5w8pu3g3
export function RequireUser({ children }: { readonly children: ReactNode }) {
  const { user, isPending } = useSession()
  const { paths } = useAuth()
  const { pathname } = useLocation()
  if (isPending) return <p className="muted">Checking your session…</p>
  if (user === null) return <Navigate to={`${paths.signIn}?${REDIRECT_PARAM}=${encodeURIComponent(pathname)}`} replace />
  return children
}

export function AccountPage() {
  const { user } = useSession()
  const { signOut } = useSessionActions()
  const message = useErrorMessage()
  const [error, setError] = useState<AuthError | null>(null)
  return (
    <section aria-labelledby="account">
      <h1 id="account">{user?.name}</h1>
      <p className="muted">Only a signed-in user sees this page.</p>
      {/* signOut() navigates to paths.afterSignOut through the router. */}
      <button type="button" onClick={async () => setError(await signOut())}>
        Sign out
      </button>
      {error && <p role="alert">{message(error)}</p>}
    </section>
  )
}

/** Email and password, then back to the page the guard came from (checked by safeRedirect) or paths.afterSignIn. */
export function SignInPage() {
  const passwordClient = usePluginClient("password")
  const { refreshSession } = useSessionActions()
  const { navigate, paths } = useAuth()
  const [params] = useSearchParams()
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
    navigate(safeRedirect(params.get(REDIRECT_PARAM), paths.afterSignIn))
  }

  return (
    <>
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
      <SendMagicLink />
    </>
  )
}

function SendMagicLink() {
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

/**
 * The page a magic link opens (/magic-link?token=…). The token comes from
 * the router's search params, and is spent by one click, so a mail scanner
 * that opens the link signs nobody in.
 */
export function MagicLinkPage() {
  const magic = usePluginClient("magiclink")
  const { refreshSession } = useSessionActions()
  const { navigate, paths } = useAuth()
  const message = useErrorMessage()
  const [params] = useSearchParams()
  const [error, setError] = useState<AuthError | null>(null)
  const token = params.get("token") ?? ""
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

// The React kit without its components: @ubgo/auth-react's provider and
// hooks driving markup the app writes itself. No router either, so the
// provider's default navigation (a page load) and default link (<a>) are the
// ones in use, and custom `paths` say where those go. Every piece of UI here
// is a stand-in for the app's own design system.

import { createAuthClient, email, magiclink, oauth, passkey, password, twofactor, type AuthError } from "@ubgo/auth-client"
import {
  AuthProvider,
  SESSION_QUERY_KEY,
  SignedIn,
  SignedOut,
  oauthStartURL,
  supportsPasskeys,
  useAuth,
  useErrorMessage,
  useOAuthProviders,
  usePlugin,
  usePluginClient,
  useSession,
  useSessionActions,
  type AuthLocalization,
  type AuthPaths,
} from "@ubgo/auth-react"
import { useState, type FormEvent } from "react"

/** Where the Go server mounts the routes; Vite proxies it (vite.config.ts), so it is same-origin. */
const BASE_URL = "/auth"

/** One client for the page, with the plugins the server has. Built once, outside React. */
// ds:def id=headless-client-kjnvsfqa owner=@khanakia stability=stable
const client = createAuthClient({
  baseURL: BASE_URL,
  plugins: [email(), password(), magiclink(), oauth(), passkey(), twofactor()],
})

/**
 * This app is one page, so the routes the kit navigates to are query flags
 * on it. useSessionActions().signOut goes to afterSignOut; a sign-in that
 * needs a second factor goes to twoFactor.
 */
const SIGNED_OUT_FLAG = "signed-out"
const SECOND_FACTOR_FLAG = "second-factor"
// ds:def id=headless-paths-27arp6wu owner=@khanakia stability=stable
const PATHS: Partial<AuthPaths> = {
  signIn: "/",
  afterSignIn: "/",
  afterSignOut: `/?${SIGNED_OUT_FLAG}`,
  twoFactor: `/?${SECOND_FACTOR_FLAG}`,
}

/** The app's own wording for one error code; every other code keeps the server's message. */
const LOCALIZATION: AuthLocalization = {
  errors: { "password.invalid_credentials": "That email and password do not match." },
}

/** Where the OAuth callback lands the browser: this page, on this site. */
const OAUTH_RETURN_TO = "/"

/** Whether the page was loaded with a flag the kit navigated to (see PATHS). */
function hasFlag(flag: string): boolean {
  return new URLSearchParams(window.location.search).has(flag)
}

// ds:def id=headless-app-ta8bvga4 owner=@khanakia stability=stable
export function App() {
  return (
    <AuthProvider client={client} baseURL={BASE_URL} paths={PATHS} localization={LOCALIZATION}>
      <h1>React hooks, no components</h1>
      {hasFlag(SIGNED_OUT_FLAG) && <p role="status">You were signed out on every device.</p>}
      {hasFlag(SECOND_FACTOR_FLAG) && <p role="status">This account has a second factor: an app renders its challenge page here.</p>}
      <SignedIn fallback={<p className="muted">Checking your session…</p>}>
        <Account />
      </SignedIn>
      <SignedOut>
        <PasswordSignIn />
        <OAuthButtons />
        <MagicLink />
        <PasskeySupport />
      </SignedOut>
    </AuthProvider>
  )
}

/** The signed-in view: who, and the two ways to sign out. */
// ds:def id=headless-account-6xr8hky3 owner=@khanakia stability=stable
function Account() {
  const { user } = useSession()
  const { signOut } = useSessionActions()
  const message = useErrorMessage()
  const [error, setError] = useState<AuthError | null>(null)

  // redirectTo null: stay on this page; SignedOut renders once the cache
  // says nobody is signed in. Everywhere goes to paths.afterSignOut.
  const here = async () => setError(await signOut({ redirectTo: null }))
  const everywhere = async () => setError(await signOut({ everywhere: true }))

  return (
    <section aria-labelledby="account">
      <h2 id="account">Signed in as {user?.name}</h2>
      <button type="button" onClick={here}>Sign out</button>
      <button type="button" onClick={everywhere}>Sign out everywhere</button>
      {error && <p role="alert">{message(error)}</p>}
      <Rename />
    </section>
  )
}

/**
 * A call the kit knows nothing about changes the user, so the app tells the
 * cache: invalidating SESSION_QUERY_KEY refetches the session, and every
 * useSession on the page (the heading above) shows the new name.
 */
// ds:def id=headless-rename-q4m7xz2c owner=@khanakia stability=stable
function Rename() {
  const { queryClient } = useAuth()
  const message = useErrorMessage()
  const [name, setName] = useState("")
  const [error, setError] = useState<AuthError | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const { error } = await client.profile({ name })
    setError(error)
    if (error) return
    await queryClient.invalidateQueries({ queryKey: SESSION_QUERY_KEY })
  }

  return (
    <form onSubmit={submit}>
      <label>
        New name
        <input name="name" value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <button type="submit">Rename</button>
      {error && <p role="alert">{message(error)}</p>}
    </form>
  )
}

/** An email and password form of the app's own, calling the password plugin through the provider's client. */
// ds:def id=headless-passwordsignin-kkyct6ng owner=@khanakia stability=stable
function PasswordSignIn() {
  // ds:def id=headless-signin-submit-ejvycaf5 owner=@khanakia stability=stable span=+22
  const passwordClient = usePluginClient("password")
  const { refreshSession } = useSessionActions()
  const { navigate, paths } = useAuth()
  const message = useErrorMessage()
  const [identifier, setIdentifier] = useState("")
  const [secret, setSecret] = useState("")
  const [error, setError] = useState<AuthError | null>(null)
  const [busy, setBusy] = useState(false)

  if (passwordClient === null) return null // the client has no password plugin: offer no form

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true)
    const { data, error } = await passwordClient.signIn({ identifier, password: secret })
    setBusy(false)
    setError(error)
    if (error) return
    if (data.secondFactorRequired) navigate(paths.twoFactor)
    // The session query is stale now; refreshing it flips SignedOut to SignedIn.
    else await refreshSession()
  }

  return (
    <section aria-labelledby="sign-in">
      <h2 id="sign-in">Sign in</h2>
      <form onSubmit={submit}>
        <label>
          Email
          <input name="identifier" type="email" autoComplete="username" value={identifier} onChange={(e) => setIdentifier(e.target.value)} required />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" value={secret} onChange={(e) => setSecret(e.target.value)} required />
        </label>
        <button type="submit" disabled={busy}>Sign in</button>
        {error && <p role="alert">{message(error)}</p>}
      </form>
    </section>
  )
}

/**
 * One link per provider the server has. OAuth is a page navigation, not a
 * fetch: the start route redirects to the provider and binds the flow to a
 * cookie, so this is an <a>, never a client call.
 */
// ds:def id=headless-oauthbuttons-f7dhbkek owner=@khanakia stability=stable
function OAuthButtons() {
  const { baseURL } = useAuth()
  const { providers, isPending, error } = useOAuthProviders()
  const message = useErrorMessage()
  if (isPending || (providers.length === 0 && error === null)) return null
  return (
    <section aria-labelledby="oauth">
      <h2 id="oauth">Or continue with</h2>
      {providers.map((p) => (
        <a key={p.id} className="button" href={oauthStartURL(baseURL, p.id, { returnTo: OAUTH_RETURN_TO })}>
          Continue with {p.name}
        </a>
      ))}
      {error && <p role="alert">{message(error)}</p>}
    </section>
  )
}

/** Shown only when the client has the magic-link plugin (usePlugin). */
// ds:def id=headless-magiclink-f9zkp5bj owner=@khanakia stability=stable
function MagicLink() {
  const hasMagicLink = usePlugin("magiclink")
  const magic = usePluginClient("magiclink")
  const message = useErrorMessage()
  const [address, setAddress] = useState("")
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<AuthError | null>(null)
  if (!hasMagicLink || magic === null) return null

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

/** Whether to offer a passkey button at all: the plugin is on and this browser has WebAuthn. */
// ds:def id=headless-passkeysupport-3ree8qsj owner=@khanakia stability=stable
function PasskeySupport() {
  const hasPasskey = usePlugin("passkey")
  if (!hasPasskey) return null
  return <p className="muted">{supportsPasskeys() ? "This browser can sign in with a passkey." : "This browser cannot use passkeys."}</p>
}

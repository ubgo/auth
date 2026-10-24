# React hooks

`@ubgo/auth-react` is the headless half of the React UI kit: the provider, the session as TanStack Query state, plugin gating, OAuth start URLs, the passkey ceremonies and the text pipeline. Every registry component is built on it, and you can build every screen on it yourself. This page shows each export with a complete, working use.

## When you want the hooks

- Your sign-in, sign-up or account screens are your own design, and editing a copied component would be a rewrite.
- You need a flow the kit has no component for: an organization switcher, an API-key page, an admin screen. The session, sign-out and error text still come from here.
- You use the [components](react-components.md) and want a small piece beside them: a "signed in as" line, a gate around a route, a sign-out button somewhere else.

For a frontend that is not React, the [TypeScript client](flows.md) is the whole story; these hooks only add React state on top of it.

## Before you start

- The [quickstart's](react.md) Steps 1, 2 and 4: the client and package linked with one copy of React and TanStack Query, `/auth` on the page's origin, and the client created with the server's plugins. The registry (Step 3) is not needed for anything on this page.
- React 19 and TanStack Query 5, the package's peers.

## Step 1 — Mount the provider

`AuthProvider` holds the client and everything the hooks share. Mount it once near the root, inside your router when you pass a router-aware `navigate` or `Link`. The examples on this page come from [examples/react-headless](../../examples/react-headless/), a page that uses only these hooks, with no registry component, no Tailwind and no router. Its client is created once, outside React, with the plugins the server has:

<!-- ds:block id=headless-client-kjnvsfqa -->
**client** · [`examples/react-headless/web/src/app.tsx:32-35`](../../examples/react-headless/web/src/app.tsx#L32-L35)

```tsx
const client = createAuthClient({
  baseURL: BASE_URL,
  plugins: [email(), password(), magiclink(), oauth(), passkey(), twofactor()],
})
```
<!-- /ds:block hash=f0038f -->

It is one page, so the routes the kit navigates to are query flags on it:

<!-- ds:block id=headless-paths-27arp6wu -->
**PATHS** · [`examples/react-headless/web/src/app.tsx:45-50`](../../examples/react-headless/web/src/app.tsx#L45-L50)

```tsx
const PATHS: Partial<AuthPaths> = {
  signIn: "/",
  afterSignIn: "/",
  afterSignOut: `/?${SIGNED_OUT_FLAG}`,
  twoFactor: `/?${SECOND_FACTOR_FLAG}`,
}
```
<!-- /ds:block hash=08bb00 -->

The provider gets the client, the same `baseURL`, those paths and one reworded error message. `SignedIn` and `SignedOut` (Step 3) pick which half of the page renders:

<!-- ds:block id=headless-app-ta8bvga4 -->
**App** · [`examples/react-headless/web/src/app.tsx:66-83`](../../examples/react-headless/web/src/app.tsx#L66-L83)

```tsx
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
```
<!-- /ds:block hash=299386 -->

No `QueryClientProvider` is mounted, so the provider creates a private cache for the session; an app that already uses TanStack Query mounts its provider above `AuthProvider`, and the session joins that cache.

Every prop of [`AuthProviderProps`](ds:block?id=authproviderprops-pajkyadw):

| Prop | Default | What it does |
|---|---|---|
| `client` | required | The client from `createAuthClient`; its plugin list decides what `usePlugin` answers |
| `baseURL` | [`"/auth"`](ds:block?id=default-base-url-37mk67qf) | The same `baseURL` the client was created with, for flows that are page navigations (OAuth start) |
| `queryClient` | the `QueryClientProvider` above, else a private one | The cache the session lives in. With one above, your queries and the session share a cache |
| `navigate` | `window.location.assign` | Client-side navigation: `(href: string) => void` |
| `Link` | a plain `<a>` | A component taking `{ href, className, children }` |
| `paths` | `DEFAULT_AUTH_PATHS` | Where the components and `signOut` send people; each key overridable on its own |
| `localization` | none | App-wide text: `errors` by code, and each component's strings under its key |
| `allowedRedirectOrigins` | none | Origins a component's `redirectTo` may point at besides this site (`"https://app.example.com"`); any other absolute `redirectTo` is ignored and the component's default applies |

The default paths:

<!-- ds:block id=default-auth-paths-ebuuq6mh -->
**DEFAULT_AUTH_PATHS** · [`clients/react/src/context.tsx:60-69`](../../clients/react/src/context.tsx#L60-L69)

```tsx
export const DEFAULT_AUTH_PATHS: AuthPaths = {
  signIn: "/sign-in",
  signUp: "/sign-up",
  forgotPassword: "/forgot-password",
  twoFactor: "/two-factor",
  setupTwoFactor: "/setup-two-factor",
  account: "/account",
  afterSignIn: "/",
  afterSignOut: "/sign-in",
};
```
<!-- /ds:block hash=691a3a -->

`useAuth()` returns all of it with the defaults filled in (`client`, `baseURL`, `queryClient`, `navigate`, `Link`, `paths`, `localization`), for a component of yours that needs to link to `paths.account` or call the client. It throws `useAuth: wrap the app in <AuthProvider client={...}>` outside the provider, because every hook needs the client and a silent fallback would only move the failure to the first call.

## Step 2 — Read the session

`useSession()` reads `GET /auth/session` once into the query cache, and every component that calls it shares that one entry:

<!-- ds:block id=sessionstate-hq59hy5v -->
**SessionState** · [`clients/react/src/session.ts:40-57`](../../clients/react/src/session.ts#L40-L57)

```typescript
export type SessionState = {
  /** The session, or null when signed out (including a pending second factor, which signs nobody in). */
  readonly session: AuthSessionResult | null;
  /** The signed-in user, or null. */
  readonly user: AuthUserView | null;
  /** True until the first answer arrives. Render neither signed-in nor signed-out UI while it is true. */
  readonly isPending: boolean;
  /**
   * True while a later read is in flight (a refetchInterval tick, a window
   * focus, refetch()), with the last session still shown. False during the
   * first read, which is isPending.
   */
  readonly isRefetching: boolean;
  /** The failure of the last read, when it was not a plain "signed out". */
  readonly error: AuthError | null;
  /** Asks the server again now. */
  readonly refetch: () => Promise<void>;
};
```
<!-- /ds:block hash=37a294 -->

A signed-out answer (`auth.signed_out`) is data, not an error: it becomes `session: null`, so a page branches on it without error handling. Any other failure (the network, a 500) is kept in `error` and the last known session stays, so a flaky connection does not sign the user out of the UI. A pending second factor reads as signed out, because a pending session signs nobody in. The session counts as fresh for [`SESSION_STALE_MS`](ds:block?id=session-stale-ms-frks37zb), a minute: a remount or a window focus after that asks the server again, so a session revoked on another device disappears from this tab within about a minute.

The example's signed-in view reads the user, and offers both ways to sign out (Step 5):

<!-- ds:block id=headless-account-6xr8hky3 -->
**Account** · [`examples/react-headless/web/src/app.tsx:87-107`](../../examples/react-headless/web/src/app.tsx#L87-L107)

```tsx
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
```
<!-- /ds:block hash=db6687 -->

### Polling the session

`useSession(options)` takes per-use options, so a page that must notice a session revoked elsewhere sooner than the window-focus refetch can poll it, while every other reader of the same entry keeps its own settings:

<!-- ds:block id=usesessionoptions-4ru6ttpw -->
**UseSessionOptions** · [`clients/react/src/session.ts:61-76`](../../clients/react/src/session.ts#L61-L76)

```typescript
export type UseSessionOptions = {
  /**
   * Ask the server again every this many milliseconds while the component is
   * mounted, so a session revoked elsewhere (another device, an admin) leaves
   * this tab within that time. False (the default) polls never; the session
   * is still re-read on window focus once it is SESSION_STALE_MS old.
   */
  readonly refetchInterval?: number | false;
  /** Keep polling while the tab is in the background. False by default, so a hidden tab costs nothing. */
  readonly refetchIntervalInBackground?: boolean;
  /**
   * Re-read when the window regains focus: true (the default) once the
   * session is SESSION_STALE_MS old, "always" on every focus, false never.
   */
  readonly refetchOnWindowFocus?: boolean | "always";
};
```
<!-- /ds:block hash=772923 -->
<!-- /ds:block hash=772923 -->

`isRefetching` is true while a later read is in flight (a poll tick, a window focus, `refetch()`), with the last session still on screen; the first read is `isPending`. Show a quiet "refreshing" hint on `isRefetching`, never a loading state that hides the page. The react-demo's overview polls every 30 seconds with `useSession({ refetchInterval: 30_000 })`.

## Step 3 — Show UI for one side

`<SignedIn>` and `<SignedOut>` render their children only for one side of the session, and nothing (or `fallback`) while the first read is in flight, so a signed-in user never sees a flash of the sign-in button. The example's `App` (Step 1) uses both, with a "Checking your session…" fallback on the signed-in side:

<!-- ds:block id=sessiongateprops-8zaganxf -->
**SessionGateProps** · [`clients/react/src/gates.tsx:10-14`](../../clients/react/src/gates.tsx#L10-L14)

```tsx
export type SessionGateProps = {
  readonly children: ReactNode;
  /** Rendered while the first session read is in flight. Nothing by default. */
  readonly fallback?: ReactNode;
};
```
<!-- /ds:block hash=d61825 -->

`<SignedOut>` treats a pending second factor as signed out, like `useSession`. For a gate with more than two states (a banner while `error` is set, a redirect for a signed-out user), call `useSession()` yourself and branch on `isPending` first.

## Step 4 — Sign in with a form of your own

A plugin's typed methods come from `usePluginClient(name)`, which answers null when the client was built without that plugin; `usePlugin(name)` answers only the boolean. After any call that changes who is signed in, call `refreshSession()` from `useSessionActions()`: it marks the session stale and waits for the new one, so every `useSession` updates. `useErrorMessage()` turns an error into the text a person should see:

The example's [`PasswordSignIn`](ds:block?id=headless-passwordsignin-kkyct6ng) is a plain form; its hooks and its submit handler:

<!-- ds:block id=headless-signin-submit-ejvycaf5 -->
**PasswordSignIn.passwordClient** · [`examples/react-headless/web/src/app.tsx:145-167`](../../examples/react-headless/web/src/app.tsx#L145-L167)

```tsx
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

```
<!-- /ds:block hash=a03edb -->

A sign-in that needs a second factor answers `secondFactorRequired`; the form navigates to `paths.twoFactor` with the provider's `navigate`, where your challenge page (or the registry's [TwoFactorChallenge](react-components.md#twofactorchallenge)) calls `twofactor.verify` and then `refreshSession()`. `usePlugin` renders a method only when the client has its plugin:

<!-- ds:block id=headless-magiclink-f9zkp5bj -->
**MagicLink** · [`examples/react-headless/web/src/app.tsx:213-246`](../../examples/react-headless/web/src/app.tsx#L213-L246)

```tsx
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
```
<!-- /ds:block hash=a8f554 -->

`usePlugin` and `usePluginClient` know the plugins the components drive (`KnownPlugins`): `email`, `magiclink`, `oauth`, `passkey`, `password`, `phone`, `twofactor` and `username`. For any other plugin (`organization`, `apikey`, `admin`, your own), call your own `auth` client directly: it is fully typed with the plugins you passed, and `refreshSession()` still updates the UI when the call changed the session.

## Step 5 — Sign out

`signOut()` ends the session on the server, sets the cached session to null, removes every other cached auth entry (everything under `AUTH_QUERY_ROOT`), and navigates to `paths.afterSignOut`. `{ everywhere: true }` calls `signOutAll` instead, ending every session of the user; `redirectTo` goes elsewhere, and `redirectTo: null` stays on the page. It resolves to the server's error, or null. An `auth.signed_out` answer counts as success, since the session the caller wanted gone is gone. The example's `Account` (Step 2) calls it both ways:

<!-- ds:block id=sessionactions-d79ktzpu -->
**SessionActions** · [`clients/react/src/session.ts:122-135`](../../clients/react/src/session.ts#L122-L135)

```typescript
export type SessionActions = {
  /**
   * Marks the session stale and waits for the new one. Call it after any
   * call that changed who is signed in (a sign-in, a second factor, an
   * account switch); the components in the registry already do.
   */
  readonly refreshSession: () => Promise<void>;
  /**
   * Ends the session on the server, forgets every cached auth entry, and
   * navigates to paths.afterSignOut unless `redirectTo` says otherwise
   * (null stays on the page). Resolves to the server's error, or null.
   */
  readonly signOut: (options?: { readonly everywhere?: boolean; readonly redirectTo?: string | null }) => Promise<AuthError | null>;
};
```
<!-- /ds:block hash=10eaee -->

## Step 6 — OAuth buttons

OAuth sign-in is a page navigation, not a fetch: the start route redirects to the provider and binds the flow to this browser with a cookie, which only works top-level. `useOAuthProviders()` reads the providers the server lists (once per page load; it answers an empty list without the oauth plugin), and `oauthStartURL(baseURL, provider, options)` builds the start URL under the client's prefix. The buttons are plain links:

<!-- ds:block id=headless-oauthbuttons-f7dhbkek -->
**OAuthButtons** · [`examples/react-headless/web/src/app.tsx:193-209`](../../examples/react-headless/web/src/app.tsx#L193-L209)

```tsx
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
```
<!-- /ds:block hash=fe089f -->

The options:

<!-- ds:block id=oauthstartoptions-c85ngzme -->
**OAuthStartOptions** · [`clients/react/src/oauth.ts:22-34`](../../clients/react/src/oauth.ts#L22-L34)

```typescript
export type OAuthStartOptions = {
  /** Where the browser lands after the callback signs the user in: a path on this site or a trusted origin. */
  readonly returnTo?: string;
  /** Where the browser lands when the provider or the callback fails. */
  readonly errorTo?: string;
  /** Where a brand-new account lands instead of returnTo. */
  readonly newUserTo?: string;
  /**
   * Link the provider account to the signed-in user instead of signing in
   * (account settings' "Connect"); the start route then needs a session.
   */
  readonly link?: boolean;
};
```
<!-- /ds:block hash=74f803 -->

A failed flow lands on `errorTo` with `?error=<code>`; read it there and show `errorMessage` for it, as the account page's linked-accounts section does.

## Step 7 — Passkeys

The server's passkey routes speak WebAuthn JSON; the browser's `navigator.credentials` speaks binary. `getPasskeyCredential(options)` (sign-in) and `createPasskeyCredential(options)` (registration) convert both ways, using the browser's own `parseRequestOptionsFromJSON` and `toJSON` when it has them and a base64url fallback when it does not. Neither throws: a ceremony answers `{ credential, failure: null }` or `{ credential: null, failure }`, because a closed prompt is an expected outcome, not an exception. `supportsPasskeys()` says whether the browser can run one at all; render a passkey button only when it is true:

<!-- ds:block id=headless-passkeysupport-3ree8qsj -->
**PasskeySupport** · [`examples/react-headless/web/src/app.tsx:250-254`](../../examples/react-headless/web/src/app.tsx#L250-L254)

```tsx
function PasskeySupport() {
  const hasPasskey = usePlugin("passkey")
  if (!hasPasskey) return null
  return <p className="muted">{supportsPasskeys() ? "This browser can sign in with a passkey." : "This browser cannot use passkeys."}</p>
}
```
<!-- /ds:block hash=4570f1 -->

A ceremony's `failure` is one of:

<!-- ds:block id=passkeyfailure-xeqr573b -->
**PasskeyFailure** · [`clients/react/src/webauthn.ts:10-18`](../../clients/react/src/webauthn.ts#L10-L18)

```typescript
export type PasskeyFailure =
  /** The browser has no WebAuthn. */
  | "unsupported"
  /** The person closed the prompt, or no passkey matched (WebAuthn does not tell the two apart, on purpose). */
  | "cancelled"
  /** The server's options were not WebAuthn request or creation options. */
  | "invalid_options"
  /** Registration only: this authenticator already holds a passkey for the account (InvalidStateError). */
  | "already_registered";
```
<!-- /ds:block hash=dfa9c8 -->

A passkey sign-in is three steps: `passkey.loginBegin()` returns `{ options, ceremony }`, `getPasskeyCredential(options)` asks the browser, and `passkey.loginFinish({ ceremony, credential })` signs in and answers `secondFactorRequired` like a password sign-in; then `refreshSession()`. Registration is `registerBegin`, `createPasskeyCredential` and `registerFinish` with a name for the passkey. The registry's [sign-in-form.tsx](../../clients/react/registry/auth/sign-in-form.tsx) and [passkey-list.tsx](../../clients/react/registry/auth/passkey-list.tsx) run both ceremonies end to end, including the message for each failure.

Both take an optional `AbortSignal` as their second argument, to cancel a prompt that is still open when the page moves on. `getPasskeyCredential` takes a third, the WebAuthn `mediation`.

### Passkey autofill

Browsers can offer passkeys in an input's autofill list, beside saved passwords, when the input carries `autocomplete="username webauthn"` and the page has a credential request pending with `mediation: "conditional"` (WebAuthn conditional mediation). `supportsPasskeyAutofill()` resolves whether the browser can. `usePasskeyAutofill` runs the whole thing for a sign-in form of yours: it calls `passkey.loginBegin` on mount, keeps the conditional request open, and on a pick calls `passkey.loginFinish` and your `onSignedIn` with the result (`secondFactorRequired` included):

<!-- ds:block id=passkeyautofill-5gb93jhu -->
**PasskeyAutofill** · [`clients/react/src/autofill.ts:34-46`](../../clients/react/src/autofill.ts#L34-L46)

```typescript
export type PasskeyAutofill = {
  readonly status: PasskeyAutofillStatus;
  /**
   * Aborts the pending request now, synchronously, and keeps it stopped.
   * Call it first thing when the person picks another way in (the passkey
   * button, a password submit, an OAuth button): a browser runs one
   * credential request at a time, so the passkey dialog fails while an
   * autofill request is pending.
   */
  readonly pause: () => void;
  /** Starts it again after pause, for when the other way in failed and the form is back. */
  readonly resume: () => void;
};
```
<!-- /ds:block hash=e3c7f7 -->
<!-- /ds:block hash=e3c7f7 -->

A browser runs one credential request at a time, so call `pause()` first thing when the person picks another way in (a passkey button, a password submit, an OAuth button) and `resume()` when that way failed; it also aborts on unmount and when `enabled` turns false. Turn it off (`enabled: false`) while the page has no `username webauthn` input, because the browser has nowhere to offer the passkeys. A passkey the server refuses goes to `onError`, and autofill starts again so another pick works. The registry's [sign-in-form.tsx](../../clients/react/registry/auth/sign-in-form.tsx) wires it this way.

Under the hook, `runPasskeyAutofill(calls, signal, onStage?)` is one attempt with no React: pass the client's `passkey` namespace and an `AbortSignal`. It never throws and answers one of:

<!-- ds:block id=passkeyautofilloutcome-xa546psy -->
**PasskeyAutofillOutcome** · [`clients/react/src/webauthn.ts:242-252`](../../clients/react/src/webauthn.ts#L242-L252)

```typescript
export type PasskeyAutofillOutcome =
  /** A passkey was picked and the server signed its owner in (maybe pending a second factor). */
  | { readonly kind: "signed_in"; readonly result: PasskeySignInResult }
  /** A passkey was picked and the server refused it: an expired ceremony, a passkey it does not know. */
  | { readonly kind: "refused"; readonly error: AuthError }
  /** Autofill was not offered: no conditional mediation in this browser, or login-begin failed. */
  | { readonly kind: "unavailable"; readonly error: AuthError | null }
  /** The browser ended the request without a credential (no passkey for this site, or it gave up). */
  | { readonly kind: "no_credential" }
  /** `signal` aborted it: the person chose another method, or the page went away. */
  | { readonly kind: "aborted" };
```
<!-- /ds:block hash=75195f -->
<!-- /ds:block hash=75195f -->

The hook ends quietly on `unavailable` and `no_credential`: autofill is an offer, and the page's other methods are still there.

## Step 8 — Text and errors

Every string the components show goes through two helpers you can use too:

- `errorMessage(error, overrides?)` picks the message for an `AuthError`, most specific first: your override for the code, then the server's message (already translated when the server has a catalogue), then the code's declared English message. The client's own codes (`client.network_error`, `client.invalid_response`, `client.unknown_code`, `client.hook_failed`) always get the friendly English of `CLIENT_ERROR_MESSAGES`, never the developer's message they carry. `useErrorMessage(overrides?)` is the same, bound to the provider's `localization.errors`.
- `useLocalization(key, defaults, override)` merges a component's English defaults under the provider's `localization[key]` under the component's own prop; `format(text, values)` fills `{name}` placeholders and leaves a placeholder with no value as it is, so a missing value shows up in the UI instead of becoming an empty string.

Overrides are keyed by the closed error-code union (`AnyErrorCode`), so a translation for a code that does not exist is a compile error. A component of your own becomes localizable through the provider by declaration merging, exactly as the registry's components do:

```ts
declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    orgSwitcher: OrgSwitcherText
  }
}
```

## Step 9 — Organizations

With `organization()` in the client, these hooks read the organization plugin as server state. Each is inert (no request, an empty answer) when the client lacks the plugin or nobody is signed in, so a component can call them unconditionally.

| Hook | What it gives |
|---|---|
| `useOrganizations()` | `{ organizations, isPending, error }`: every organization the user belongs to, with their `role` (`organization.list`) |
| `useActiveOrganization()` | The session's active organization (`organization.active`), below |
| `useOrganizationMembers({ orgId?, page?, limit? })` | `{ orgId, members, total, isPending, error }`: one page of members, of the active organization when `orgId` is left out; the previous page stays on screen while the next loads |
| `useOrganizationInvitations(orgId?)` | `{ invitations, isPending, error }`: the invitations the organization sent, any status; filter `status === "pending"` for open ones |
| `useReceivedInvitations()` | `{ invitations, isPending, error }`: the open invitations addressed to the user's verified identifiers (`organization.invites`), what an invitation mail's page lists |
| `useOrganizationPermission(permissions, orgId?)` | `{ allowed, isPending }`: whether the server lets the caller do something (`organization.has-permission`), such as `{ invitation: ["create"] }` |
| `useOrganizationActions()` | The calls that change state, below |

The active organization belongs to the session, as on the server, so it survives a reload and another device signed in as the same user has its own:

<!-- ds:block id=activeorganizationstate-3t4tfdcx -->
**ActiveOrganizationState** · [`clients/react/src/organization.ts:98-107`](../../clients/react/src/organization.ts#L98-L107)

```typescript
export type ActiveOrganizationState = {
  /** The session's active organization, or null when none is set (or signed out). */
  readonly organization: OrganizationOrg | null;
  /** Its id, or null. */
  readonly activeOrganizationId: string | null;
  /** The session's active team, when the plugin has teams on. */
  readonly activeTeamId: string | null;
  readonly isPending: boolean;
  readonly error: AuthError | null;
};
```
<!-- /ds:block hash=e9bf54 -->
<!-- /ds:block hash=e9bf54 -->

The actions each resolve to the server's error (or null), never throw, and update the cache entries they affect: `setActive` writes the new active organization and re-reads everything scoped to it, `create`, `acceptInvitation` and `leave` re-read every organization entry, `removeMember` re-reads the member lists, and `setRole` re-reads everything but the active organization (the caller's own role and permissions may have changed). `leave` is `organization.remove-member` naming the signed-in user, the server's one way out of an organization; `removeMember` and `setRole` name the member by `userId`, and the last owner is refused with `organization.last_owner`:

<!-- ds:block id=organizationactions-pmrrj2p2 -->
**OrganizationActions** · [`clients/react/src/organization.ts:156-191`](../../clients/react/src/organization.ts#L156-L191)

```typescript
export type OrganizationActions = {
  /** Makes an organization the session's active one (null clears it), then re-reads everything scoped to it. */
  readonly setActive: (target: ActiveOrganizationTarget) => Promise<AuthError | null>;
  /**
   * Creates an organization with the caller as its owner. The server makes it
   * the active one unless `keepCurrentActiveOrganization` is set.
   */
  readonly create: (input: OrganizationCreateRequest) => Promise<{ readonly organization: OrganizationOrg | null; readonly error: AuthError | null }>;
  /** Invites someone into an organization (the active one when `orgId` is left out). */
  readonly invite: (input: OrganizationInviteRequest) => Promise<AuthError | null>;
  /** Cancels a pending invitation. */
  readonly cancelInvitation: (inviteId: string) => Promise<AuthError | null>;
  /** Accepts an invitation addressed to the caller and joins its organization. */
  readonly acceptInvitation: (inviteId: string) => Promise<{ readonly organization: OrganizationOrg | null; readonly error: AuthError | null }>;
  /** Declines an invitation addressed to the caller. */
  readonly rejectInvitation: (inviteId: string) => Promise<AuthError | null>;
  /**
   * Removes another member (`organization.remove-member`); needs member:delete,
   * and only an owner may remove an owner. The last owner is refused with
   * `organization.last_owner`.
   */
  readonly removeMember: (input: OrganizationMemberTarget) => Promise<AuthError | null>;
  /**
   * Takes the caller out of an organization (the active one when `orgId` is
   * left out): `organization.remove-member` naming themselves, which any
   * member may do except the last owner (`organization.last_owner`). The
   * session's active organization is cleared when it was this one.
   */
  readonly leave: (orgId?: string) => Promise<AuthError | null>;
  /**
   * Changes a member's role (`organization.set-role`); needs member:update.
   * Only an owner may grant the owner role or change an owner's, and the last
   * owner cannot be demoted (`organization.last_owner`).
   */
  readonly setRole: (input: OrganizationRoleChange) => Promise<AuthError | null>;
};
```
<!-- /ds:block hash=d53f49 -->
<!-- /ds:block hash=adb3a4 -->

`useOrganizationPermission` only hides what would be refused; the server checks again on the action itself. Because it asks the server, it follows whatever roles, access control or `Authorizer` the server runs, which a client-side role table could not. Organization reads count as fresh for [`ORGANIZATION_STALE_MS`](ds:block?id=organization-stale-ms-469j2v33), a minute; changes made through these hooks update the cache themselves.

## Step 10 — An admin dashboard

With `admin()` in the client, these hooks read the admin plugin as server state, under `ADMIN_QUERY_ROOT`. Each is inert (no request, an empty answer) when the client lacks the plugin or nobody is signed in, so a page can call them unconditionally; the server checks every permission again on each call.

| Hook | What it gives |
|---|---|
| `useAdminPermissions()` | `{ can, isAdmin, isPending }`: whether the caller holds each capability in `ADMIN_CAPABILITIES` (list users, ban, set role, impersonate, revoke sessions, the second-factor actions and the rest), asked of the server with `admin.has-permission`, so it follows whatever roles or `Authorizer` the server runs; `isAdmin` is any capability at all |
| `useAdminUsers({ page?, pageSize?, search?, searchField?, admin?, banned?, sort? })` | `{ users, total, page, pageSize, isPending, isFetching, error }`: one page of users (`admin.users`), or of users matching a fragment (`admin.search-users`) when `search` is not blank; the previous page stays on screen while the next loads. Debounce `search`: the server rate-limits fragment searches |
| `useAdminUser(userId)` | `{ detail, isPending, error }`: one user with identities, ban reason and session count (`admin.user`) |
| `useAdminUserSessions(userId, enabled?)` | `{ sessions, isPending, error }`: another user's sessions (`admin.sessions`); pass `can.listSessions` as `enabled` |
| `useAdminTwoFactor(userId, enabled?)` | `{ twoFactor, available, isPending, error }`: another user's second factor (`admin.two-factor`); `available` is false when the server has no second-factor plugin |
| `useAdminUserMetadata(userId, enabled?)` | `{ metadata, available, isPending }`: another user's public, private and unsafe metadata (`metadata.admin-get`); `available` is false when the server refuses or does not serve it |
| `useImpersonation()` | `{ impersonating, isPending }`: whether the current session is an admin acting as this user, from the user's own session list |
| `useAdminActions()` | The calls that change a user, below |

The actions each resolve to the server's error (or null), never throw, and re-read every admin entry on success, so the table, the detail and the sessions all show the change. `impersonate` and `stopImpersonating` change who is signed in: they forget every cached auth entry but the session, then re-read the session:

<!-- ds:block id=adminactions-v6r9t3qk -->
**AdminActions** · [`clients/react/src/admin.ts:428-461`](../../clients/react/src/admin.ts#L428-L461)

```typescript
export type AdminActions = {
  /** Bans a user and ends every session of theirs (`admin.ban`). */
  readonly ban: (input: AdminBanInput) => Promise<AuthError | null>;
  /** Lifts a ban (`admin.unban`). */
  readonly unban: (userId: string) => Promise<AuthError | null>;
  /** Ends one of a user's sessions (`admin.revoke-session`). */
  readonly revokeSession: (userId: string, sessionId: string) => Promise<AuthError | null>;
  /** Ends every session of a user without banning them (`admin.revoke-sessions`). */
  readonly revokeSessions: (userId: string) => Promise<AuthError | null>;
  /** Replaces a user's roles (`admin.set-role`); the server refuses a role it does not define. */
  readonly setRole: (userId: string, roles: readonly string[]) => Promise<AuthError | null>;
  /** Sets a user's password under the password plugin's rules; their sessions end (`admin.set-password`). */
  readonly setPassword: (userId: string, password: string) => Promise<AuthError | null>;
  /** Deletes a user and everything that references them (`admin.remove-user`). */
  readonly removeUser: (userId: string) => Promise<AuthError | null>;
  /** Removes a user's second factor and recovery codes, so they enrol again (`admin.reset-two-factor`). */
  readonly resetTwoFactor: (userId: string) => Promise<AuthError | null>;
  /** Pauses a user's second factor: sign-in stops asking for it (`admin.disable-two-factor`). */
  readonly disableTwoFactor: (userId: string) => Promise<AuthError | null>;
  /** Switches a paused second factor back on and ends the user's sessions (`admin.enable-two-factor`). */
  readonly enableTwoFactor: (userId: string) => Promise<AuthError | null>;
  /**
   * Signs this browser in as the user (`admin.impersonate`), for up to
   * `minutes` (the server caps it at an hour). The admin's own session is
   * kept for stopImpersonating; every cached auth entry is re-read as the user.
   */
  readonly impersonate: (userId: string, minutes?: number) => Promise<{ readonly result: AdminImpersonateResult | null; readonly error: AuthError | null }>;
  /**
   * Ends an impersonation (`admin.stop-impersonating`). `restored` is true
   * when the admin's own session came back, false when the browser is now
   * signed out (the flow cookie was gone).
   */
  readonly stopImpersonating: () => Promise<{ readonly restored: boolean; readonly error: AuthError | null }>;
};
```
<!-- /ds:block hash=b0d46a -->

The table state becomes a request through `adminUsersCall(query)`, and a pager's buttons come from `pageItems(current, last)` (the first and last page, the current one with a page either side, and `PAGE_GAP` for each run of skipped pages), with `pageRange` and `lastPage` for the "1–50 of N" line; all four are pure and exported, so a table of your own pages the same way. Admin reads count as fresh for [`ADMIN_STALE_MS`](ds:block?id=admin-stale-ms-7wq3rk2d), 15 seconds, because other admins change the same users. Most admin changes need a recent sign-in (`auth.fresh_session_required`); see AdminUserDetail's `onFreshSessionRequired` in [React components](react-components.md#adminuserdetail).

## Step 11 — Session tasks, domains and tokens for other services

**Session tasks.** A session can be signed in but unusable until a step is done: with `twofactor.RequireEnrolment` the server lists `tasks: ["setup-mfa"]` on the session and answers every other operation `403 auth.session_task_pending`. `useSessionTasks()` gives `{ tasks, pending }` from the session entry, and `SessionTaskRedirect` (or `useSessionTaskRedirect(routes?)` in a layout) sends the browser to the page that finishes the first open task: `setup-mfa` goes to `paths.setupTwoFactor` (`/setup-two-factor` by default, where TaskSetupMFA lives), and an app's own task ids go where `routes` says. Finishing a task replaces the session, so the page re-reads it (`refreshSession`). [`SESSION_TASK_SETUP_MFA`](ds:block?id=session-task-setup-mfa-2kq8vn4w) and `SESSION_TASK_PENDING_CODE` are the wire values.

**Verified domains.** With `organization()` and a server that passes `organization.Domains(...)`:

| Hook | What it gives |
|---|---|
| `useOrganizationDomains(orgId?)` | `{ orgId, domains, available, isPending, error }`: the organization's domains (`organization.list-domains`); `available` is false when the server does not serve domains |
| `useMembershipRequests(orgId?, enabled?)` | `{ requests, isPending, error }`: requests to join a domain brought in; pass the `member: ["create"]` permission as `enabled` |
| `useDomainSuggestions()` | `{ suggestions, available, isPending, error }`: the organizations the user could ask to join by their verified address |
| `useOrganizationDomainActions()` | `addDomain`, `verifyDomain`, `updateDomain`, `removeDomain`, `approveRequest`, `rejectRequest` and `requestToJoin`, each resolving to the server's error or null and re-reading what it changed |

[`DOMAIN_ENROLLMENT_MODES`](ds:block?id=domain-enrollment-modes-8xq4vn2k) lists the four enrollment modes the server takes.

**Tokens for other services.** With `jwt()` in the client, `useGetToken()` returns `getToken({ template?, skipCache? })`: the session's default JWT (`jwt.token`) or a named template's (`jwt.template`, `jwt.WithTemplate` on the server), resolving to `{ token, error }` and never throwing. Each token is cached under `JWT_QUERY_ROOT` until [`JWT_REFRESH_MARGIN_MS`](ds:block?id=jwt-refresh-margin-ms-5vq2nm8k) before it expires, so calling it before every request to another service costs a round trip only when a token is nearly spent; sign-out drops them with every other auth entry. Without React, `client.jwt.template({ template })` is the same call in the TypeScript client.

## The query keys

Everything the package caches sits under `AUTH_QUERY_ROOT` (`["ubgo-auth"]`), so `queryClient.removeQueries({ queryKey: AUTH_QUERY_ROOT })` forgets every auth entry and `signOut()` does exactly that. The keys are exported so your code can invalidate one after a change it made:

| Key | Holds | Exported from |
|---|---|---|
| `SESSION_QUERY_KEY` | The session (`useSession`) | `@ubgo/auth-react` |
| `OAUTH_PROVIDERS_QUERY_KEY` | The configured providers (`useOAuthProviders`) | `@ubgo/auth-react` |
| `EMAIL_LIST_QUERY_KEY` | The user's addresses (`usePrimaryEmail`) | `components/auth/user-button.tsx` |
| `SESSIONS_QUERY_KEY`, `OAUTH_ACCOUNTS_QUERY_KEY` | The account page's session and linked-account lists | `components/auth/account-settings.tsx` |
| `PASSKEY_LIST_QUERY_KEY` | The passkey list | `components/auth/passkey-list.tsx` |
| `ORGANIZATION_QUERY_ROOT` | Every organization entry: the list, the active organization, members, invitations sent and received, permission answers (Step 9) | `@ubgo/auth-react` |
| `JWT_QUERY_ROOT` | Tokens `useGetToken` handed out, by user and template (Step 11) | `@ubgo/auth-react` |
| `ADMIN_QUERY_ROOT` | Every admin entry: user pages and searches, one user, their sessions and second factor, the caller's capabilities, whether this session is an impersonation (Step 10) | `@ubgo/auth-react` |

Key your own auth-related queries under `AUTH_QUERY_ROOT` too, and sign-out clears them with the rest.

The example's signed-in view has a rename form of its own: it calls `client.profile`, a call the kit knows nothing about, and then invalidates `SESSION_QUERY_KEY`, so the heading that reads `useSession` shows the new name without a reload (`task ui:headless` checks it):

<!-- ds:block id=headless-rename-q4m7xz2c -->
**Rename** · [`examples/react-headless/web/src/app.tsx:115-139`](../../examples/react-headless/web/src/app.tsx#L115-L139)

```tsx
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
```
<!-- /ds:block hash=1d2d45 -->

## Try it

`task ui:headless` builds the demo's Go server, starts it and the example's Vite app on ports of their own (8113 and 5190), and drives the page headless with Playwright:

```sh
task ui:install   # once
task ui:headless
```

```text
       supportsPasskeys: "This browser can sign in with a passkey."
  ok   SignedOut renders the app's own form, the server's providers and the passkey check
       message: "That email and password do not match."
  ok   a wrong password shows the provider's localized message (useErrorMessage)
  ok   the right password signs in and SignedIn shows useSession's user
  ok   a profile change of the app's own shows after invalidating SESSION_QUERY_KEY
  ok   signOut({ redirectTo: null }) stays on the page and SignedOut comes back
  ok   usePluginClient('magiclink') sends a link
  ok   oauthStartURL is a page navigation that signs in through the provider
  ok   signOut({ everywhere: true }) goes to the custom paths.afterSignOut
react-headless: all 8 steps passed
```

The message is the provider's `localization.errors` override for `password.invalid_credentials`, not the server's text. To try it by hand, run the server and the page as in the [example's README](../../examples/react-headless/README.md#run-it) and sign in as `ada@example.com` with `correct horse battery staple`.

## Pitfalls

- **Rendering on `isPending`.** Until the first read answers, `session` is null and `isPending` is true. Treating null as "signed out" before checking `isPending` flashes the sign-in UI at a signed-in user, and a redirect on it sends them to the sign-in page. Branch on `isPending` first, or use `<SignedIn>`/`<SignedOut>`.
- **Forgetting `refreshSession()`.** A sign-in through the client sets the cookie, but the cached session still says signed out for up to a minute; call `refreshSession()` after every call that changes who is signed in, including a second-factor verify and an account switch.
- **Treating `error` as signed out.** `error` is set only for a failure that is not "nobody is signed in"; the last known session stays beside it. Show a banner, do not sign the user out of the UI.
- **A plugin outside `KnownPlugins`.** `usePluginClient("organization")` does not compile. Import your own client for those calls; it already has their types.
- **One provider, one cache.** Two `AuthProvider`s, or a provider given a different `queryClient` than the rest of the app, hold two sessions that do not see each other's refreshes.
- **Unstable props.** The provider's value is memoised on `client`, `baseURL`, `queryClient`, `navigate`, `Link`, `paths` and `localization`; inline objects and arrow functions change it on every render and re-render every consumer.
- **OAuth through fetch.** Calling the start route with `fetch` cannot work: the flow cookie and the provider's redirect need a top-level navigation. Assign `oauthStartURL(...)` to `window.location`.
- **A passkey `failure` is not an error.** `"cancelled"` covers a closed prompt, a timeout and "no passkey matched", which WebAuthn deliberately does not tell apart; show a quiet message, not an alert.

## Related

- [React UI kit](react.md): the quickstart.
- [React components](react-components.md): the components built on these hooks.
- [React with your router](react-routers.md): `navigate` and `Link` for each router, and server rendering.
- [Errors](errors.md): the error codes and `AuthError` in the TypeScript client.
- [Flows](flows.md): every flow with the client alone.

# Put the React UI on another API

The React kit's components work with any backend, not only a Go server running this library. Every registry component comes in two layers: a pure view (`SignInFormView`) that takes values, state, text and callbacks, and the wired component (`SignInForm`) that connects that view to `@ubgo/auth-react`. This page shows the three ways to put the same screens on another API, each with an example that a test runs and the type checker compiles, so the code on this page cannot go stale without a gate failing.

## Pick a way

| Your situation | Way | What you write | What you keep |
|---|---|---|---|
| Another API with its own shapes, and you are happy to own the calls and the state | [1. The views alone](#way-1--the-views-alone) | One handler per action, plus `useState` for pending and errors | The markup, validation, accessibility, slots and text of every screen |
| Another API you can map call by call onto this library's routes, or a fake backend for tests and stories | [2. A translating `fetch`](#way-2--a-translating-fetch) | One `fetch` function that rewrites requests and answers | Everything: the wired components, the provider, the hooks, the session |
| Another identity SDK (a vendor's JavaScript SDK, an in-memory store) with no HTTP you control | [3. An adapter client](#way-3--an-adapter-client) | One object with the client's method names, each answering `{ data, error }` | Everything, as in way 2 |

Ways 2 and 3 keep the wired components unchanged: the provider, the session query, redirects, the second-factor hand-off and every text override work as with the real server. Way 1 is the most flexible and the most work: you decide what each button does.

## The two layers

Each component file in the registry has a sibling view file, and `shadcn add` installs both:

| File | Exports | Imports |
|---|---|---|
| `components/auth/sign-in-form-view.tsx` | `SignInFormView`, its props, `SignInFormText` and `SIGN_IN_FORM_TEXT`, the slot union, the values type | React, the shadcn primitives, `lucide-react`, TanStack Form for local validation, `auth-view.tsx`, and types only from `@ubgo/auth-client` |
| `components/auth/sign-in-form.tsx` | `SignInForm`, and everything above again, re-exported | `@ubgo/auth-react`, TanStack Query, and the view |
| `components/auth/auth-view.tsx` | `AnchorLink`, `ViewLinkComponent`, `ViewHeadingLevel`, `fillText` | React only |

A view never imports `@ubgo/auth-react`, TanStack Query or a router, and never navigates. Its props are the screen's state (`pending`, `formError`, `fieldErrors`, the methods to show), its text (`text`, merged over the English defaults), its links (`forgotPasswordHref`, `Link`) and its events (`onSubmit(values)`, `onPasskey()`, `onProvider(id)`). It still owns what is purely presentation: form values, required-field checks, focus on the first invalid field. `clients/react/test/views-guard.test.ts` reads every view module's syntax tree, and every registry file it imports in turn, and fails on a data-layer import, so a view cannot quietly grow a dependency on the provider. Each view also has a test that renders it with plain props and no provider, no query client and no mocks (`clients/react/test/views/`).

## Way 1 — the views alone

Render the view and give it your own handlers. Nothing from `@ubgo/auth-react` is involved, so there is no provider to mount. Your API can have any shape; here it is one login call:

<!-- ds:block id=myauthapi-jwwej3zq -->
**MyAuthApi** · [`clients/react/examples/custom-backend/views-only.tsx:13-15`](../../clients/react/examples/custom-backend/views-only.tsx#L13-L15)

```tsx
export type MyAuthApi = {
  login(email: string, password: string): Promise<{ readonly ok: true; readonly userId: string } | { readonly ok: false; readonly message: string }>
}
```
<!-- /ds:block hash=52d162 -->

The screen holds the pending flag and the error, calls the API from `onSubmit`, and feeds the result back. `onSubmit` receives the typed values ([`SignInFormValues`](../../clients/react/registry/auth/sign-in-form-view.tsx): the mode, the identifier already trimmed, and the password), and the form stays in its submitting state until the promise settles:

<!-- ds:block id=customsignin-zudarghh -->
**CustomSignIn** · [`clients/react/examples/custom-backend/views-only.tsx:36-59`](../../clients/react/examples/custom-backend/views-only.tsx#L36-L59)

```tsx
export function CustomSignIn({ api, onSignedIn }: { readonly api: MyAuthApi; readonly onSignedIn: (userId: string) => void }) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(values: SignInFormValues) {
    setPending(true)
    setError(null)
    const result = await api.login(values.identifier, values.password)
    setPending(false)
    if (result.ok) onSignedIn(result.userId)
    else setError(result.message)
  }

  return (
    <SignInFormView
      pending={pending ? "password" : null}
      formError={error}
      forgotPasswordHref="/forgot"
      signUpHref="/register"
      text={{ description: "Sign in to your Acme account." }}
      onSubmit={submit}
    />
  )
}
```
<!-- /ds:block hash=eb8c52 -->

Every other view works the same way: read its props type in its `-view.tsx` file. Links render through the `Link` prop (a plain `<a>` by default), so pass your router's link component the way [React with your router](react-routers.md) does for the provider. Error text is yours too: a view shows the strings it is given, so translate your API's errors before passing them in.

## Way 2 — a translating `fetch`

`createAuthClient` takes a `fetch` option. The client keeps speaking this library's wire format, and your function answers it, by calling another API or by answering from memory. The wire format is small:

- Each method is one request to `baseURL` plus the operation's path: `POST /password/sign-in` with a JSON body, `GET /session` with the input in the query string. The paths are in the [HTTP API reference](../reference/http-api.md) and on each operation's doc comment in the generated client.
- Success is a `2xx` whose JSON body is the operation's output type (for sign-in, `{ user: { id, name, image }, verificationRequired, secondFactorRequired }`).
- Failure is any other status with the body `{ error: { code, message } }`. A code the client does not know becomes `client.unknown_code` with the raw code kept in `rawCode`; a body of any other shape becomes `client.invalid_response`. Use the library's codes where the components react to them (the list is under [Way 3](#the-error-codes-the-components-react-to)).

This `fetch` serves sign-in, the session and sign-out from a legacy API that takes `POST /api/login { email, password }`:

<!-- ds:block id=legacyfetch-w46whdwa -->
**legacyFetch** · [`clients/react/examples/custom-backend/translate-fetch.tsx:51-78`](../../clients/react/examples/custom-backend/translate-fetch.tsx#L51-L78)

```tsx
export function legacyFetch(baseURL: string, legacyBase: string, upstream: typeof fetch = fetch): typeof fetch {
  return async (input, init) => {
    const path = pathOf(input, baseURL)
    if (path === "/password/sign-in") {
      const sent = bodyOf(init)
      const res = await upstream(`${legacyBase}/api/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: sent["identifier"], password: sent["password"] }),
      })
      const user = res.ok ? legacyUser(await res.json()) : null
      if (user === null) return reply(401, { error: { code: "password.invalid_credentials", message: "Wrong email or password." } })
      return reply(200, { user: { id: user.id, name: user.name, image: "" }, verificationRequired: false, secondFactorRequired: false })
    }
    if (path === "/session") {
      const res = await upstream(`${legacyBase}/api/me`, { credentials: "include" })
      const user = res.ok ? legacyUser(await res.json()) : null
      if (user === null) return reply(401, { error: { code: "auth.signed_out", message: "Sign in to continue." } })
      return reply(200, { user: { id: user.id, name: user.name, image: "" }, expiresAt: new Date(Date.now() + 3_600_000).toISOString() })
    }
    if (path === "/sign-out") {
      await upstream(`${legacyBase}/api/logout`, { method: "POST", credentials: "include" })
      return reply(200, { ok: true })
    }
    return reply(501, { error: { code: "legacy.unsupported", message: `${path} has no legacy equivalent.` } })
  }
}
```
<!-- /ds:block hash=91a2fa -->

The client lists only the plugins the translation serves, so the components show only those methods:

<!-- ds:block id=legacyclient-mnsdjy8v -->
**legacyClient** · [`clients/react/examples/custom-backend/translate-fetch.tsx:82-84`](../../clients/react/examples/custom-backend/translate-fetch.tsx#L82-L84)

```tsx
export function legacyClient(upstream: typeof fetch = fetch) {
  return createAuthClient({ baseURL: "/auth", plugins: [password()], fetch: legacyFetch("/auth", "https://legacy.example.com", upstream) })
}
```
<!-- /ds:block hash=d900b8 -->

Then mount the provider and the wired component as usual ([`translate-fetch.tsx`](../../clients/react/examples/custom-backend/translate-fetch.tsx) has the page). The same seam fakes the whole backend in a component test or a story: answer from an object instead of calling `upstream`.

## Way 3 — an adapter client

`<AuthProvider client={…}>` takes any object with the client's method names, so an object written over another SDK works without HTTP at all. Its type is the contract, and the compiler enforces it:

<!-- ds:block id=signinadapter-khybttxg -->
**SignInAdapter** · [`clients/react/examples/custom-backend/adapter.tsx:46`](../../clients/react/examples/custom-backend/adapter.tsx#L46-L46)

```tsx
export type SignInAdapter = AnyAuthClient & { readonly password: KnownPlugins["password"] }
```
<!-- /ds:block hash=c5aa4f -->

What the object must provide:

1. **Every core method** of [`AnyAuthClient`](../../clients/react/src/context.tsx): `session`, `sessionRefresh`, `signOut`, `signOutAll`, `profile`, `sessions`, `sessionsRevoke`, `deviceSessions`, `deviceSessionsRevoke`, `deviceSessionsSwitch`, `accountDelete`, `accountDeleteConfirm`. The provider's session query calls `session()`, sign-out calls `signOut()` (or `signOutAll()`), and the account pages call the rest.
2. **A namespace for each plugin whose screens you want**, with every method of [`KnownPlugins[name]`](../../clients/react/src/plugins.ts). A namespace's presence is what switches a method on: with `password` present SignInForm shows the password form, with no `passkey` there is no passkey button. Leave a plugin out entirely rather than half-implementing it.
3. **Every method answers `{ data, error }` and never throws.** `data` is the operation's output type from `@ubgo/auth-client`; `error` is an `AuthError` (`code`, `rawCode`, `message`, `status`). An operation the SDK cannot do answers an error, never a thrown exception; `client.unknown_code` with a descriptive `rawCode` reads well.

The core methods, over an SDK that throws on failure and has its own user shape:

<!-- ds:block id=sdkcore-f93225u3 -->
**sdkCore** · [`clients/react/examples/custom-backend/adapter.tsx:55-78`](../../clients/react/examples/custom-backend/adapter.tsx#L55-L78)

```tsx
export function sdkCore(sdk: IdentitySdk): AnyAuthClient {
  const session = async (): Promise<AuthResult<AuthSessionResult>> => {
    const user = sdk.currentUser()
    return user === null ? fail("auth.signed_out", "Sign in to continue.", 401) : { data: sessionOf(user), error: null }
  }
  const signOut = async (): Promise<AuthResult<AuthDone>> => {
    await sdk.signOut()
    return { data: { ok: true }, error: null }
  }
  return {
    session,
    sessionRefresh: session,
    signOut,
    signOutAll: signOut,
    accountDelete: () => unsupported("accountDelete"),
    accountDeleteConfirm: () => unsupported("accountDeleteConfirm"),
    deviceSessions: () => unsupported("deviceSessions"),
    deviceSessionsRevoke: () => unsupported("deviceSessionsRevoke"),
    deviceSessionsSwitch: () => unsupported("deviceSessionsSwitch"),
    profile: () => unsupported("profile"),
    sessions: () => unsupported("sessions"),
    sessionsRevoke: () => unsupported("sessionsRevoke"),
  }
}
```
<!-- /ds:block hash=e0e3a2 -->

The password namespace, mapping the SDK's failures onto the library's codes:

<!-- ds:block id=sdkpassword-4ca8yqjn -->
**sdkPassword** · [`clients/react/examples/custom-backend/adapter.tsx:82-101`](../../clients/react/examples/custom-backend/adapter.tsx#L82-L101)

```tsx
export function sdkPassword(sdk: IdentitySdk): KnownPlugins["password"] {
  return {
    async signIn(input): Promise<AuthResult<PasswordSignInResult>> {
      try {
        const user = await sdk.signIn(input.identifier, input.password)
        return { data: { user: { id: user.uid, name: user.displayName, image: "" }, verificationRequired: false, secondFactorRequired: false }, error: null }
      } catch (cause) {
        if (cause instanceof IdentitySdkError && cause.code === "network") return fail("client.network_error", "The request did not reach the server.", 0)
        // Wrong password and unknown account answer alike, so the form does not tell which emails have accounts.
        return fail("password.invalid_credentials", "Wrong email or password.", 401)
      }
    },
    signUp: () => unsupported("password.signUp"),
    change: () => unsupported("password.change"),
    forgot: () => unsupported("password.forgot"),
    reauthenticate: () => unsupported("password.reauthenticate"),
    reset: () => unsupported("password.reset"),
    verify: () => unsupported("password.verify"),
  }
}
```
<!-- /ds:block hash=a853ac -->

And the adapter is the two together:

<!-- ds:block id=sdkadapter-9pazz82r -->
**sdkAdapter** · [`clients/react/examples/custom-backend/adapter.tsx:105-107`](../../clients/react/examples/custom-backend/adapter.tsx#L105-L107)

```tsx
export function sdkAdapter(sdk: IdentitySdk): SignInAdapter {
  return { ...sdkCore(sdk), password: sdkPassword(sdk) }
}
```
<!-- /ds:block hash=f57cc3 -->

The page is the wired component under the provider, with the adapter created once:

<!-- ds:block id=sdksigninpage-ezyjqyy9 -->
**SdkSignInPage** · [`clients/react/examples/custom-backend/adapter.tsx:111-118`](../../clients/react/examples/custom-backend/adapter.tsx#L111-L118)

```tsx
export function SdkSignInPage({ sdk, onSignedIn }: { readonly sdk: IdentitySdk; readonly onSignedIn: (userId: string) => void }) {
  const [client] = useState(() => sdkAdapter(sdk))
  return (
    <AuthProvider client={client}>
      <SignInForm showSignUp={false} onSuccess={(result) => onSignedIn(result.userId)} />
    </AuthProvider>
  )
}
```
<!-- /ds:block hash=092303 -->

### The error codes the components react to

A component shows any error's message, but it branches on a few codes. Answer these where they apply:

| Code | Where | What the UI does |
|---|---|---|
| `auth.signed_out` | `session()` | The session is `null` (signed out), not an error |
| `password.invalid_credentials` | `password.signIn` | The form-level "wrong email or password" message; answer it for an unknown account too, so the form does not reveal which emails have accounts |
| `auth.identifier_invalid` | sign-in, sign-up | Shown under the identifier field instead of above the form |
| `password.too_long` | sign-in, sign-up, reset | Shown under the password field |
| `client.network_error` | any | The friendly "could not reach the server" message |

The message shown is `localization.errors[code]` from the provider when set, else your `message`, else the code's English default, the same rule as with the real server ([CONTRACT.md](../../clients/react/CONTRACT.md) rule 6).

## Which methods each screen calls

The wired components call the client through `usePluginClient(name)`, and the organization and admin screens through the hooks in `@ubgo/auth-react`. For an adapter, implement the namespaces of the screens you mount:

| Screen | Namespaces |
|---|---|
| SignInForm | `password`, `magiclink`, `passkey`, `oauth` (providers), `username` (label only) |
| SignUpForm | `password`, `email`, `username`, `phone` |
| ForgotPasswordForm, ResetPasswordForm | `password` |
| VerifyEmail, ConfirmEmailChange, UserButton | `email` |
| MagicLinkCallback | `magiclink` |
| TwoFactorChallenge, TwoFactorSetup, SecurityKeys, TaskSetupMFA | `twofactor` |
| PasskeyList | `passkey` |
| AccountSettings | core methods, plus `email`, `password`, `passkey`, `oauth`, `twofactor` for their sections |
| Organization screens | `organization` |
| Admin screens, ImpersonationBanner | `admin` |

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| Every sign-in fails with `client.invalid_response` | The translating `fetch` answers a `2xx` with an empty body (a `204`, or `200` with no JSON); the client reads only a JSON body as success | Answer a JSON body, even `{ "ok": true }`, as the example's sign-out does |
| A refusal shows as `client.invalid_response` instead of its message | The error body is not `{ error: { code, message } }`: a bare string, a code without a `message`, or another API's own error shape passed through | Rewrite the failure into that shape, with both `code` and `message` as strings |
| A signed-out visitor sees an error box instead of the sign-in screen | `session` answers a failure other than `auth.signed_out` (a `401` with your API's own code); `useSession` turns only that code into "no session" and keeps any other as an error | Answer `auth.signed_out` when there is no session, in the translating `fetch` and in an adapter's `session()` |
| The form shows a code instead of a sentence, or the right message in the wrong place | A code of your API's own is `client.unknown_code` on the client (the raw code is kept in `rawCode`), and the components place only the codes they know | Map your codes onto the ones [in the table above](#the-error-codes-the-components-react-to) |
| A button is shown that only fails | The client lists a plugin the translation or the adapter does not serve, so the wired component offers its method | List only the plugins you serve, as `legacyClient` does with `password()` alone |
| Every request falls through to the "unsupported" branch | The translating `fetch` compares full URLs, or a `baseURL` other than the one the client was created with | Strip the client's own `baseURL` first, as `pathOf` does |
| A view stops compiling in a library-free package | A view file imported `@ubgo/auth-react`, TanStack Query or a router | Keep data access in the wired component; `views-guard.test.ts` fails on such an import |

## Where the examples live

The three files are in [clients/react/examples/custom-backend](../../clients/react/examples/custom-backend/). `task ui:check` type-checks them under the package's strict settings and runs [custom-backend.test.tsx](../../clients/react/test/custom-backend.test.tsx), which signs in through each one against a fake backend of its kind: a REST API, a legacy API behind the translating `fetch`, an identity SDK behind the adapter.

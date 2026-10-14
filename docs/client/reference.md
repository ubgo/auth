# TypeScript client reference

Everything the client exports, every option, the commands that regenerate it, a troubleshooting table and the questions people ask. For every method with its route and types, see the generated [method reference](../reference/ts-client.md).

## createAuthClient options

`createAuthClient(options)` builds a client: the core's methods on the root and one namespace per plugin in `options.plugins`.

| Option | Type | Default | What it does |
|---|---|---|---|
| `baseURL` | `string` | required | Where the routes are mounted, prefix included: `"/auth"` on the same site, `"https://api.example.com/auth"` elsewhere. A trailing slash is ignored. |
| `plugins` | array of factories | `[]` | The plugins whose methods the client has: `[email(), password()]`. Each name may appear once. |
| `tokenMode` | `"cookie" \| "bearer"` | `"cookie"` | Cookie mode sends credentials and lets the browser keep the session cookie. Bearer mode asks for the token, keeps it in `tokenStore` and sends it as `Authorization: Bearer`. |
| `tokenStore` | `TokenStore` | `memoryTokenStore()` | Bearer mode only: where the token is kept. |
| `fetch` | `typeof fetch` | the global `fetch` | A different fetch: tests, a runtime without one, a cookie jar on a server. |
| `headers` | `Record<string, string>` | none | Headers sent with every request. |
| `onRequest`, `onResponse`, `onSuccess`, `onError` | functions, each may be async | none | Hooks around every call (see [Hooks](#hooks-onrequest-onresponse-onsuccess-onerror)). |
| `sessionExtras` | `(value: unknown) => E` | none | Checks and types the `extras` that `auth.WithSessionExtras` adds to `client.session()` and the device-session list (see [Typed session extras](#sessionextras-typed-session-extras)). |
| `oauthQuery` | `() => string \| undefined` | the page's `location.search` without `?` | The signed query the OAuth provider's consent and login pages post back as `oauth_query`; the client fills it on `oauthprovider.consent`, `continue` and `publicClientPrelogin` when the call leaves it out. Give it where there is no `location`. |

Every method takes `(input, options?)`, where the per-call options are `signal` (an `AbortSignal`; an aborted call resolves to `client.network_error`), `headers` (extra headers for that call only) and the four hooks (for that call only, after the client's). The input may be left out when the operation has no fields or every field is optional.

## The options by example

Every snippet below is from [`clients/ts/examples/options.ts`](../../clients/ts/examples/options.ts), which the build type-checks and which runs without a server, because its client uses a stub `fetch`.

### `fetch`: a stub, a cookie jar, a test server

`fetch` takes any function with the global `fetch`'s signature. This one answers from a table and records each request, which is all a unit test of your auth screens needs:

<!-- ds:block id=options-stubfetch-7kq3wn5x -->
**stubFetch** · [`clients/ts/examples/options.ts:20-34`](../../clients/ts/examples/options.ts#L20-L34)

```typescript
export function stubFetch(answers: Record<string, () => Response>, seen: Seen[]): typeof fetch {
  return async (input, init) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const watched: Record<string, string> = {};
    for (const name of WATCHED_HEADERS) {
      const value = headers.get(name);
      if (value !== null) watched[name] = value;
    }
    seen.push({ method: init?.method ?? "GET", path: url.pathname, headers: watched });
    if (init?.signal?.aborted) throw init.signal.reason;
    const answer = answers[url.pathname];
    return answer ? answer() : new Response("404 page not found", { status: 404 });
  };
}
```
<!-- /ds:block hash=9e275a -->

The client built on it also sets `headers`, sent with every request (here a request id for the server's logs):

<!-- ds:block id=options-fetch-3wn8kq2v -->
**auth** · [`clients/ts/examples/options.ts:48-63`](../../clients/ts/examples/options.ts#L48-L63)

```typescript
const auth = createAuthClient({
  baseURL: "https://api.example.com/auth",
  tokenMode: "bearer",
  tokenStore: store,
  plugins: [password()],
  headers: { "X-Request-Id": "demo-1" },
  fetch: stubFetch(
    {
      "/auth/password/sign-in": () =>
        json(200, { user: USER, verificationRequired: false, secondFactorRequired: false }, { "Set-Auth-Token": "tok_1" }),
      "/auth/session": () => json(401, { error: { code: "auth.signed_out", message: "Melde dich an, um fortzufahren.", originalMessage: "Sign in to continue." } }),
      "/auth/sign-out": () => json(401, { error: { code: "auth.signed_out", message: "Sign in to continue." } }),
    },
    seen,
  ),
});
```
<!-- /ds:block hash=0982f5 -->

Other uses: server code that must keep cookies across calls (Node's `fetch` keeps none; [`test/smoke.ts`](../../clients/ts/test/smoke.ts) has a small cookie jar), a runtime with no global `fetch` (see Pitfalls), or a fetch that adds tracing headers.

### Per-call `headers`

Set on top of the client's `headers` for one call. The method's first argument is its input, so an operation with no input takes `undefined` before the options:

<!-- ds:block id=options-callheaders-5qx2mw8k -->
**sessionInGerman** · [`clients/ts/examples/options.ts:68-71`](../../clients/ts/examples/options.ts#L68-L71)

```typescript
export async function sessionInGerman(): Promise<AuthError | null> {
  const { error } = await auth.session(undefined, { headers: { "Accept-Language": "de" } });
  return error;
}
```
<!-- /ds:block hash=02e10d -->

`Accept-Language` asks the server to translate `message` (and to keep the English in `originalMessage`, see [Errors › Step 5](errors.md#step-5--translated-messages)); `X-Pow-Proof` carries a solved [proof-of-work](../plugins/pow.md) puzzle on the call the server challenged.

### `signal`

An aborted call does not throw: it resolves to `client.network_error` with the abort reason in `cause`, like any request that got no answer:

<!-- ds:block id=options-signal-8mw4kx3q -->
**signInWithin** · [`clients/ts/examples/options.ts:77-86`](../../clients/ts/examples/options.ts#L77-L86)

```typescript
export async function signInWithin(ms: number, identifier: string, secret: string): Promise<AuthError | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`no answer within ${ms}ms`)), ms);
  try {
    const { error } = await auth.password.signIn({ identifier, password: secret }, { signal: controller.signal });
    return error;
  } finally {
    clearTimeout(timer);
  }
}
```
<!-- /ds:block hash=cf5526 -->

### The helper types

`Methods<Ops>` is the type of one namespace and `typeof client` the type of a whole client, so a helper can take just the part it uses and work with any client that has it:

<!-- ds:block id=options-generic-2kw7qn4x -->
**signInAs** · [`clients/ts/examples/options.ts:92-95`](../../clients/ts/examples/options.ts#L92-L95)

```typescript
export async function signInAs(methods: Methods<PasswordOps>, identifier: string, secret: string): Promise<string | null> {
  const { data } = await methods.signIn({ identifier, password: secret });
  return data?.user.name ?? null;
}
```
<!-- /ds:block hash=de343b -->

### Hooks: `onRequest`, `onResponse`, `onSuccess`, `onError`

Hooks see every call of the client. They run in order: the plugins' hooks, the client's, then the call's own. `onRequest` gets the operation, the URL and the request `Headers` (change them to change the request), `onResponse` a copy of the answer (reading its body leaves the client's intact), then exactly one of `onSuccess` (with the data) and `onError` (with the `AuthError`). The client waits for an async hook. A hook that throws fails the call with `client.hook_failed`, the thrown value as its `cause`; a throwing `onRequest` sends nothing.

<!-- ds:block id=tsx-hooks-client-5qw8kn3v -->
**traced** · [`clients/ts/examples/hooks-and-extras.ts:10-19`](../../clients/ts/examples/hooks-and-extras.ts#L10-L19)

```typescript
export const traced = createAuthClient({
  baseURL: "/auth",
  plugins: [password()],
  onRequest: ({ headers }) => {
    headers.set("X-Request-Id", crypto.randomUUID());
  },
  onError: ({ op, error }) => {
    if (error.code !== "auth.signed_out") console.warn(op.id, error.code, error.rawCode);
  },
});
```
<!-- /ds:block hash=f67b9d -->

### `sessionExtras`: typed session extras

`auth.WithSessionExtras` returns `any` in Go, so the generator cannot know the shape, and without this option `extras` is `unknown`. Give a decoder that returns the shape or throws; the client runs it on every `extras` in the core's answers, and the type follows: `data.extras` is what the decoder returns. Extras the decoder refuses fail the call with `client.invalid_response`.

<!-- ds:block id=tsx-session-extras-8mv2qk4w -->
**planExtras** · [`clients/ts/examples/hooks-and-extras.ts:30-36`](../../clients/ts/examples/hooks-and-extras.ts#L30-L36)

```typescript
function planExtras(value: unknown): Plan {
  if (typeof value === "object" && value !== null && "plan" in value && "seats" in value) {
    const { plan, seats } = value;
    if ((plan === "free" || plan === "pro") && typeof seats === "number") return { plan, seats };
  }
  throw new Error("session extras are not a Plan");
}
```
<!-- /ds:block hash=cca356 -->

<!-- ds:block id=tsx-session-seats-4wq9kn2v -->
**seatsLeft** · [`clients/ts/examples/hooks-and-extras.ts:41-44`](../../clients/ts/examples/hooks-and-extras.ts#L41-L44)

```typescript
export async function seatsLeft(used: number): Promise<number> {
  const { data } = await withPlan.session();
  return (data?.extras?.seats ?? 0) - used; // extras is Plan here
}
```
<!-- /ds:block hash=fda258 -->

### Try it

```sh
node clients/ts/examples/options.ts
```

Node 22.18 or later runs the `.ts` file as it is. The output of a real run (the German message comes from the stub, standing in for a server with a German catalogue):

```text
signIn           ok, store holds tok_1
session (de)     401 auth.signed_out "Melde dich an, um fortzufahren." original "Sign in to continue."
signIn (aborted) 0 client.network_error, cause: Error: user left the page
signOut          401 auth.signed_out, store holds null
signInAs         Ada
requests the stub saw:
  POST /auth/password/sign-in {"auth-token-mode":"bearer","x-request-id":"demo-1"}
  GET /auth/session {"accept-language":"de","authorization":"Bearer tok_1","auth-token-mode":"bearer","x-request-id":"demo-1"}
  POST /auth/password/sign-in {"authorization":"Bearer tok_1","auth-token-mode":"bearer","x-request-id":"demo-1"}
  POST /auth/sign-out {"authorization":"Bearer tok_1","auth-token-mode":"bearer","x-request-id":"demo-1"}
  POST /auth/password/sign-in {"auth-token-mode":"bearer","x-request-id":"demo-1"}
```

Read the request lines against the options: `x-request-id` (the client's `headers`) is on every request, `accept-language` (per-call) only on the one call that set it, `auth-token-mode: bearer` on all of them, and `authorization` from the moment a sign-in stored a token. The fourth result line is the first pitfall below.

### Pitfalls

- **The server says when the token is dead; `auth.signed_out` alone does not.** A bearer client empties its `TokenStore` whenever a response carries `Set-Auth-Token` with an empty value: the call ended the session (sign-out, revoking the current session, deleting the account) or the token names no session any more (expired, revoked elsewhere). A pending second-factor token is refused with the same `auth.signed_out` but is alive, so no header comes and the store keeps it for `twofactor.verify`; any other refusal (a wrong password, a rate limit, a network failure) keeps it too. The stub above sends no header, so the `signOut` line shows the fallback for a server without it: `signOut()` and `signOutAll()` forget the token when they answer `auth.signed_out`. See [Bearer mode › Forget the token](bearer-and-mobile.md#forget-the-token-when-the-session-is-gone).
- **No global `fetch` fails at construction.** Without the `fetch` option, `createAuthClient` reads `globalThis.fetch` when it builds the client, so on a runtime that has none (Node 16 and older, some test environments) it throws `` auth client: this runtime has no global fetch; pass one as the `fetch` option of createAuthClient `` before any call. Pass `fetch` explicitly there: `createAuthClient({ baseURL, fetch: myFetch })`.
- **A per-call header replaces a client header of the same name**, it does not add a second value; and the client sets `Accept` (and `Content-Type` on a POST) after both, so neither the client's `headers` nor a call's can change them.
- **`sessionExtras` decodes every `extras`, at any depth, of the core's answers only.** A plugin's own answer that happens to have an `extras` member is left alone.
- **`signal` aborts only the request.** The call resolves to `client.network_error`, which your error handling may show as "you are offline"; check `error.cause` (or your own flag) before telling a user who navigated away that their connection failed.

## Everything the package exports

`index.ts` re-exports three modules.

From `client.ts` (generated):

| Export | What it is |
|---|---|
| `createAuthClient(options)` | Builds a client typed with the core's operations and the plugins given |
| `password()`, `twofactor()`, ... | One factory per plugin the generating program knows; see the [method reference](../reference/ts-client.md#plugins) |
| `CoreOps`, `coreOps` | The core's operation table, its type and its value |
| `<Plugin>Ops` (`PasswordOps`, ...) | Each plugin's operation table type |
| `<Package><Type>` (`PasswordSignInRequest`, `AuthSessionResult`, ...) | One type per Go input and output, named after its package and type |

From `runtime.ts` (the same for every app):

| Export | What it is |
|---|---|
| `AuthClient<Core, P>` | The client's type; `typeof client` is usually easier |
| `AuthResult<Out>` | `{ data: Out, error: null } \| { data: null, error: AuthError }` |
| `AuthError` | `code`, `rawCode`, `message`, `status`, and optional `originalMessage`, `retryAfter`, `cause`; see [Errors](errors.md) |
| `ClientErrorCode` | `"client.network_error" \| "client.invalid_response" \| "client.unknown_code" \| "client.hook_failed"` |
| `ClientOptions<P, E>`, `CallOptions` | The options above |
| `ClientHooks`, `RequestContext`, `ResponseContext`, `SuccessContext`, `ErrorContext`, `OpInfo` | The hooks and what each receives |
| `TokenMode`, `TokenStore`, `memoryTokenStore(initial?)` | Bearer mode's token handling; see [Bearer mode](bearer-and-mobile.md) |
| `keyValueTokenStore(storage, key?)`, `KeyValueStorage`, `TOKEN_STORAGE_KEY` | A `TokenStore` over `localStorage`, `sessionStorage` or React Native's `AsyncStorage`, under `"ubgo-auth.token"` unless given a key |
| `WithExtras<T, E>` | `T` with every `extras` member typed `E`; how `sessionExtras` types the answers |
| `Fill<In, K>`, `InputFill` | An input whose fields `K` the client fills (`oauth_query`) |
| `Op<In, Out>`, `OpTable`, `Plugin<Name, Ops, Actions>`, `AnyPlugin`, `NoActions`, `ActionsOf<Q>`, `ClientContext`, `Method<O, E>`, `Methods<Ops, E>`, `PluginMethods<P>` | The types the generated tables and the hand-written plugins are built from; needed only to write generic helpers or a plugin with actions |
| `EmptyInput` | The input of an operation with no fields |
| `HttpMethod` | `"GET" \| "POST"` |
| `createClient(core, options)` | What `createAuthClient` wraps; an app never calls it |

From `extensions.ts` (hand-written, the same for every app; see [Plugins › Hand-written plugins](plugins.md#hand-written-plugins-popup-sign-in-and-the-last-login-hint)):

| Export | What it is |
|---|---|
| `oauthPopup(options?)` | The popup sign-in of `plugin/oauthproxy/oauthpopup`, as `client.oauthPopup.signIn` |
| `OAuthPopupSignIn`, `OAuthPopupResult`, `OAuthPopupSuccess`, `OAuthPopupError`, `OAuthPopupClientErrorCode`, `OAuthPopupServerErrorCode`, `OAuthPopupMessage`, `OAuthPopupData`, `OAuthPopupOptions`, `OAuthPopupActions`, `PopupHost`, `PopupWindow`, `PopupMessageEvent`, `OAUTH_POPUP_TIMEOUT_MS` | Its input, answer, closed error codes, the page's message, and the window seam a test or a shell replaces |
| `lastLoginMethod(options?)` | The last-login hint of `plugin/lastlogin`, as `client.lastLoginMethod` |
| `LastLoginMethodOptions`, `LastLoginMethodActions`, `LAST_LOGIN_STORAGE_KEY` | Its options (`storage`, `resolve`), its methods, and the key it is kept under on a device |

From `error-codes.ts` (generated):

| Export | What it is |
|---|---|
| `AUTH_ERROR_CODES` | Every code with its `status`, `message` and owning `plugin` |
| `AuthErrorCode` | The union of every code |
| `AuthErrorBody` | The wire shape `{ error: { code, message } }` |
| `isAuthErrorCode(code)` | Narrows a string to `AuthErrorCode` |

## Regenerate

| Client | Command | Run it when |
|---|---|---|
| The prebuilt one (`clients/ts/src`, in this repository) | `task docs:api` | A plugin, operation, type or error code of the library changed; `task check` fails until you do |
| Your app's own | `myapp auth client ts --out web/src/auth` (or `go run . auth client ts --out web/src/auth`) | Your plugins, their types or codes changed, you added a plugin, or you upgraded the library |
| A copy of the prebuilt one in your frontend | copy `clients/ts/src/*.ts` again | You upgraded the library |

The [freshness check](custom-plugins.md#step-7--fail-the-build-when-the-copy-is-stale) makes the second one impossible to forget.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Property 'x' does not exist on type 'AuthClient<...>'` | The plugin's factory is not in `plugins`. | Add `x()`; see [Plugins](plugins.md). |
| A factory you expect is not exported | The client was generated by a program that does not wire that plugin (your plugin, in the prebuilt client). | [Generate from your app](custom-plugins.md). |
| `auth.origin_not_trusted` (403) on a cookie-mode POST | The page's origin is not the server's base URL or one of `auth.WithTrustedOrigins`, as with a dev server on another port. | [SPA frontends › Step 2](../integrations/spa-frontends.md#step-2--trust-the-frontends-origin). |
| Every call is `auth.signed_out` right after a successful sign-in, browser on another site | Cookie mode across sites, or bearer mode without CORS exposing `Set-Auth-Token`. | [Bearer mode › Step 4](bearer-and-mobile.md#step-4--a-frontend-on-another-site). |
| `client.network_error` from a browser, server log shows nothing | A CORS preflight was refused, or the URL is wrong. | Check `baseURL`, then CORS. |
| `client.invalid_response` | Something other than the library answered: a proxy error page, a 404 from a wrong `baseURL`, or an app's own error encoder. | Check the response in the network tab. |
| `client.unknown_code` | The copy of the client predates the code. | [Regenerate](#regenerate). |
| `client.hook_failed` | One of your hooks threw; `error.cause` is what it threw. | Fix the hook, or catch inside it if a failure there should not fail the call. |
| `auth client ts` fails with `TypeScript name collision` | Two operations of one plugin differ only in punctuation, a plugin is named after a TypeScript keyword or a core method, or a Go type's name equals a runtime export. | Rename what the message names. |
| An OAuth start call returns nothing useful | Browser flows are navigations, not calls. | [Flows › OAuth](flows.md#oauth-continue-with-google). |
| `An import path can only end with a '.ts' extension when 'allowImportingTsExtensions' is enabled` | The tsconfig lacks the two settings the files need. | Set `"allowImportingTsExtensions": true` and `"moduleResolution": "bundler"`. |
| `auth client: "x" is given twice, or is also a core method` thrown at start | A factory is listed twice. | List each plugin once. |
| `` auth client: this runtime has no global fetch; pass one as the `fetch` option of createAuthClient `` thrown at start | The runtime has no global `fetch` and none was passed. | Pass `fetch` ([Pitfalls](#pitfalls)). |
| Bearer mode: the app still thinks it is signed in although every call answers `auth.signed_out` | The token is pending a second factor, or the server predates the empty `Set-Auth-Token`, or CORS does not expose it. | Finish `twofactor.verify`; expose `Set-Auth-Token`; against an older server clear the store on `auth.signed_out` yourself ([Pitfalls](#pitfalls)). |

## FAQ

**Do I generate one client per plugin?** No. One generation writes one `client.ts` with every plugin the program knows; each client you create picks plugins from it with `plugins: [...]`.

**Do I commit the generated files?** Yes. They are source your frontend compiles against, the diff shows reviewers what changed in the API, and a [freshness check](custom-plugins.md#step-7--fail-the-build-when-the-copy-is-stale) keeps them honest. Do not edit them; the next generation overwrites them.

**What if the server has a plugin I did not list?** Nothing breaks: the client just has no methods for it. You can still call its routes with your own `fetch`; add its factory when you want them typed.

**What if I list a plugin the server does not have?** The methods exist in TypeScript and the server answers 404: `auth.unknown_operation` when the library's handler answers the miss, or `client.invalid_response` when a router or proxy in front of it answers first with a body that is not the library's JSON. Keep `plugins` the same as the server's plugin list.

**Is there a React hook / Vue composable / Svelte store?** For React, yes: [`@ubgo/auth-react`](react.md) has `AuthProvider`, `useSession` and the rest, and a registry of copy-in components built on them. For Vue and Svelte, not yet: call the methods from your framework's own data layer (a query library, a store, an effect); every method is a plain promise.

**Can I use it from Node, a server, or a test?** Yes: Node 18 or later has `fetch`, Node 22.18 or later runs the `.ts` files as they are, without a flag. Use bearer mode, forward a cookie per request, or pass your own `fetch`. See [Bearer mode › Step 5 and 6](bearer-and-mobile.md#step-5--server-side-code-calling-for-a-browser).

**Is it on npm?** No. `@ubgo/auth-client` is not published to npm; copy the files, or generate them from your app.

**Does the client refresh the session by itself?** No. How long a session lives and whether use extends it is the server's configuration ([Sessions](../concepts/sessions.md)); when a session ends, calls answer `auth.signed_out` and your app signs the user in again. `client.sessionRefresh()` is there for a server that defers refreshing to the client.

## Not built yet

- Vue and Svelte bindings (React has [its own kit](react.md)).
- Helpers for browser redirects in the client itself (OAuth start, the pages mail links open); the [Flows](flows.md) page shows the few lines each takes, and the [React kit](react.md) has `oauthStartURL` and a component for each mailed page.
- The bearer-mode headers for a session cache snapshot and a remembered device (`Set-Auth-Session-Cache`, `Set-Auth-Device`): the client returns what the routes answer, and an app that needs them keeps them through a custom `fetch`.
- A published npm package.

## See also

- [`clients/ts/README.md`](../../clients/ts/README.md): the package, its tasks and how it is generated.
- [HTTP API reference](../reference/http-api.md) and [`openapi.json`](../reference/openapi.json): the same routes as a table and as OpenAPI 3.1.
- [CLI](../integrations/cli.md): `auth client ts` beside the other operator commands.

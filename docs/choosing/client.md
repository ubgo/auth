# Choose a client setup

This guide answers the questions a frontend settles before its first call: which copy of the TypeScript client, how the session travels, where the page lives relative to the API, how much of the React kit to take, how it meets your router, and which plugins to list. Every option is the same generated client underneath (the [TypeScript client](../client/README.md) explains it), so a choice made here can be changed later without touching the server. Each answer links the guide section that does it and the example that runs it.

## 1. Which copy of the client

| Your situation | Use | Why | Guide | Example |
|---|---|---|---|---|
| You use only the library's own plugins | The prebuilt client: copy the five files of `clients/ts/src` | Ready now; it knows the core, every built-in plugin and every built-in error code | [Quickstart › Step 1](../client/quickstart.md#step-1--copy-the-client-into-your-frontend) | [clients/ts/examples](../../clients/ts/examples/) |
| You wrote an operation of your own (`auth.Define`) and call it from TypeScript | Your app generates its own: `myapp auth client ts --out dir` | Only a client generated from your binary knows your operations, their types and your error codes | [Your own plugins](../client/custom-plugins.md) | [ts-client-custom](../../examples/ts-client-custom/) |
| You want only your app's routes in the editor, and your OAuth providers' methods | Your app generates its own | The prebuilt client was generated with Google and GitHub and every plugin; yours has exactly what you wire | [Plugins › Pitfalls](../client/plugins.md#pitfalls) | [ts-client-custom](../../examples/ts-client-custom/) |
| You are not sure | Start prebuilt | Switching is replacing five files; the API (`createAuthClient`, `{ data, error }`, the factories) is the same | [Two ways to get the client](../client/README.md#two-ways-to-get-the-client) | |

- If you generate your own, commit the files and add the test that fails when the copy is stale ([Step 7](../client/custom-plugins.md#step-7--fail-the-build-when-the-copy-is-stale)); a stale client compiles and calls routes that changed.
- If you keep the prebuilt copy, copy it again whenever you upgrade the library.

## 2. Cookie or bearer

| The code runs in | Mode | Why | Guide | Example |
|---|---|---|---|---|
| A browser on the API's site (same origin, or another origin under the same registrable domain) | `cookie`, the default | The session is an `HttpOnly` cookie no script can read; the client sends `credentials: "include"` and the browser does the rest | [Quickstart › Step 2](../client/quickstart.md#step-2--create-one-client-for-the-app) | [spa.ts](../../clients/ts/examples/spa.ts) |
| A browser on another site (`app.example` calling `api.example.com`) | `bearer` | A `SameSite=Lax` cookie is not sent on a cross-site `fetch`, so it cannot carry the session | [Bearer mode › Step 4](../client/bearer-and-mobile.md#step-4--a-frontend-on-another-site) | [spa-cross-origin](../../examples/spa-cross-origin/) |
| A mobile app, a desktop app, a CLI, a Node script | `bearer` with a `TokenStore` | There is no cookie jar; the token lives where you put it (keychain, secure storage, a file) | [Bearer mode › Step 3](../client/bearer-and-mobile.md#step-3--choose-where-the-token-is-kept) | [ts-client-bearer](../../examples/ts-client-bearer/) |
| A Node server rendering a page for a browser that is signed in by cookie | `cookie` with the browser's `Cookie` header forwarded, one client per request | The session belongs to the browser; the server only reads it | [Bearer mode › Step 5](../client/bearer-and-mobile.md#step-5--server-side-code-calling-for-a-browser) | [ts-client-bearer](../../examples/ts-client-bearer/) (`web/server.ts`) |

- If a page can use the cookie, use it: a bearer token in browser memory or storage is readable by any script an attacker manages to inject, and the cookie is not.
- If you pick bearer without a `tokenStore`, the token lives in memory and is gone when the page or process ends. Pass a store to stay signed in.
- If you forward a browser's cookie from server code, do reads only: a mutation sent with a cookie must carry an `Origin` the API trusts, which a server-side caller does not have. For writes, call the Go API in-process or use bearer mode.
- A bearer client forgets its token by itself whenever the server answers an empty `Set-Auth-Token`: the call ended the session, or the token expired or was revoked. A pending second-factor token is never cleared. Clear the store yourself on `auth.signed_out` only against a server older than that header ([Forget the token](../client/bearer-and-mobile.md#forget-the-token-when-the-session-is-gone)).

## 3. Where the page lives

| The page is served from | The browser sees | You need on the server | Guide | Example |
|---|---|---|---|---|
| The API's own origin (the bundle and `/auth` on one host), or a dev server proxying `/auth` | same origin | nothing: the origin check passes on its own | [React UI kit › Step 2](../client/react.md#step-2--serve-the-api-on-the-same-origin) | [react-demo](../../examples/react-demo/), [react-headless](../../examples/react-headless/) |
| Another origin on the same site (`app.example.com` and `api.example.com`, or `localhost:5173` and `localhost:8081`) | same site, different origin | the page's origin in `auth.WithTrustedOrigins`, and CORS for that origin alone with credentials | [SPA frontends › Steps 2-3](../integrations/spa-frontends.md#step-2--trust-the-frontends-origin) | [spa-cross-origin](../../examples/spa-cross-origin/) |
| Another site | cross-site | the same, plus bearer mode and `Set-Auth-Token` in `Access-Control-Expose-Headers` | [SPA frontends › Step 5](../integrations/spa-frontends.md#step-5--another-site-bearer-mode) | [spa-cross-origin](../../examples/spa-cross-origin/) |
| No browser (an app, a CLI) | no origin at all | nothing: a bearer request needs no `Origin` | [Mobile apps › Step 5](../integrations/mobile-apps.md#step-5--sign-out-and-handle-a-dead-token) | [ts-client-bearer](../../examples/ts-client-bearer/), [mobile-bearer](../../examples/mobile-bearer/) |

- If you can, proxy `/auth` through the page's own host, in development and in production: one origin means no CORS, no trusted-origin list and a first-party cookie.
- If origins change at run time (a preview deployment per branch, one origin per tenant), use `auth.WithTrustedOriginFunc` or a `https://*.example.com` pattern rather than a growing list ([SPA frontends › Step 2](../integrations/spa-frontends.md#step-2--trust-the-frontends-origin)).
- If you use the React kit, plan for one origin: it is written and tested in cookie mode through a same-origin proxy.

## 4. How much of the React kit

| You want | Use | Why | Guide | Example |
|---|---|---|---|---|
| Ready-made sign-in, sign-up, reset, two-factor, passkey and account screens close to what you would build | Registry components (`shadcn add`) on `@ubgo/auth-react` | The files are copied into your app and are yours to edit; the session logic stays in the imported package | [React UI kit](../client/react.md), [React components](../client/react-components.md) | [react-demo](../../examples/react-demo/) |
| Every screen in your own design system, with the session, gates and error text handled | `@ubgo/auth-react` hooks only | Provider, `useSession`, `useSessionActions`, `SignedIn`/`SignedOut`, `usePluginClient`, `useOAuthProviders`, `useErrorMessage`; no Tailwind or shadcn needed | [React hooks](../client/react-hooks.md) | [react-headless](../../examples/react-headless/) |
| A few components plus your own pieces beside them | Both | They share one provider and one query cache | [React hooks › When you want the hooks](../client/react-hooks.md#when-you-want-the-hooks) | [react-demo](../../examples/react-demo/) |
| Vue, Svelte, Solid, plain TypeScript, React Native | The plain TypeScript client | The hooks only add React state on top of it; every flow is a client call | [Quickstart](../client/quickstart.md), [Flows](../client/flows.md) | [ts-client-flows](../../examples/ts-client-flows/) |
| No JavaScript build at all | The Go ready-made pages (`authui`) | Server-rendered pages that follow your plugin list | [Ready-made pages](../integrations/ready-made-pages.md) | [ready-made-pages](../../examples/ready-made-pages/) |

- If you start with components and later want your own screen, replace one component with the hooks; nothing else changes.
- If you use the registry, your app needs shadcn set up for Base UI and Tailwind v4 ([React UI kit › Before you start](../client/react.md#before-you-start)); the hooks need only React 19 and TanStack Query 5.

## 5. Which router setup

| Your app | Pass to `AuthProvider` | Guide | Example |
|---|---|---|---|
| TanStack Router | `navigate` calling `router.navigate({ href })`, and a `Link` wrapper taking `href` | [TanStack Router](../client/react-routers.md#tanstack-router) | [react-demo](../../examples/react-demo/) |
| React Router | `useNavigate()` and a wrapper turning `href` into `to` | [React Router](../client/react-routers.md#react-router) | [react-router-app](../../examples/react-router-app/) |
| Next.js App Router | the provider in a `"use client"` component in the root layout, with `useRouter().push` and `next/link` | [Next.js App Router](../client/react-routers.md#nextjs-app-router) | [nextjs-app](../../examples/nextjs-app/) |
| No router, or a multi-page app | nothing: `navigate` is a page load, `Link` an `<a>` | [No router](../client/react-routers.md#no-router) | [react-headless](../../examples/react-headless/) |

- If pages render on the server, know that the hooks never read the session there: protect a page before it is sent in server code ([Server rendering](../client/react-routers.md#server-rendering)).
- If you pass `navigate` inline, wrap it in `useCallback`, or every auth component re-renders on each render.

## 6. Which plugins to list

| Situation | Do | Why | Guide |
|---|---|---|---|
| Any client | List exactly the plugins the Go app passes to `auth.WithPlugins` | A plugin the server lacks compiles and answers `auth.unknown_operation` (404) at run time; a plugin the server has but the list lacks has no methods | [Plugins › Step 1](../client/plugins.md#step-1--why-you-list-the-plugins) |
| Several apps or environments with different plugin sets | One client per app, built from that app's list, or a client generated by each app | The prebuilt client cannot know which plugins a given server wires | [Your own plugins](../client/custom-plugins.md) |
| React | The same list on the client you pass to `AuthProvider` | The components and `usePlugin` show a method only when its plugin is in the client, so the list decides which buttons appear | [React hooks › Step 4](../client/react-hooks.md#step-4--sign-in-with-a-form-of-your-own) |

- If `plugins` is built from configuration, check for duplicates: the same factory twice throws at start-up ([Plugins › Pitfalls](../client/plugins.md#pitfalls)).
- If you are unsure which plugins the server has, generate the client from the server ([Your own plugins](../client/custom-plugins.md)); its `client.ts` has only those.

## Pitfalls

- `auth.origin_not_trusted` (403) on every POST from the page: it is on an origin the server does not trust. Proxy `/auth` through the page's host, or add the origin to `auth.WithTrustedOrigins` with the exact scheme and port.
- Signed in, then signed out on the next call: the cookie is `Secure` and the page is on plain HTTP somewhere other than `localhost`, or the page is cross-site and the cookie is never sent. Serve HTTPS; use bearer mode across sites.
- `res.headers.get("Set-Auth-Token")` is `null` in a cross-origin browser: the CORS answer does not expose the header.
- A bearer app that says "signed in" forever: it decides from `tokenStore.get()` while the browser hides the empty `Set-Auth-Token` that tells the client to forget a dead token (CORS does not expose the header), or the server predates that header.
- Two copies of React or TanStack Query with a linked kit: hooks throw or the session never updates. Set `resolve.dedupe` ([React UI kit › Pitfalls](../client/react.md#pitfalls)).

## Next

- [TypeScript client](../client/README.md): the learning path from a first call to production.
- [Choose a transport](transport.md): the server side of the same questions.
- [Choose a session strategy](sessions.md): where the session lives on the server.

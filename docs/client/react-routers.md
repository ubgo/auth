# React with your router

The React UI kit works with any router, and with none. The provider takes two things from your app: a `navigate` function the components call after a sign-in, a hand-off or a sign-out, and a `Link` component they render between auth pages. This page shows both for TanStack Router, React Router and the Next.js App Router, what happens with no router at all, and what to know when pages render on the server.

## What the provider needs

<!-- ds:block id=authlinkprops-e8j2vhga -->
**AuthLinkProps** · [`clients/react/src/context.tsx:21-25`](../../clients/react/src/context.tsx#L21-L25)

```tsx
export type AuthLinkProps = {
  readonly href: string;
  readonly className?: string;
  readonly children: ReactNode;
};
```
<!-- /ds:block hash=5bee79 -->

The provider's `navigate` prop is `(href: string) => void`, and `Link` is a component taking those props.

Both are optional. Left out, `navigate` is `window.location.assign` (a full page load) and `Link` is a plain `<a>`, which work everywhere and keep nothing in memory between pages. Pass the router's versions to keep navigation client-side: no reload, the query cache and the session survive, and the next page renders at once.

`Link` receives only `href`, `className` and `children`. Most routers' links take a different prop (`to`) or more props, so you pass a small wrapper rather than the router's `Link` itself.

## Before you start

- The quickstart's Steps 1 to 4 ([React UI kit](react.md)): packages linked, `/auth` on the page's origin, the client created.
- The pages the components send people to (`paths`) and the pages mailed links open, as routes in your router: [Step 6 of the quickstart](react.md#step-6--add-the-pages-mailed-links-open).

## TanStack Router

The demo uses TanStack Router. Its `Link` takes `to`, so the demo's `RouterLink` is a plain anchor that hands a left click to `router.navigate({ href })` and leaves a modified click (new tab, new window) to the browser:

<!-- ds:block id=routerlink-n2u39u8m -->
**RouterLink** · [`examples/react-demo/web/src/components/demo-shell.tsx:22-34`](../../examples/react-demo/web/src/components/demo-shell.tsx#L22-L34)

```tsx
export function RouterLink({ href, className, children }: AuthLinkProps) {
  const router = useRouter()
  const onClick = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
    e.preventDefault()
    void router.navigate({ href })
  }
  return (
    <a href={href} className={className} onClick={onClick}>
      {children}
    </a>
  )
}
```
<!-- /ds:block hash=edc69f -->

The provider is mounted inside the root route's component, where `useRouter()` works, with `navigate` wrapped in `useCallback` so the provider's value stays stable:

<!-- ds:block id=shell-3sn7fvmr -->
**Shell** · [`examples/react-demo/web/src/components/demo-shell.tsx:87-114`](../../examples/react-demo/web/src/components/demo-shell.tsx#L87-L114)

```tsx
function Shell() {
  const router = useRouter()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const { language } = useDemoCustomise()
  const navigate = useCallback((href: string) => void router.navigate({ href }), [router])
  return (
    <AuthProvider client={auth} navigate={navigate} Link={RouterLink} localization={language === "de" ? GERMAN : undefined}>
      <div className="flex h-svh flex-col bg-background text-[13px] text-foreground">
        <header className="flex h-11 shrink-0 items-center justify-between gap-2 border-b px-4">
          <RouterLink href="/" className="flex items-center gap-2 font-semibold tracking-tight">
            Acme
            <span className="rounded-md border px-1.5 text-[11px] font-normal text-muted-foreground">ubgo/auth React demo</span>
          </RouterLink>
          <UserButton showName />
        </header>
        <ImpersonationBanner adminHref="/admin" />
        <SessionTaskRedirect />
        <MobileNav pathname={pathname} />
        <div className="flex min-h-0 flex-1">
          <Sidebar pathname={pathname} />
          <main className="min-w-0 flex-1 overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </AuthProvider>
  )
}
```
<!-- /ds:block hash=d30a08 -->

The routes are one line each:

<!-- ds:block id=routes-72e2hh2j -->
**routes** · [`examples/react-demo/web/src/router.tsx:38-59`](../../examples/react-demo/web/src/router.tsx#L38-L59)

```tsx
const routes = [
  page("/", HomePage),
  page("/sign-in", SignInPage),
  page("/sign-up", SignUpPage),
  page("/magic-link", MagicLinkPage),
  page("/forgot-password", ForgotPasswordPage),
  page("/reset-password", ResetPasswordPage),
  page("/verify-email", VerifyEmailPage),
  page("/two-factor", TwoFactorPage),
  page("/two-factor/setup", TwoFactorSetupPage),
  page("/passkeys", PasskeysPage),
  page("/setup-two-factor", SetupTwoFactorPage),
  page("/account", AccountPage),
  page("/account-sections", AccountSectionsPage),
  page("/user-button", UserButtonPage),
  page("/confirm-email-change", ConfirmEmailChangePage),
  page("/undo-email-change", UndoEmailChangePage),
  page("/organizations", OrganizationsPage),
  page("/invitations", InvitationsPage),
  page("/admin", AdminPage),
  page("/inbox", InboxPage),
]
```
<!-- /ds:block hash=e5145a -->

## React Router

React Router's `Link` also takes `to`, and `useNavigate()` returns a function that takes a path. Wrap both, and mount the provider in the component of your root route, where the hooks work. This is [examples/react-router-app](../../examples/react-router-app/) (React Router 8.4.0 in data mode, on Vite):

<!-- ds:block id=rr-routerlink-axxx6va2 -->
**RouterLink** · [`examples/react-router-app/src/root.tsx:14-20`](../../examples/react-router-app/src/root.tsx#L14-L20)

```tsx
export function RouterLink({ href, className, children }: AuthLinkProps) {
  return (
    <RRLink to={href} className={className}>
      {children}
    </RRLink>
  )
}
```
<!-- /ds:block hash=3a6499 -->

<!-- ds:block id=rr-root-xzsjnkv5 -->
**Root** · [`examples/react-router-app/src/root.tsx:24-33`](../../examples/react-router-app/src/root.tsx#L24-L33)

```tsx
export function Root() {
  const go = useNavigate()
  const navigate = useCallback((href: string) => void go(href), [go])
  return (
    <AuthProvider client={auth} navigate={navigate} Link={RouterLink}>
      <Header />
      <Outlet />
    </AuthProvider>
  )
}
```
<!-- /ds:block hash=f44351 -->

`Root` is the element of the top route, and the pages are its children, at the kit's default paths (the page a mailed link opens included, [Step 6 of the quickstart](react.md#step-6--add-the-pages-mailed-links-open)):

<!-- ds:block id=rr-router-cnmjysbt -->
**router** · [`examples/react-router-app/src/main.tsx:13-24`](../../examples/react-router-app/src/main.tsx#L13-L24)

```tsx
const router = createBrowserRouter([
  {
    path: "/",
    element: <Root />,
    children: [
      { index: true, element: <HomePage /> },
      { path: "sign-in", element: <SignInPage /> },
      { path: "account", element: <RequireUser><AccountPage /></RequireUser> },
      { path: "magic-link", element: <MagicLinkPage /> },
    ],
  },
])
```
<!-- /ds:block hash=98b277 -->

A page only a signed-in user sees waits for the first session read, then either renders or hands the visitor to the sign-in page with `redirectTo`. The sign-in page sends the user back through `navigate(safeRedirect(redirectTo, paths.afterSignIn))`:

<!-- ds:block id=rr-requireuser-5w8pu3g3 -->
**RequireUser** · [`examples/react-router-app/src/pages.tsx:38-45`](../../examples/react-router-app/src/pages.tsx#L38-L45)

```tsx
export function RequireUser({ children }: { readonly children: ReactNode }) {
  const { user, isPending } = useSession()
  const { paths } = useAuth()
  const { pathname } = useLocation()
  if (isPending) return <p className="muted">Checking your session…</p>
  if (user === null) return <Navigate to={`${paths.signIn}?${REDIRECT_PARAM}=${encodeURIComponent(pathname)}`} replace />
  return children
}
```
<!-- /ds:block hash=b44f3e -->

That guard runs in the browser, so the page's code and data reach a signed-out visitor's browser before the redirect; that is fine for a single-page app whose data comes from authenticated API calls. A page whose HTML must not be sent to a signed-out visitor needs a server check, as the Next.js example below does.

## Next.js App Router

Next.js renders client components on the server too, so the provider lives in a client component of its own (`app/providers.tsx`, whose first line is `"use client"`), mounted from the root layout. Navigation is `useRouter().push` from `next/navigation`, and `next/link` takes `href`, so the wrapper only narrows its props. This is [examples/nextjs-app](../../examples/nextjs-app/) (Next.js 16.4.0, Turbopack):

<!-- ds:block id=nextjs-link-b84mtjxj -->
**Link** · [`examples/nextjs-app/app/providers.tsx:16-22`](../../examples/nextjs-app/app/providers.tsx#L16-L22)

```tsx
function Link({ href, className, children }: AuthLinkProps) {
  return (
    <NextLink href={href} className={className}>
      {children}
    </NextLink>
  )
}
```
<!-- /ds:block hash=a530c9 -->

<!-- ds:block id=nextjs-authproviders-cd3wy594 -->
**AuthProviders** · [`examples/nextjs-app/app/providers.tsx:25-33`](../../examples/nextjs-app/app/providers.tsx#L25-L33)

```tsx
export function AuthProviders({ children }: { children: ReactNode }) {
  const router = useRouter()
  const navigate = useCallback((href: string) => router.push(href), [router])
  return (
    <AuthProvider client={auth} navigate={navigate} Link={Link}>
      {children}
    </AuthProvider>
  )
}
```
<!-- /ds:block hash=ad0dbe -->

`app/layout.tsx` stays a server component and renders the provider inside `<body>`:

<!-- ds:block id=nextjs-rootlayout-8g4wjq9h -->
**RootLayout** · [`examples/nextjs-app/app/layout.tsx:12-23`](../../examples/nextjs-app/app/layout.tsx#L12-L23)

```tsx
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProviders>
          <Header />
          {children}
        </AuthProviders>
      </body>
    </html>
  )
}
```
<!-- /ds:block hash=fada79 -->

A page does not have to be a client component itself. The components that call the kit's hooks live in a `"use client"` module (the example's `app/auth-ui.tsx`), and a page, a server component, renders them.

`/auth` reaches the Go server through a `rewrites` entry, so the client's `baseURL` stays `/auth` and the browser sees one origin, as Step 2 of the quickstart requires; the session cookie and the `Origin` the server checks pass through the rewrite unchanged:

<!-- ds:block id=nextjs-config-6bwn2h3q -->
**config** · [`examples/nextjs-app/next.config.ts:15-26`](../../examples/nextjs-app/next.config.ts#L15-L26)

```typescript
const config: NextConfig = {
  turbopack: { root: REPO_ROOT },
  // Same-origin API: the browser talks to Next only, and Next forwards /auth
  // to the Go server, so the session cookie is first-party and Origin is the
  // app's own. /dev is the demo server's in-memory inbox, read by the e2e run.
  async rewrites() {
    return [
      { source: "/auth/:path*", destination: `${AUTH_API_URL}/auth/:path*` },
      { source: "/dev/:path*", destination: `${AUTH_API_URL}/dev/:path*` },
    ]
  },
}
```
<!-- /ds:block hash=c5075e -->

The example links `@ubgo/auth-react` and `@ubgo/auth-client` from this repository's `clients/` folder, outside its own; that is the only reason for `turbopack.root`, without which the build fails with `Can't resolve '@ubgo/auth-client'`.

For the token pages (`/verify-email`, `/reset-password`, `/magic-link`, `/confirm-email-change`, `/undo-email-change`), pass the token from the address instead of letting the component read `window.location`, so the server's HTML and the browser's first render agree. The simplest way is the server page's `searchParams`, handed to the client component as a prop (pass it to a kit component's `token` prop the same way):

<!-- ds:block id=nextjs-magiclinkpage-q62fcy87 -->
**MagicLinkPage** · [`examples/nextjs-app/app/magic-link/page.tsx:11-13`](../../examples/nextjs-app/app/magic-link/page.tsx#L11-L13)

```tsx
export default async function MagicLinkPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  return <MagicLinkFinish token={firstParam(await searchParams, "token") ?? ""} />
}
```
<!-- /ds:block hash=122dc4 -->


## No router

Leave out `navigate` and `Link`. Every navigation the components make is then a full page load, and every link a plain anchor:

```tsx
<AuthProvider client={auth}>{children}</AuthProvider>
```

That is correct for a multi-page app (each page its own HTML file, or server-rendered pages with a React island) and for a page that holds a single auth component. The session is read again on each page load; the [TanStack Query cache](react-hooks.md#the-query-keys) does not survive a reload.

## Server rendering

The package and the components are written to render on the server without touching the browser:

- The provider's default `navigate` touches `window` only when called, never while rendering.
- `useSession()` does not fetch during a server render: the query stays pending, so `<SignedIn>` and `<SignedOut>` render their `fallback` and the components render their loading state. The real session is read in the browser after hydration.
- The token pages (VerifyEmail, ResetPasswordForm, MagicLinkCallback, ConfirmEmailChange) read `?token=` only when `window` exists. On the server they see no token, so pass `token` from your framework's search params when the page is rendered on the server, or the server's HTML (the "no token" state) and the browser's first render will differ.
- `supportsPasskeys()` answers false on the server, so passkey buttons appear only after hydration.
- No component reads `window` while rendering (the address is read in handlers and effects), which `task ui:check` proves by rendering every registry component to HTML in Node with no `window` (`examples/react-demo/web/scripts/ssr.mjs`).

What it does not do: read the session on the server. A server-rendered page cannot know who is signed in through these hooks, signed in or not: the Next.js example's home page is the same HTML for everyone, holding `SignedIn`'s fallback. Check the session in your server code when a page must be protected before it is sent: the Go side, or server code that calls `GET /auth/session` with the browser's cookie (see also [Bearer mode and other runtimes](bearer-and-mobile.md)). In the Next.js example:

<!-- ds:block id=nextjs-serveruser-y4kjm4n5 -->
**serverUser** · [`examples/nextjs-app/lib/server-session.ts:14-21`](../../examples/nextjs-app/lib/server-session.ts#L14-L21)

```typescript
export async function serverUser(): Promise<ServerUser | null> {
  const cookie = (await headers()).get("cookie")
  if (cookie === null) return null
  const res = await fetch(`${AUTH_API_URL}/auth/session`, { headers: { cookie }, cache: "no-store" })
  if (!res.ok) return null
  const body: unknown = await res.json()
  return userOf(body)
}
```
<!-- /ds:block hash=6dbfe3 -->

<!-- ds:block id=nextjs-accountpage-c2tnrmtc -->
**AccountPage** · [`examples/nextjs-app/app/account/page.tsx:13-23`](../../examples/nextjs-app/app/account/page.tsx#L13-L23)

```tsx
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
```
<!-- /ds:block hash=c7d921 -->

A signed-out request for `/account` gets a `307` to `/sign-in?redirectTo=%2Faccount` and none of the page; a signed-in one gets HTML that already names the user.

## Try it

Each wiring on this page is run by an example, and each example's test drives it headless with Playwright against throwaway servers on ports of its own.

- **TanStack Router:** the demo, `task ui:e2e`: a sign-in navigates to `/` through `navigate`, the header link and the sign-out menu go through `Link` and `navigate`, and a magic link opened from the Inbox lands on the `/magic-link` route ([the transcript](react.md#try-it)).
- **No router:** [examples/react-headless](../../examples/react-headless/), `task ui:headless`, including `signOut({ everywhere: true })` loading the custom `paths.afterSignOut` as a full page ([the transcript](react-hooks.md#try-it)).
- **React Router** and **Next.js:** `task ui:router` and `task ui:nextjs`. Each step that navigates also checks that a marker set on the page after the first load is still there, which a full page load would have wiped, so every `Link` and `navigate` call is proven client-side. `task ui:nextjs` also reads the HTML Next sends, with and without the session cookie:

```text
       GET /account: 307 → /sign-in?redirectTo=%2Faccount
  ok   server HTML for an anonymous visitor: / holds SignedIn's fallback, /account is a redirect
  ok   in the browser, signed out, the home page links to paths.signIn through next/link
  ok   /account, checked on the server, sends a signed-out visitor to /sign-in?redirectTo=%2Faccount
  ok   signing in comes back to /account through router.push, and the server knows the user
  ok   server HTML with the session cookie: /account names the user, / still holds the fallback
  ok   the header's Home link keeps the session without a reload
  ok   signOut() lands on paths.afterSignOut (/sign-in) through router.push
       link: http://localhost:5201/magic-link?token=…
  ok   a mailed magic link opens /magic-link, whose server page passes the token down
nextjs-app: all 8 steps passed
```

The React Router run is in [its README](../../examples/react-router-app/README.md#run-it).

By hand, with `task demo` running: open `http://localhost:5180`, click between the auth pages in the sidebar and watch the network panel: no document request is made, because every link goes through the router.

## Pitfalls

- **Passing the router's `Link` directly.** A router link that takes `to` instead of `href` renders an anchor without a target, and TypeScript may not catch it when the router's props are loose. Always pass a wrapper that takes `href`.
- **An unstable `navigate`.** `navigate={(href) => router.navigate({ href })}` inline is a new function on every render, which changes the provider's value and re-renders every auth component. Wrap it in `useCallback` (or define it at module scope when the router is a module singleton).
- **The provider outside the router.** `useRouter()`, `useNavigate()` and Next's `useRouter()` only work inside the router. Mount `AuthProvider` in the root route's component or the root layout, not above the router provider.
- **`redirectTo` from the address.** SignInForm carries `redirectTo` to `paths.twoFactor` in the query string, and the components follow it only when it is a path on this site (or an origin in `AuthProvider`'s `allowedRedirectOrigins`), falling back to their default otherwise. Your own code that navigates to `?redirectTo=` should go through `safeRedirect` from `@ubgo/auth-react` too, because the router's `navigate` or `location.assign` follows a full URL to another site.
- **Absolute `paths`.** A `paths` entry may be an absolute URL (an auth app on a subdomain); the router's navigate may not accept one. Keep `paths` relative when `navigate` is the router's.

## Related

- [React UI kit](react.md): the quickstart.
- [React hooks](react-hooks.md): `useAuth`, `useSession` and the rest.
- [React components](react-components.md): what each component navigates to.
- [Bearer mode and other runtimes](bearer-and-mobile.md): a frontend on another site, server-side code.

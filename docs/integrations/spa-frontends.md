# SPA frontends: React, Vue or Svelte against the API

You will have a single-page app that signs in against the library's JSON routes, keeps the session in a cookie the script never sees when it is served from the same site, or as a bearer token when it is not, passes the origin check, answers CORS preflights, and needs no CSRF token of its own.

## Before you start

- [net/http](net-http.md) for the routes and the error JSON every call returns.
- The example is [`examples/spa-cross-origin`](../../examples/spa-cross-origin/main.go): the API on `localhost:8081` allowing a frontend on `localhost:5173`, a Vite dev server's default. `go run ./spa-cross-origin` in `examples/` serves it; `go test ./spa-cross-origin` runs its tests. Any framework works on the frontend; the fences below are plain `fetch`.
- No extra module.

## Step 1 — Decide: same site, or another one

Where the frontend is served decides how the session travels.

| The frontend is served from | The browser treats it as | Session travels as | You need |
|---|---|---|---|
| The API's own origin (`https://app.example.com` serves both the bundle and `/auth`) | same origin | the cookie, automatically | nothing: [Your first app](../start/first-app.md) is this case |
| Another origin on the same site (`https://app.example.com` and `https://api.example.com`, or `localhost:5173` and `localhost:8081`) | same site, different origin | the cookie, with `credentials: "include"` and CORS | this guide, steps 2 to 4 |
| Another site (`https://app.example` and `https://api.example.com`) | cross-site | a bearer token the script holds | step 5 |

`SameSite=Lax` is what decides the third row: browsers do not send a Lax cookie on a cross-site `fetch`, so a cookie cannot carry the session there.

## Step 2 — Trust the frontend's origin

The core refuses a cookie-authenticated POST whose `Origin` is not `auth.WithBaseURL`'s origin. A frontend on another origin is, to the core, another site, which is exactly what the check is for. Add it with `auth.WithTrustedOrigins`:

<!-- ds:block id=spa-newauth-j6fr3wkd -->
**newAuth** · [`examples/spa-cross-origin/main.go:116-127`](../../examples/spa-cross-origin/main.go#L116-L127)

```go
func newAuth(db *sql.DB, m email.Mailer, previews *previewOrigins) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithTrustedOrigins(spaOrigin),
		auth.WithTrustedOriginFunc(previews.Trusted),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=1f669c -->

A set of frontends that a fixed list cannot name has two more forms. A pattern such as `https://*.example.com` ([`WildcardHost`](ds:block?id=core-wildcardhost-2kq6xr3n)) or `https://preview-*.example.com` ([`WildcardAny`](ds:block?id=core-wildcardchars-6vn3qk8w)) in `auth.WithTrustedOrigins` trusts every matching origin; a pattern must end with at least [two fixed labels](ds:block?id=core-minpatternsuffixlabels-2pw7xn4k), so `https://*.com` is refused at start-up. For a set that changes while the process runs (one origin per tenant read from a table, a preview deployment per branch), [`auth.WithTrustedOriginFunc(fn)`](ds:block?id=opt-withtrustedoriginfunc-7j7xq3hq) is asked about an origin the list and the patterns did not accept. It runs on every cookie-authenticated mutation, so it must be fast (read a cache, not the database on every call) and must not fail open: an error of its own is "false".

The example keeps its preview deployments in memory: the deploy pipeline adds an origin when a preview of a branch goes up and removes it when the branch is merged, and `Trusted` is the function the core asks, passed as `auth.WithTrustedOriginFunc(previews.Trusted)` in `newAuth` above.

<!-- ds:block id=spa-previeworigins-nddesh6m -->
**previewOrigins** · [`examples/spa-cross-origin/main.go:138-141`](../../examples/spa-cross-origin/main.go#L138-L141)

```go
type previewOrigins struct {
	mu  sync.RWMutex
	set map[string]bool
}
```
<!-- /ds:block hash=1b4f39 -->

<!-- ds:block id=spa-previewtrusted-mwn47fts -->
**previewOrigins.Trusted** · [`examples/spa-cross-origin/main.go:169-173`](../../examples/spa-cross-origin/main.go#L169-L173)

```go
func (p *previewOrigins) Trusted(origin string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.set[origin]
}
```
<!-- /ds:block hash=311b8e -->

Check: `TestSPA_PreviewOriginsChangeAtRunTime` signs out from `https://preview-42.app.example` and is refused while the preview is unknown, allowed once it is added, and refused again once it is removed, all without restarting the API.

Check: a POST with the cookie and `Origin: http://localhost:5173` passes; one from `https://evil.example` is refused with `auth.origin_not_trusted` (step 4).

## Step 3 — Answer CORS for that origin only

CORS decides what a script may read; the origin check decides what the server does. Both are needed. The middleware echoes the allowed origin (never `*`, which cannot be combined with credentials and would hand the cookie to any page), allows credentials, lists the request headers bearer mode and the session cache use, and exposes the response headers a script could not otherwise read.

<!-- ds:block id=spa-corsheaders-m4ny7sbx -->
**corsAllowHeaders** · [`examples/spa-cross-origin/main.go:84-87`](../../examples/spa-cross-origin/main.go#L84-L87)

```go
var (
	corsAllowHeaders  = []string{"Content-Type", "Authorization", authhttp.TokenModeHeader, authhttp.SessionCacheHeader}
	corsExposeHeaders = []string{authhttp.SetTokenHeader, authhttp.SetTokenExpiresHeader, authhttp.SetSessionCacheHeader, "Retry-After"}
)
```
<!-- /ds:block hash=88b401 -->

<!-- ds:block id=spa-cors-r2ve6hna -->
**cors** · [`examples/spa-cross-origin/main.go:192-211`](../../examples/spa-cross-origin/main.go#L192-L211)

```go
func cors(a *auth.Auth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && a.TrustsOrigin(auth.OriginOf(origin)) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Expose-Headers", strings.Join(corsExposeHeaders, ", "))
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
				h.Set("Access-Control-Allow-Headers", strings.Join(corsAllowHeaders, ", "))
				h.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
```
<!-- /ds:block hash=e5d6d7 -->

The frontend sends every call with `credentials: "include"`, so the browser stores the cookie from the sign-in answer and sends it back:

```js
const api = "http://localhost:8081";

async function signIn(identifier, password) {
  const res = await fetch(`${api}/auth/password/sign-in`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier, password }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error.code); // "password.invalid_credentials", "auth.rate_limited", ...
  return body.user;
}

async function me() {
  const res = await fetch(`${api}/me`, { credentials: "include" });
  if (res.status === 401) return null; // auth.signed_out
  return res.json();
}
```

Check: the preflight for the frontend's origin is answered with the origin and credentials; the sign-up answer sets the cookie and is readable; `/me` reads it:

```sh
curl -si -X OPTIONS localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:5173' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
```

```text
HTTP/1.1 204 No Content
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type, Authorization, Auth-Token-Mode, Auth-Session-Cache
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Origin: http://localhost:5173
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After
Access-Control-Max-Age: 3600
Vary: Origin
```

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:5173' \
  -H 'Content-Type: application/json' -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -si -b cookies.txt localhost:8081/me -H 'Origin: http://localhost:5173'
```

```text
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://localhost:5173
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After
Set-Cookie: __Host-auth_session=Xn8j-btGU6UOvY40LhWJ0Zs1MLPBnqCut1F8_l7u7Bc; Path=/; Expires=Thu, 08 Oct 2026 05:17:46 GMT; HttpOnly; Secure; SameSite=Lax

{"user":{"id":"usr_nj5n5bhcrzipa5ptjfa35jaw","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://localhost:5173
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After

{"id":"usr_nj5n5bhcrzipa5ptjfa35jaw","hello":"Alice"}
```

Headers unrelated to CORS and auth are left out.

## Step 4 — Know that no CSRF token is needed

Every cookie-authenticated mutation is checked against `Origin` (or `Referer` when `Origin` is missing) inside the operation, before anything runs, so a page on another origin cannot make the browser perform a signed-in POST even though the browser would attach the cookie. The cookie is also `HttpOnly`, so a script on your own page cannot read it, and `SameSite=Lax`, so a cross-site navigation carries it only on a top-level GET. A CORS answer that lacks the origin stops the hostile page from reading anything, and the core stops it from doing anything:

```sh
curl -si -X OPTIONS localhost:8081/auth/sign-out -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST'
curl -si -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```text
HTTP/1.1 405 Method Not Allowed
HTTP/1.1 403 Forbidden
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

The preflight gets no `Access-Control-*` header at all (the middleware passes it to the library, which answers an `OPTIONS` like any unknown method), so the browser never sends the POST; and if something did, the core refuses it.

Check: the refused sign-out signed nobody out; `/me` from the frontend still answers 200.

## Step 5 — Another site: bearer mode

When the frontend is on another site, the cookie never travels, so the script asks for a bearer token with `Auth-Token-Mode: bearer`, reads it from `Set-Auth-Token` (exposed by the CORS middleware above), keeps it in memory or `sessionStorage`, and sends `Authorization: Bearer` on every call. [Mobile apps](mobile-apps.md) walks this mode end to end, including the session cache header; the trade is that a token the script can read is a token an injected script can read too, so a same-site deployment with cookies is the better default.

```js
const res = await fetch(`${api}/auth/password/sign-in`, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Auth-Token-Mode": "bearer" },
  body: JSON.stringify({ identifier, password }),
});
const token = res.headers.get("Set-Auth-Token"); // readable because it is exposed
```

```sh
curl -si -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:5173' -H 'Auth-Token-Mode: bearer' \
  -H 'Content-Type: application/json' -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
HTTP/1.1 200 OK
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After
Set-Auth-Token: LB3o3hZJSzAMhWYHcnBY8YCOuToTAWn9Ik4tt_QxQAg

{"user":{"id":"usr_nj5n5bhcrzipa5ptjfa35jaw","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Check: no `Set-Cookie` is sent in bearer mode, and `/me` answers to the `Authorization` header alone.

## Step 6 — Call it with the typed client

The fences above are plain `fetch` so every header is visible. The [TypeScript client](../client/README.md) sends exactly these requests with the Go input and output types and the error codes as a closed union. In its default cookie mode it sets `credentials: "include"` on every call, so Steps 2 to 4 apply unchanged; in bearer mode it sends `Auth-Token-Mode: bearer`, reads `Set-Auth-Token` itself and keeps the token in a `TokenStore`, so the exposed header of Step 3 is what it needs.

On one origin (the bundle and `/auth` on one host, or a dev server proxying `/auth`), the client takes a path. This is the [react-headless](../../examples/react-headless/) page, whose [`vite.config.ts`](../../examples/react-headless/web/vite.config.ts) proxies `/auth` to the Go server so the cookie is first-party and no CORS is needed at all:

<!-- ds:block id=headless-client-kjnvsfqa -->
**client** · [`examples/react-headless/web/src/app.tsx:32-35`](../../examples/react-headless/web/src/app.tsx#L32-L35)

```tsx
const client = createAuthClient({
  baseURL: BASE_URL,
  plugins: [email(), password(), magiclink(), oauth(), passkey(), twofactor()],
})
```
<!-- /ds:block hash=f0038f -->

On another site, the client takes the API's absolute URL and bearer mode (this file is type-checked by `task ts:check`, not run):

<!-- ds:block id=bearer-client-2xq7kw9n -->
**remote** · [`clients/ts/examples/bearer.ts:61-66`](../../clients/ts/examples/bearer.ts#L61-L66)

```typescript
export const remote = createAuthClient({
  baseURL: "https://api.example.com/auth",
  tokenMode: "bearer",
  tokenStore: localStorageTokenStore(),
  plugins: [password()],
});
```
<!-- /ds:block hash=9849c8 -->

Try it: `task ui:headless` builds the Go server and the page, serves them on one origin, and drives the page headless; each line is a step that passed:

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

Pitfalls with the client:

- A Vite proxy with `changeOrigin: true` rewrites the `Host` the Go server sees, and the origin check then compares the page's `Origin` with another host. Leave it off, as the example does.
- A linked React kit brings its own `node_modules`: without `resolve.dedupe` for `react`, `react-dom` and `@tanstack/react-query`, the hooks see two contexts ([React UI kit › Pitfalls](../client/react.md#pitfalls)).
- A plugin in the client's `plugins` that the server does not wire compiles, and answers `auth.unknown_operation` (404) when called ([Plugins › Pitfalls](../client/plugins.md#pitfalls)).
- Which mode, origin and React layer to pick is the subject of [Choose a client setup](../choosing/client.md).

## Options you may want

| Need | Do |
|---|---|
| Several frontends (a web app and an admin app) | List every origin in `auth.WithTrustedOrigins`; the middleware above allows exactly those, through `a.TrustsOrigin`. |
| A browser extension | Its origin is `chrome-extension://<id>`: `auth.WithTrustedOrigins("chrome-extension://<id>")`. Trusting every extension (a `chrome-extension://` prefix in `auth.WithTrustedOriginFunc`) is possible and not advised: any extension the user installs then passes the origin check with their cookie. |
| Configure origins per environment | `auth.EnvOptions` reads `AUTH_TRUSTED_ORIGINS` as a comma-separated list; see [Configuration](../concepts/configuration.md). |
| The whole site on one origin in production | Serve the bundle from the API's origin and drop CORS; the dev server alone needs it, or use Vite's proxy so the browser only ever sees one origin. |
| Show "signed in as" without a round trip | Keep the user from the sign-in answer in state; `/me` is the source of truth on reload. |
| Rate-limit feedback | A `429` carries `Retry-After` in seconds (exposed above) and the code `auth.rate_limited`. |
| Typed error codes | Copy [`docs/reference/error-codes.ts`](../reference/error-codes.ts) into the frontend: `AUTH_ERROR_CODES` is every code with its status and message, `AuthErrorCode` the union, `isAuthErrorCode` the guard, so a `switch` on `error.code` is checked by the compiler and a translation table cannot miss one. Regenerated by `task docs:api`; [`error-codes.json`](../reference/error-codes.json) is the same list for other tooling. |
| Request and response types | [`docs/reference/openapi.json`](../reference/openapi.json) describes every route with its input and output schema; any OpenAPI client generator produces the TypeScript types, and `authhttp.OpenAPI` serves the document for the routes an app actually wires. |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| The browser console says the CORS request is blocked; the server never logs the call | The preflight failed: the origin is not trusted, or a header is not in `Access-Control-Allow-Headers`. | Add the origin to `auth.WithTrustedOrigins`; add the header to `corsAllowHeaders`. |
| `200` on sign-in but `/me` answers `auth.signed_out` | The sign-in `fetch` lacked `credentials: "include"`, so the cookie was discarded; or the frontend is on another site, where the cookie does not travel. | Add `credentials: "include"`, or switch to bearer mode. |
| `auth.origin_not_trusted` on every POST from the frontend | CORS is fine but the core does not trust the origin. | `auth.WithTrustedOrigins("http://localhost:5173")`, matching the scheme and port exactly. |
| It works in Chrome on `localhost` but not on the deployed frontend over `http://` | The cookie is `Secure`; only `localhost` is exempt. | Serve both origins over HTTPS. |
| `res.headers.get("Set-Auth-Token")` is `null` in the browser but curl shows the header | The header is not exposed to scripts. | Keep `Set-Auth-Token` in `Access-Control-Expose-Headers`. |
| The cookie is set with `SameSite=Lax` but never sent to the API | The two origins are different sites, not just different origins. | Bearer mode, or put both under one registrable domain. |
| A preview deployment is refused with `auth.origin_not_trusted` although a pattern lists it | A first label `*` spans one label or more, but any other wildcard label matches within one label only: `https://preview-*.example.com` does not match `preview-42.eu.example.com`. | Add a pattern for the deeper level, or decide in `WithTrustedOriginFunc`. |
| `auth.New` fails on a trusted origin such as `https://*.com` | A pattern must name a domain the app owns: two fixed labels after the last wildcard. | Name your own domain. |

## Next

- [Mobile apps](mobile-apps.md) for bearer mode in full.
- [Security](../concepts/security.md) for the origin check, the cookies and what the app must still do.
- [TypeScript client](../client/README.md) for the same calls typed, instead of hand-written `fetch`, and the [React UI kit](../client/react.md) for ready-made components on top of it.
- [The HTTP API](../reference/http-api.md) for every route the frontend can call.

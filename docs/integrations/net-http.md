# net/http, chi and gorilla

You will have the library's routes served by the standard mux, chi or gorilla/mux, your own handlers behind its session middleware, routes guarded by a signed-in user or by an API key scope, and the cookies and headers every client of yours will see.

## Before you start

- [Your first app](../start/first-app.md) built the handler this guide takes apart. The plugins and `auth.New` do not change here.
- The examples are [`examples/quickstart`](../../examples/quickstart/main.go) (the standard mux) and [`examples/chi`](../../examples/chi/main.go). `go run ./chi` in `examples/` serves it on `http://localhost:8081`; `go test ./chi` runs its tests.
- `authhttp` is part of the core module and uses only the standard library, so there is nothing to install beyond `github.com/ubgo/auth`. Any router that takes an `http.Handler` and `func(http.Handler) http.Handler` middleware uses it as it is; gin, echo and fiber have adapters of their own ([gin](gin.md), [echo](echo.md), [fiber](fiber.md)).

## Step 1 — Mount the handler

`authhttp.Handler` serves every registered operation at the prefix plus the operation's route: a Query as GET with its input in the query string, a Mutation as POST with a JSON body. It owns its own route table, so an unknown path answers 404 `auth.unknown_operation` and a known path with the wrong method 405 `auth.method_not_allowed` with an `Allow` header, as JSON like every other error. `Prefix` must match the pattern you register. With `Health()` the table also holds `GET <prefix>/ok`, a database-free liveness answer.

<!-- ds:block id=authhttp-handler-3xrumz2e lines=1-10 -->
**Handler** · [`authhttp/authhttp.go:789-839`](../../authhttp/authhttp.go#L789-L839)

```go
func Handler(a *auth.Auth, opts ...Option) http.Handler {
	cfg := newConfig(opts)
	cfg.warnWeakened()
	routes := map[string]map[string]http.Handler{}
	for _, op := range a.Operations() {
		path := cfg.prefix + op.Route()
		if routes[path] == nil {
			routes[path] = map[string]http.Handler{}
		}
		routes[path][MethodOf(op.Info().Kind)] = serveOp(a, op, cfg)
```
<!-- /ds:block hash=8dfb61 -->

On the standard mux, the quick start registers it under `/auth/` and puts `/me` behind `Middleware` and `RequireUser`:

<!-- ds:block id=newhandler-zmz4j9w2 -->
**newHandler** · [`examples/quickstart/main.go:114-119`](../../examples/quickstart/main.go#L114-L119)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=9e6587 -->

On chi, `Mount` hands the handler the whole `/auth` subtree, and a `Group` carries the two middlewares:

<!-- ds:block id=chi-newhandler-f2hm8ktq -->
**newHandler** · [`examples/chi/main.go:113-122`](../../examples/chi/main.go#L113-L122)

```go
func newHandler(a *auth.Auth) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Mount(authPrefix, authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	r.Group(func(r chi.Router) {
		r.Use(authhttp.Middleware(a), authhttp.RequireUser)
		r.Get("/me", me)
	})
	return r
}
```
<!-- /ds:block hash=d77fff -->

gorilla/mux is the same shape: `r.PathPrefix("/auth/").Handler(authhttp.Handler(a, authhttp.Prefix("/auth")))` for the routes, and `r.Use(authhttp.Middleware(a))` on a subrouter for your own.

Check: under the mount the answers stay the library's; outside it the router's own:

```sh
curl -si localhost:8081/auth/nope
curl -si localhost:8081/auth/password/sign-in
curl -si localhost:8081/nope
```

```text
HTTP/1.1 404 Not Found
{"error":{"code":"auth.unknown_operation","message":"Not found."}}
HTTP/1.1 405 Method Not Allowed
Allow: POST
{"error":{"code":"auth.method_not_allowed","message":"This method is not allowed here."}}
HTTP/1.1 404 Not Found
```

## Step 2 — Resolve the session once with Middleware

`Middleware` attaches the request to the core and resolves the session once, lazily and at most once per request, for your own handlers and for a GraphQL handler. A lookup that fails for a reason other than "signed out" (a database that is down) answers 500 rather than running the handler as if nobody were signed in; a coded refusal from a token plugin (a disabled, expired or rate-limited API key) answers its own code and status instead. Effects recorded by operations called inside the handler, such as the cookie of a sign-in you ran from your own form, become headers before the handler's first byte.

<!-- ds:block id=authhttp-middleware-j6kn46zp lines=1-12 -->
**Middleware** · [`authhttp/authhttp.go:1692-1717`](../../authhttp/authhttp.go#L1692-L1717)

```go
func Middleware(a *auth.Auth, opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig(opts)
	cfg.warnWeakened()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, err := begin(a, r, cfg)
			if err != nil {
				// A coded refusal (a disabled or rate-limited API key) is
				// answered as itself; anything else is a 500 with no detail
				// (WriteError's rule), logged because the log is its only
				// record.
				if auth.ErrorOf(err).Code == auth.ErrInternal.Code {
```
<!-- /ds:block hash=4e9b1e -->

`RequireUser` answers 401 `auth.signed_out` without a session; behind it, `authhttp.MustUser(r)` returns the user and `authhttp.CurrentUser(r)` is the two-value form for a handler that serves visitors too. Neither queries the database.

<!-- ds:block id=me-6d2msbjr -->
**me** · [`examples/quickstart/main.go:132-136`](../../examples/quickstart/main.go#L132-L136)

```go
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Hello: u.Name}) // a client that hung up cannot be told
}
```
<!-- /ds:block hash=99bd31 -->

Check: sign up, read `/me`, sign out, and `/me` refuses the old cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_jhsqe2w4y2espwz5qtvwufad","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_jhsqe2w4y2espwz5qtvwufad","hello":"Alice"}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## Step 3 — Protect a whole tree, deny by default

`RequireUser` is opt-in per route, which fits an API with a few protected routes. An app where almost every page needs a user turns it around with `RequireUserExcept`: every path needs a signed-in user except the ones listed, so a page added next month is protected until someone opens it by name. An entry ending in `/` opens a subtree (`"/auth/"` for the library's own routes), any other entry exactly that path.

<!-- ds:block id=authhttp-requireuserexcept-7fjw2qsd -->
**RequireUserExcept** · [`authhttp/authhttp.go:1853-1862`](../../authhttp/authhttp.go#L1853-L1862)

```go
func RequireUserExcept(next http.Handler, allow ...string) http.Handler {
	guarded := RequireUser(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pathAllowed(r.URL.Path, allow) {
			next.ServeHTTP(w, r)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}
```
<!-- /ds:block hash=ab430c -->

For a redirect to the sign-in page before a page renders, where a database call per request is not wanted, `HasCredential(r)` reports whether the request carries a session cookie or a bearer token at all. Presence is not validity: a forged or expired cookie passes, so the check only decides where to send the visitor, never what they may do.

<!-- ds:block id=authhttp-hascredential-m8rt4kzb -->
**HasCredential** · [`authhttp/authhttp.go:1214-1216`](../../authhttp/authhttp.go#L1214-L1216)

```go
func HasCredential(r *http.Request, opts ...Option) bool {
	return requestOf(r, newConfig(opts)).Credential != auth.CredentialNone
}
```
<!-- /ds:block hash=5cb39e -->

Check: `TestHTTP_HealthAndDenyByDefault` (integration) serves `/login` to a visitor, refuses `/dashboard` with `auth.signed_out`, and serves it once signed in.

## Step 4 — Guard routes by scope or by your own rule

`RequireScope(scope)` is for routes that programs call with an API key (the [apikey plugin](../plugins/apikey.md)). It answers 401 `auth.signed_out` when there is no principal at all (no credential, or a key that is revoked, expired or unknown), so a script knows to get a new key, and 403 `auth.missing_scope` when a principal lacks the scope, a browser session included, because a scope-guarded route is a route for keys. No `RequireUser` is needed in front of it.

<!-- ds:block id=requirescope-4aee4fww -->
**RequireScope** · [`authhttp/authhttp.go:1929-1939`](../../authhttp/authhttp.go#L1929-L1939)

```go
func RequireScope(scope string) func(http.Handler) http.Handler {
	return RequireFunc(func(r *http.Request) error {
		if _, ok := auth.CurrentUser(r.Context()); !ok {
			return auth.ErrSignedOut
		}
		if !auth.HasScope(r.Context(), scope) {
			return ErrMissingScope
		}
		return nil
	})
}
```
<!-- /ds:block hash=8904ce -->

`RequireFunc(check)` turns any rule of yours (a role, who owns the resource) into middleware that answers the rule's error as the library's JSON: an `*auth.Error` keeps its code and status, anything else is a 500 with no detail. For a route both people and keys use, guard it with `RequireUser` and decide per request with `auth.HasScope(ctx, scope)`.

Check: [`examples/api-keys-and-jwt`](../../examples/api-keys-and-jwt/README.md) shows a key with the scope passing, one without it refused with `auth.missing_scope`, and a revoked key answered `auth.signed_out`.

Errors are answered in the request's locale when the app configured a message catalogue with `auth.WithMessages`: `Handler`, `RequireUser` and `RequireFunc` render through `WriteErrorFor`, which reads the locale the request arrived with (`Accept-Language`, or the `LocaleCookie`). The code and the status never change, so a client matching codes sees no difference; [Errors](../concepts/errors.md) explains the catalogue. The request's `Sec-Fetch-Site` header reaches the core as `Client.FetchSite`, which `auth.WithFetchMetadata` turns into a refusal of cross-site mutations even before any cookie exists.

## Step 5 — Know the cookies

Every cookie is `HttpOnly`, `Secure`, `SameSite=Lax` and `Path=/`.

| Cookie | Holds |
|---|---|
| [`__Host-auth_session`](ds:block?id=cookiename-xgdjargz) | The session token. The `__Host-` prefix makes the browser refuse it unless it is Secure, has `Path=/` and no `Domain`, so no subdomain can set or read it. A session made without "remember me" has no `Expires`, so it ends with the browser; the server still ends it at its expiry. |
| [`__Host-auth_flow`](ds:block?id=flowcookiename-rnhn6vw5) | The binding of a multi-step flow, such as an OAuth sign-in, to this browser. |
| `__Host-auth_session_cache` | The client's sealed copy of its session when a snapshot `auth.SessionCache` is configured; see [Sessions](../concepts/sessions.md). Cleared with the session. |

`Secure` means the cookies travel only over HTTPS. On `http://localhost` browsers make an exception, which is why the examples work in development; a deployment is always HTTPS.

### CookieDomain

`CookieDomain("example.com")` shares the session with every subdomain, for `app.example.com` and `admin.example.com` on one sign-in. The cookies are then named [`__Secure-auth_session`](ds:block?id=domaincookiename-y5xjae8s) and [`__Secure-auth_flow`](ds:block?id=domainflowcookiename-pgbydmxs) (and `__Secure-auth_session_cache`), because `__Host-` forbids a `Domain` attribute. Every subdomain can then read and set the session, including one that serves user content or runs someone else's code, so use it only when every subdomain is yours. Pass the same option to `Handler`, `Middleware` and every adapter, or they disagree about which cookie is the session; in host-only mode a `__Secure-` cookie is ignored, and under `CookieDomain` a `__Host-` one is, so a sibling subdomain cannot plant a session.

<!-- ds:block id=authhttp-cookiedomain-emmfkgm8 -->
**CookieDomain** · [`authhttp/authhttp.go:304`](../../authhttp/authhttp.go#L304-L304)

```go
func CookieDomain(domain string) Option { return func(c *config) { c.cookieDomain = domain } }
```
<!-- /ds:block hash=4cfcaf -->

## Step 6 — Know the bearer headers

A client that cannot keep cookies sends [`Auth-Token-Mode`](ds:block?id=tokenmodeheader-s6xp5wjc)`: `[`bearer`](ds:block?id=tokenmodebearer-3p2r26xe) on sign-in and receives the token in [`Set-Auth-Token`](ds:block?id=settokenheader-j7vbxqvy) with its expiry in [`Set-Auth-Token-Expires`](ds:block?id=settokenexpiresheader-rxwtm4ay), never as a cookie and never in the JSON body; it then sends `Authorization: Bearer <token>` on every request. An empty `Set-Auth-Token`, on any status, tells the client to forget its token: the call ended the session, or the token sent names no session any more ([`ForgetRejectedToken`](ds:block?id=authhttp-forgetrejectedtoken-p4n7wq2c)); a pending second-factor token never gets it. [Mobile apps](mobile-apps.md) walks it end to end. When a request carries both a cookie and a bearer header, the cookie wins.

## Step 7 — Know the error JSON

Every error, from every route and helper, has one shape and the error's HTTP status:

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

`code` is stable, for programs to branch on; `message` is safe to show. A rate-limited answer adds `Retry-After` in seconds. An error that is not an `*auth.Error` (a database failure, a bug) is `auth.internal`, 500, with the generic message; the detail is logged through `authhttp.Logger`, `slog.Default()` unless set. [Errors](../concepts/errors.md) lists every code.

An API with its own error contract (RFC 9457 `application/problem+json`, a house envelope) passes [`authhttp.EncodeErrors(enc)`](ds:block?id=authhttp-encodeerrors-2hv7kc4p) to `Handler`, `Middleware` and every adapter. The [`ErrorEncoder`](ds:block?id=authhttp-errorencoder-5qd8wn3r) receives the request and the `auth.ErrorInfo` (code, message, status) and writes the body and its `Content-Type`; the status stays the library's whatever it writes, and so does `Retry-After`.

[`examples/behind-proxy`](../../examples/behind-proxy/README.md) answers RFC 9457 problem documents. The encoder only shapes the body: by the time it runs, a database failure is already the generic 500 and the message is already translated.

<!-- ds:block id=behindproxy-writeproblem-9xk4mq2w -->
**writeProblem** · [`examples/behind-proxy/main.go:208-217`](../../examples/behind-proxy/main.go#L208-L217)

```go
func writeProblem(w http.ResponseWriter, _ *http.Request, info auth.ErrorInfo) {
	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(info.Status)
	_ = json.NewEncoder(w).Encode(problem{ // a client that hung up cannot be told
		Type:   problemTypeBase + info.Code,
		Title:  info.Message,
		Status: info.Status,
		Code:   info.Code,
	})
}
```
<!-- /ds:block hash=654955 -->

Check: with the `auth_locale` cookie set to `fr`, a signed-out `/me` answers the problem document in French under the library's 401:

```sh
curl -si localhost:8081/me -H 'Cookie: auth_locale=fr'
```

```text
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json

{"type":"https://example.com/problems/auth.signed_out","title":"Connectez-vous pour continuer.","status":401,"code":"auth.signed_out"}
```

`TestBehindProxy_ProblemJSONInTheChosenLanguage` pins it.

## Step 8 — Run behind a reverse proxy

The client IP is what per-IP rate limits count and what the session list shows. By default it is the connection's remote address, and `X-Forwarded-For` is not trusted, because any client could otherwise choose its IP and escape per-IP rate limits. Behind a load balancer every request then seems to come from the balancer, so one busy office can exhaust the sign-in limit for everyone.

Name the proxy's network with [`TrustedProxies`](ds:block?id=authhttp-trustedproxies-6tkc9vqm). A request from that network takes the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy, then `X-Real-IP`; a request from anywhere else keeps its own address. A proxy that writes another header (Cloudflare's `CF-Connecting-IP`, Fly's `Fly-Client-IP`) is named with [`ClientIPHeaders`](ds:block?id=authhttp-clientipheaders-2gnm5wxt), which replaces the default list. A proxy that writes the standard `Forwarded` header (RFC 7239) is read with `ClientIPHeaders(authhttp.HeaderForwarded)`, by its `for=` values, and only from a trusted network, like every other forwarded header. A value that is not a CIDR or an address panics at start-up, so a typo cannot quietly trust nothing.

A platform whose rules these cannot express (the address in a context value, a header the edge signs) passes [`ClientIPFunc`](ds:block?id=authhttp-clientipfunc-8vq3mx2k). Its answer is the client IP, and an answer that is not an IP (`""` included) falls back to the rules above, so the function can decline a request it does not vouch for. The example uses all three, one option per concern, in one list it passes to both `Handler` and `Middleware`:

<!-- ds:block id=behindproxy-transportoptions-7nw3qk5r -->
**transportOptions** · [`examples/behind-proxy/main.go:138-156`](../../examples/behind-proxy/main.go#L138-L156)

```go
func transportOptions(secret string) []authhttp.Option {
	return []authhttp.Option{
		authhttp.Prefix(authPrefix),
		// The client address: a signed edge header first, else the load
		// balancer's forwarded headers, else the connection's address.
		authhttp.ClientIPFunc(edgeClientIP(secret)),
		authhttp.TrustedProxies(proxyNetwork),
		authhttp.ClientIPHeaders(authhttp.HeaderForwarded, forwardedForHeader),
		// Errors in the API's own contract.
		authhttp.EncodeErrors(writeProblem),
		// For the platform: GET /auth/ok and GET /auth/openapi.json.
		authhttp.Health(),
		authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: apiTitle, Version: apiVersion, Servers: []string{baseURL}}),
		// For plain HTML forms and the language picker.
		authhttp.AcceptForms(),
		authhttp.SkipTrailingSlash(),
		authhttp.LocaleCookie(""),
	}
}
```
<!-- /ds:block hash=e92964 -->

`edgeClientIP` believes the edge's header only when its HMAC checks out, compared in constant time:

<!-- ds:block id=behindproxy-edgeclientip-6hp2nt8v -->
**edgeClientIP** · [`examples/behind-proxy/main.go:173-185`](../../examples/behind-proxy/main.go#L173-L185)

```go
func edgeClientIP(secret string) func(r *http.Request) string {
	return func(r *http.Request) string {
		ip, sig := r.Header.Get(edgeIPHeader), r.Header.Get(edgeSignatureHeader)
		if secret == "" || ip == "" || net.ParseIP(ip) == nil {
			return ""
		}
		got, err := hex.DecodeString(sig)
		if err != nil || !hmac.Equal(got, signIP(secret, ip)) {
			return ""
		}
		return ip
	}
}
```
<!-- /ds:block hash=8bb141 -->

Try it: a request from this machine is not from `10.0.0.0/8`, so the `X-Forwarded-For` it carries is ignored and the session records the connection's address. With `EDGE_SECRET=s3cret`, a correctly signed edge header is believed:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -H 'X-Forwarded-For: 192.0.2.66' \
  --data-urlencode identifier=alice@example.com --data-urlencode 'password=correct horse battery staple'
curl -s -b cookies.txt localhost:8081/auth/sessions
SIG=$(printf %s 203.0.113.7 | openssl dgst -sha256 -hmac s3cret -hex | awk '{print $NF}')
curl -s -c edge.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -H 'X-Edge-Client-IP: 203.0.113.7' -H "X-Edge-Signature: $SIG" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b edge.txt localhost:8081/auth/sessions
```

```json
{"sessions":[{"id":"ses_yljmbeorqwane4zgkty4qhz2","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:06:15.339288Z","lastSeenAt":"2026-10-09T03:06:15.339288Z"}]}
{"sessions":[{"id":"ses_pnslin3774amt4b3uiay67s4","current":true,"impersonated":false,"ip":"203.0.113.7","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:06:15.473054Z","lastSeenAt":"2026-10-09T03:06:15.473054Z"},{"id":"ses_yljmbeorqwane4zgkty4qhz2","current":false,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:06:15.339288Z","lastSeenAt":"2026-10-09T03:06:15.339288Z"}]}
```

Check: `TestBehindProxy_ForwardedFromTheProxy` sends `Forwarded: for=203.0.113.7` from `10.0.0.5` and finds that address on the session; `TestBehindProxy_StrangerCannotChooseItsAddress` sends the same headers from outside the network and finds the connection's; `TestBehindProxy_SignedEdgeHeader` covers a signed and a forged edge header.

## Step 9 — Add health, OpenAPI, forms and a language choice

Five more switches, all off by default so an existing app sees no change:

- [`Health()`](ds:block?id=authhttp-health-x3vd7npa) adds `GET <prefix>/ok`, answering `{"ok":true}` without reading the database, for a liveness probe or a smoke test after a deploy.
- [`OpenAPI(info)`](ds:block?id=authhttp-openapi-8wq2nr5t) adds `GET <prefix>/openapi.json`, the OpenAPI 3.1 document of every route this handler serves, with schemas derived from the operations' Go types. [`OpenAPIInfo`](ds:block?id=authhttp-openapiinfo-3kx9pz4w) names the app, the version and the servers.
- [`AcceptForms()`](ds:block?id=authhttp-acceptforms-j7xq3bre) lets a Mutation take a form-encoded body as well as JSON, one value per field, so a plain HTML form works without JavaScript (lists and objects stay JSON-only).
- [`SkipTrailingSlash()`](ds:block?id=authhttp-skiptrailingslash-p5wd8kzh) routes `/auth/sign-out/` as `/auth/sign-out`.
- [`LocaleCookie(name)`](ds:block?id=authhttp-localecookie-8rfv2mqa) reads the user's chosen language from a cookie ([`auth_locale`](ds:block?id=authhttp-defaultlocalecookiename-4hpr8wnz) by default) before `Accept-Language`, so a choice made in the app wins over the browser's list; the app sets the cookie. [`LocaleFunc(fn)`](ds:block?id=authhttp-localefunc-7mq4xk2p) runs before both: the app answers the locale from whatever it knows (its own header or cookie, the tenant's default), and an empty answer falls through. The function sees only the request, because the locale must be settled before the session is looked up: the lookup's own error is rendered in it, so a preference stored on the user row cannot be the source.

The locale changes only messages, and only with a catalogue: the example passes `auth.WithMessages(i18n.Messages())`, every shipped translation.

<!-- ds:block id=behindproxy-newauth-4kq8wz2m -->
**newAuth** · [`examples/behind-proxy/main.go:121-131`](../../examples/behind-proxy/main.go#L121-L131)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithMessages(i18n.Messages()),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=795d71 -->

Try it:

```sh
curl -s localhost:8081/auth/ok
curl -s localhost:8081/auth/openapi.json | jq -r '.openapi, .info.title, (.paths | length)'
curl -s -X POST localhost:8081/auth/sign-out/ -b edge.txt -H 'Origin: http://localhost:8081'
```

```text
{"ok":true}
3.1.0
Example auth API
22
{"ok":true}
```

The form-encoded sign-up in Step 8 works because of `AcceptForms`; without it the same request answers `auth.bad_request`. Check: `TestBehindProxy_PlatformRoutes` reads the health route and the OpenAPI paths and signs out through a trailing slash.

## Options you may want

| Option | What it does |
|---|---|
| `Prefix(p)` | The path the handler is mounted at. |
| `Logger(l)` | Where internal errors are logged; their text never reaches a client. |
| `CookieDomain(d)` | Step 5. |
| `CookiePrefix(p)`, [`RenameCookie(role, name)`](ds:block?id=authhttp-renamecookie-3vn8qx5k) | Every cookie's `auth` part, or one cookie's name (`RenameCookie(authhttp.CookieSession, "sid")` is `__Host-sid`); the browser prefix and the attributes stay. Pass the same options to every handler and middleware. |
| [`WeakenCookies(attrs)`](ds:block?id=authhttp-weakencookies-8kw3nq2v), `WeakenCookie(role, attrs)` | Escape hatch: turn `HttpOnly`, `Secure` (and the browser prefix), `SameSite` or `Path=/` off for every cookie or one; logged as a warning at start. For plain-HTTP development on a non-localhost host, or a cross-site embed; never the default. |
| `TrustedProxies(nets...)`, `ClientIPHeaders(names...)`, [`ClientIPFunc(fn)`](ds:block?id=authhttp-clientipfunc-8vq3mx2k) | Believe the proxy's forwarded client address, or decide it yourself; Step 8. |
| `EncodeErrors(enc)` | Your own error body; Step 7. |
| `AcceptForms()`, `SkipTrailingSlash()`, `LocaleCookie(name)`, `LocaleFunc(fn)` | Form bodies, lenient paths, a locale cookie, the app's own locale rule; Step 9. |
| `OpenAPI(info)`, [`Reference(opts)`](ds:block?id=authhttp-reference-2kx7mv9q) | `OpenAPI` adds `GET <prefix>/openapi.json`, the OpenAPI 3.1 document of the routes this handler serves; `Reference` adds `GET <prefix>` + [`ReferencePath`](ds:block?id=authhttp-referencepath-3nk8wq5m) (`/reference`), a page that renders that document with Scalar, loaded from a pinned CDN URL ([`DefaultReferenceScript`](ds:block?id=authhttp-defaultreferencescript-9vt2px6r)) or from [`ReferenceOptions`](ds:block?id=authhttp-referenceoptions-5wq8mn2k)`.ScriptURL` when the app serves the viewer itself, with `Nonce` for a CSP that allows scripts by nonce and `Theme` for one of the viewer's themes. Both opt-in; `Reference` needs `OpenAPI` and `Handler` panics at start-up without it. A development convenience: mount it behind your own guard, or not in production. |
| [`Health()`](ds:block?id=authhttp-health-x3vd7npa) | Adds `GET <prefix>` + [`HealthPath`](ds:block?id=authhttp-healthpath-9kq2mwer) (`/ok`) answering `{"ok":true}` for a liveness probe or a post-deploy smoke test. Opt-in, so an existing route table is unchanged; it reads no database, so green means mounted and running, not ready. |
| `authhttp.WriteError(w, err)` | Answer an error from your own handler in the library's JSON, with `Retry-After` for a rate limit. `authhttp.WriteErrorFor(w, r, err)` does the same in the request's locale and in the `EncodeErrors` shape the `Middleware` in front was given. |
| `authhttp.OperationHandler(a, op)` | One operation as an `http.Handler`, for a router that registers each route itself. |
| [`authhttp.HTTPRequest(ctx)`](ds:block?id=authhttp-httprequest-8kq3nw5x) | The raw `*http.Request` inside an operation, a hook or a handler behind `Middleware`; false for a direct Go call. |

A request body is capped at [1 MiB](ds:block?id=maxbodybytes-u79t9fxq) (`maxBodyBytes`).

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `auth.origin_not_trusted` (403) on a POST with the cookie | The `Origin` (or, without one, the `Referer`) is not `auth.WithBaseURL`'s origin or one of `auth.WithTrustedOrigins`. Browsers always send `Origin` on a cross-site POST; curl sends none unless told. | Add `-H 'Origin: http://localhost:8081'` in curl; for a frontend on another origin see [SPA frontends](spa-frontends.md). |
| `auth.signed_out` (401) right after signing in over plain HTTP from a browser | The cookie is `Secure`; the browser kept it only because the host is `localhost`. On any other plain-HTTP host it is dropped. | Serve HTTPS. |
| `auth.internal` (500) from a route behind `Middleware` | The session lookup failed. | Read the log. |
| `panic: authhttp: MustUser called on a request without a user; wrap the handler in RequireUser` | `MustUser` on a route without `RequireUser`. | Add `RequireUser`, or use `CurrentUser`. |
| `auth.bad_request` (400) on a POST | The JSON body has a field the operation does not know, or does not decode. | Check the route's input in the plugin's README or [the HTTP API](../reference/http-api.md). |
| A cookie set from your handler never arrives | You wrote the body before calling the operation. | Call the operation first. |
| Every session shows the load balancer's address, and one office hits the sign-in rate limit for everyone | The proxy is not named, so its forwarded headers are ignored. | `TrustedProxies` with the proxy's network (Step 8); `ClientIPHeaders` when it writes another header. |
| `panic: authhttp: TrustedProxies: "10.0.0.0/33" is not a CIDR or an IP address` at start-up | A value in `TrustedProxies` does not parse. The process refuses to start rather than trust the wrong network. | Fix the value. |
| The right IP in your handlers but the proxy's in sessions, or errors in two shapes | The options were passed to `Middleware` but not to `Handler`, or the other way round; each reads the request itself. | Build the options once, as `transportOptions` does, and pass the same list to `Handler`, `Middleware` and every adapter. |
| `auth.bad_request` (400) on a form post | A form-encoded body without `AcceptForms`. | Add `AcceptForms()`, or send JSON. |
| Messages stay in English although `auth_locale` is set | No catalogue, or `LocaleCookie` was not passed. The locale picks among translations; it does not supply them. | `auth.WithMessages(i18n.Messages())` and `LocaleCookie("")`. |
| `panic: authhttp: Reference needs OpenAPI: …` at start-up | `Reference` renders the document `OpenAPI` serves. | Pass `OpenAPI(info)` too. |

## Next

- [Mobile apps](mobile-apps.md) and [SPA frontends](spa-frontends.md): the two kinds of client, with cookies against bearer tokens.
- [`examples/behind-proxy`](../../examples/behind-proxy/README.md): Steps 7 to 9 in one runnable app.
- [Security](../concepts/security.md): the origin check, cookies and what the app must still do.
- The package's [README](../../authhttp/README.md) is the reference for every helper, constant and test.

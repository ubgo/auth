# github.com/ubgo/auth/authhttp

Serves every auth operation as a JSON route on net/http. It also gives your own handlers the signed-in user, sets the session cookie or bearer token, and turns errors into JSON.

## Install

```sh
go get github.com/ubgo/auth
```

It is part of the core module and uses only the standard library, so it adds no dependency. Any router that accepts an `http.Handler` (the standard mux, chi, gorilla/mux) mounts it directly. gin, echo and fiber have their own adapters in `contrib/`, and those adapters are built on this package.

## Wire it

From [examples/quickstart](../examples/quickstart/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)

mux := http.NewServeMux()
mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth")))
mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))

func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	_ = json.NewEncoder(w).Encode(u.ID)
}
```

`auth.WithBaseURL` matters here: its origin is the only one, apart from `auth.WithTrustedOrigins`, allowed to send cookie-authenticated POSTs.

## Options

These apply to `Handler`, `Middleware` and every building block below. Pass the same ones everywhere, or two parts of the app will disagree about which cookie holds the session.

| Option | What it does | Default |
|---|---|---|
| `Prefix(p)` | Path the handler is mounted at, such as `"/auth"`; a trailing slash is dropped. It must match the pattern the handler is registered under. | `""` (routes at the root) |
| `Logger(l)` | Where internal errors are logged. Their text never reaches the client. | `slog.Default()` |
| `CookieDomain(domain)` | Shares the session with every subdomain of `domain`, and renames the cookies to [`DomainCookieName`](ds:block?id=domaincookiename-y5xjae8s) and [`DomainFlowCookieName`](ds:block?id=domainflowcookiename-pgbydmxs). Every subdomain can then read and set the session, so use it only when every subdomain is yours and trusted. | host-only cookies |
| `CookieDomainFromBaseURL()` | `CookieDomain` with the domain taken per response from the host of `a.BaseURL(ctx)` for that request, so a dynamic base URL sets the cookie domain: a request to `pr-42.preview.example.com` under `auth.WithAllowedHosts("*.preview.example.com")` sets its cookies for that host and its subdomains. The host is one `WithAllowedHosts` accepted, or the static base URL's, so a forged `Host` header cannot choose the scope. Cookies are named like `CookieDomain`'s (`__Secure-`); an explicit `CookieDomain` wins. | host-only cookies |
| [`CookiePrefix(prefix)`](ds:block?id=authhttp-cookieprefix-7nk3wq9r) | Replaces the `auth` in every cookie name: `CookiePrefix("myapp")` names them `__Host-myapp_session`, `__Host-myapp_flow`, `__Host-myapp_session_cache`, `__Host-myapp_device` and `__Host-myapp_account_…` (`__Secure-` under `CookieDomain`), for two apps on one host or a cookie policy that names its cookies. The `__Host-`/`__Secure-` prefix cannot be removed. The prefix must be a cookie-name token (no spaces, separators or control characters) or the option panics, because net/http would otherwise drop every `Set-Cookie` silently. | [`DefaultCookiePrefix`](ds:block?id=authhttp-defaultcookieprefix-2vq8xk5m), `auth` |
| [`RenameCookie(role, name)`](ds:block?id=authhttp-renamecookie-3vn8qx5k) | Names one cookie: `RenameCookie(CookieSession, "sid")` sets the session cookie as `__Host-sid`; roles are [`CookieSession`, `CookieFlow`, `CookieCache`, `CookieDevice`](ds:block?id=authhttp-cookieroles-7kq3wn2x). The browser prefix and every attribute stay. An unknown role or a name that is not a cookie-name token panics, and so does `Handler`/`Middleware`/`Begin` when two cookies end up with one name. Pass it everywhere, as with `CookiePrefix` | every name from the prefix |
| [`WeakenCookies(attrs)`](ds:block?id=authhttp-weakencookies-8kw3nq2v), [`WeakenCookie(role, attrs)`](ds:block?id=authhttp-weakencookie-2pv7nq4k) | Turns cookie protections off, on every cookie or on one, as an escape hatch: [`CookieAttributes`](ds:block?id=authhttp-cookieattributes-6wq2nk8v) `ScriptReadable` drops `HttpOnly` (one XSS bug hands over the session), `Insecure` drops `Secure` and the `__Host-`/`__Secure-` prefix (plain-HTTP development; the cookie crosses the network in clear text), `CrossSite` sends `SameSite=None` (the origin check is then the only CSRF defence; refused with `Insecure`), `Path` narrows the path and names the cookie `__Secure-`. Logged as a warning at every start. | every protection on |
| [`SameSiteStrict()`](ds:block?id=authhttp-samesitestrict-4rp7mx2k) | Sends the session, cache, device and account cookies with `SameSite=Strict` instead of `Lax`: a top-level navigation from another site arrives with no session. The flow cookie stays `Lax` whatever this says, because the OAuth return is such a navigation and a `Strict` one would never come back. Trade-off: browsers treat a redirect chain that started at the provider as cross-site, so the first page after an OAuth callback may render signed out until the next navigation. | `Lax` |
| [`PartitionedCookies()`](ds:block?id=authhttp-partitionedcookies-9tq2vk6n) | Adds `Partitioned` (CHIPS) to every cookie, for an app embedded in another site's page: one jar per top-level site. | off |
| `Health()` | Adds `GET <prefix>/ok` answering `{"ok":true}` (`HealthPath`), for a liveness probe or a post-deploy smoke test. Opt-in, so an existing route table gains nothing it did not ask for. It reads no database: green means mounted and running, not ready to sign people in. | off |
| `Reference(opts)` | Adds `GET <prefix>/reference` ([`ReferencePath`](ds:block?id=authhttp-referencepath-3nk8wq5m)): an HTML page that loads an OpenAPI viewer and points it at the document `OpenAPI` serves, so the wired routes can be browsed and tried from a browser. It needs `OpenAPI`; `Handler` panics at start-up without it. [`ReferenceOptions`](ds:block?id=authhttp-referenceoptions-5wq8mn2k): `ScriptURL` names the viewer script (empty: Scalar's standalone bundle from jsDelivr, pinned, [`DefaultReferenceScript`](ds:block?id=authhttp-defaultreferencescript-9vt2px6r); an app that will not load a third-party script serves the bundle itself), `Nonce` is called per request and its answer becomes the `nonce` attribute of both script tags for a CSP that allows scripts by nonce (the app's middleware sets the policy header). `Theme` is one of the viewer's named themes ([`ReferenceThemeValues`](ds:block?id=authhttp-referencethemes-6tq2nw8k); anything else panics at start-up), sent as the viewer's `data-configuration`. A development convenience, opt-in like `OpenAPI`. | off |
| `ErrorPage(opts)` | Adds `GET <prefix>/error` ([`ErrorPagePath`](ds:block?id=authhttp-errorpagepath-5tw8kq2n)): the page a failed browser flow lands on when `auth.WithErrorURL` points at it. It shows the `error` code when it is shaped like one (`unknown` otherwise), the code's declared message in the request's language when the library declares it, and the provider's `error_description`, escaped and capped. Its title, heading and link translate through `auth.WithMessages` under `ErrorPageTitleCode`, `ErrorPageHeadingCode` and `ErrorPageBackCode`, and its `lang` follows the request's locale when the heading is translated (`en` otherwise). [`ErrorPageOptions`](ds:block?id=authhttp-errorpage-2kx7nd4w): `Template` replaces the page with any `html/template` over [`ErrorPageData`](ds:block?id=authhttp-errorpagedata-8qm3wd5k), `Redirect` sends the request on to the app's own page with the same parameters (it must pass `TrustsReturnURL`, or `Handler` panics at start-up), `Nonce` puts a CSP nonce on the built-in page's style. The page is `no-store`. | off |
| `OpenAPI(info)` | Adds `GET <prefix>/openapi.json` ([`OpenAPIPath`](ds:block?id=authhttp-openapipath-5nq8wk2d)): the [OpenAPI 3.1](ds:block?id=authhttp-openapiversion-7rt3mv9x) document of every operation this handler serves, built once from the same operation list as the routes, with request and response schemas derived from the operations' Go types, the requirement as security (`sessionCookie` or `bearerToken`), one error schema for every failure, and `Health` and `AcceptForms` reflected when set. A field, and a query parameter, is required unless its json tag has `omitempty`, the declaration every input type uses for what a caller may leave out; a `,string` field is a string and a type with its own `MarshalJSON` is any JSON. [`OpenAPIInfo`](ds:block?id=authhttp-openapiinfo-3kx9pz4w) carries the title, version, description and server URLs. Opt-in like `Health`; the document is public because it describes routes a client can discover anyway. | off |
| `TrustedProxies(networks...)` | Believes `X-Forwarded-For`, then `X-Real-IP` (or the headers `ClientIPHeaders` names) only when the connection comes from one of the given CIDRs or addresses, taking the rightmost forwarded entry that is not itself a trusted proxy. Any other connection keeps its own address, so a client that writes the header gains nothing. A value that is not a network panics at start-up. | none: the connection's address |
| `ClientIPHeaders(names...)` | The headers a trusted proxy's client address is read from, in order, for a proxy that writes `CF-Connecting-IP` or `Fly-Client-IP`. Naming `HeaderForwarded` reads the standard `Forwarded` header (RFC 7239) by its `for=` parameters, quotes, IPv6 brackets and ports removed, with the same rightmost-untrusted rule; it is never read by default. No effect without `TrustedProxies`, for `Forwarded` as for every other header. | `X-Forwarded-For`, `X-Real-IP` |
| [`ClientIPFunc(fn)`](ds:block?id=authhttp-clientipfunc-8vq3mx2k) | Replaces how the client's address is found, for a platform whose proxy rules `TrustedProxies` cannot express (an address in a context value, a signed header). `fn` owns the trust decision, so it must not return a value a client controls without checking where the request came from. An answer that is not an IP address (`""` included) falls back to the connection's address and the `TrustedProxies` rules, so text never reaches rate-limit keys or audit rows. | off |
| [`EncodeErrors(enc)`](ds:block?id=authhttp-encodeerrors-2hv7kc4p) | Writes every error body in the app's own shape, such as RFC 9457 `application/problem+json`, through an [`ErrorEncoder`](ds:block?id=authhttp-errorencoder-5qd8wn3r) `func(w, r, info auth.ErrorInfo)`. The library still decides the rest: `info` is already the 500 with no detail for an error that is not an `*auth.Error`, the response carries `info.Status` whatever status the encoder writes (an encoder that writes nothing still answers it), and `Retry-After` is set again after the encoder returns. It applies to `Handler` (its 404 and 405 included), `OperationHandler`, `Middleware`, and the guards behind it (`RequireUser`, `RequireFunc`, `RequireScope`), and through them to the gin, echo and fiber adapters. | `{"error": info}` |
| `AcceptForms()` | Lets a Mutation take an `application/x-www-form-urlencoded` body as well as JSON, one value per field, so a plain HTML form posts to a route without JavaScript; lists and objects stay JSON-only. | off: a form body is a bad request |
| `SkipTrailingSlash()` | Routes `/auth/sign-out/` as `/auth/sign-out`. | off: exact routes |
| `LocaleCookie(name)` | Reads the locale from the named cookie (`DefaultLocaleCookieName`, `auth_locale`, when `name` is empty) before `Accept-Language`, reduced like a header value; the app sets the cookie. | off: `Accept-Language` only |
| `LocaleFunc(fn)` | Asks `fn(r)` for the locale first; a non-empty answer, reduced like a header value, wins over the cookie and `Accept-Language`, an empty or unusable one falls through. For a source the transport cannot know: the app's own cookie or header, a tenant's default, a preference the app looks up itself. It runs before the session lookup, because the lookup's own error is rendered in the locale, so a preference stored on the user is reachable only through what the request carries ([`LocaleFunc`](ds:block?id=authhttp-localefunc-7mq4xk2p)). | off |
| [`APIKeyHeader(name)`](ds:block?id=authhttp-apikeyheader-6wz3rq8n) | Lets an API key arrive in the named header (`"X-Api-Key"`) as well as in `Authorization: Bearer`. The value is handed to the core as a bearer credential, so every rule for a key there (no cookie, no origin check, scopes) applies; a session cookie, then `Authorization`, win over it. | off: `Authorization` only |
| [`APIKeyFrom(get)`](ds:block?id=authhttp-apikeyfrom-8vq3mz6k) | Reads an API key from wherever your clients send it (a query parameter, say). Runs only when there is no session cookie, no `Authorization` header and no `APIKeyHeader` value; the key gets every rule a bearer key gets. A key in a URL reaches access logs, so prefer a header. | off |

## Handlers, middleware and helpers

| API | What it does |
|---|---|
| `Handler(a, opts...)` | Serves every registered operation at prefix plus the operation's route: a Query as GET (input from the query string, one value per key), a Mutation as POST (JSON body; an empty body is the zero input; unknown fields are refused). An unknown path answers 404 `auth.unknown_operation`. A known path with the wrong method answers 405 `auth.method_not_allowed` with an `Allow` header. A failed operation that asked for a redirect on error (`Call.RedirectOnError`) is answered with that 302 instead of the error JSON. |
| `OperationHandler(a, op, opts...)` | Serves one operation, with the same decoding, effects and error JSON as `Handler`. It is for a router that registers each route itself. |
| `MethodOf(kind)` | The HTTP method for an operation kind: `GET` for `auth.Query`, `POST` otherwise. |
| `OpenAPIDocument(a, info, opts...)` | The bytes `OpenAPI` serves, for a generator that writes them to a file: the repository's `task docs:api` writes [`docs/reference/openapi.json`](../docs/reference/openapi.json) with every plugin wired and `task check` fails when it is stale. Pass the same options as `Handler` so the prefix matches. |
| `TypeScriptClient(a)` | [The files of a typed TypeScript client](ds:block?id=authhttp-typescriptclient-4vn8kq2r) for every operation `a` serves, from the same operation list: `client.ts` (a type per Go input and output, an operation table and factory per plugin, `createAuthClient`), `runtime.ts` (the fetch runtime, embedded from `tsclient/runtime.ts`), `error-codes.ts`, `extensions.ts` (the hand-written `oauthPopup()` and `lastLoginMethod()`, embedded from `tsclient/extensions.ts`) and `index.ts` ([`TSFileClient` and the other names](ds:block?id=authhttp-tsfiles-6qm2xw8k)). A plugin's methods exist on the client only when the plugin is passed to it. `ErrTypeScriptName` refuses a name two things would share. The repository's `task docs:api` writes [`clients/ts/src`](../clients/ts/) with every plugin wired; an app runs `auth client ts`. Guide: [TypeScript client](../docs/client/README.md). |
| `TypeScriptMethods(a)` | [The methods of that client](ds:block?id=authhttp-typescriptmethods-7hq4mz2c) as data (`TSMethod`: namespace, name, operation id, route, requirement, input and output types), core first; it fails exactly when `TypeScriptClient` does. The repository's `task docs:api` writes [`docs/reference/ts-client.md`](../docs/reference/ts-client.md) from it. |
| `TypeScriptErrorCodes()` | [The error-code module](ds:block?id=authhttp-typescripterrorcodes-8kw3nq5v) of the client, `docs/reference/error-codes.ts` byte for byte: every code `auth.Errors()` lists, with status, message and owning plugin, the `AuthErrorCode` union and the `isAuthErrorCode` guard. |
| `Middleware(a, opts...)` | Attaches the request to the core and resolves the session once, for your own handlers and for a GraphQL handler. Effects recorded by operations called inside the handler (such as an issued session) become headers before the handler's first byte. A session lookup that fails for any reason other than "signed out" answers 500 instead of running the handler as if nobody were signed in. |
| `RequireUser(next)` | Answers 401 `auth.signed_out` when there is no session. It must run inside `Middleware`. |
| `RequireFunc(check)` | Refuses the request when `check(r)` returns an error, answering with that error's JSON. Use it for your own rule, such as a role or who owns a resource. It must run inside `Middleware`. |
| `RequireUserExcept(next, allow...)` | `RequireUser` for a whole handler tree, deny by default: every path needs a signed-in user except the listed ones. An entry ending in `/` opens that subtree (`"/auth/"`), any other entry exactly that path (`"/login"`). It must run inside `Middleware`. |
| `RequireScope(scope)` | Lets through only a request that carries an API key with `scope`. A request with no principal at all (no credential, or a revoked, expired or unknown key) answers 401 `auth.signed_out`, so the client knows to authenticate. A principal without the scope answers 403 `auth.missing_scope`, and so does a browser session, because a scope-guarded route is for keys. No `RequireUser` is needed in front of it. It must run inside `Middleware`. |
| `HTTPMiddlewarer` (plugin interface) | A plugin that returns [`PluginMiddleware`](ds:block?id=authhttp-pluginmiddleware-6kd3nq8w) values from `HTTPMiddleware()` wraps `Handler`'s routes in net/http middleware, around every request or only matched paths: `Wrap(next)` may replace the request, answer without calling `next`, or wrap the writer to see the response; `Paths` limits it to exact routes or prefixes ending in `*`, after the prefix (empty: every request `Handler` receives). Plugins apply in order, the first outermost, each run traced as `auth.middleware <plugin> <route>` under `auth.WithTracer`. Only `Handler` applies them, not `OperationHandler` or a GraphQL call, so a rule every entry point must keep belongs in an `auth.OperationHook`. |
| `CurrentUser(r)` | The signed-in user, and `false` when signed out. It never queries the database. |
| `MustUser(r)` | The signed-in user. It panics with `ErrNoUser` when there is none, for handlers behind `RequireUser`. |
| `WriteError(w, err)` | Writes `err` as the error JSON with its status, plus `Retry-After` for a rate-limited error. An error that is not an `*auth.Error` answers 500 with no detail. |
| [`WriteErrorFor(w, r, err)`](ds:block?id=authhttp-writeerrorfor-6pm3xk8q) | `WriteError` with the message in the request's locale when the app set `auth.WithMessages` and `r` went through `Begin`, `Middleware` or `Handler`; code and status are unchanged, and without a catalogue so is the message. Every error `Handler`, `RequireUser` and `RequireFunc` answer goes through it; under `EncodeErrors` the body is the encoder's. |
| `WriteErrorWith(w, r, err, opts...)` | `WriteError` for an adapter that holds the request and the options but no context from `Begin` yet (because `Begin` failed): the `EncodeErrors` encoder when `opts` or `r`'s context set one, else the error JSON. The message is not translated, as `WriteError`'s is not. |
| `ErrorEncoderOf(ctx, opts...)` | The `EncodeErrors` encoder `opts` set, else the one `ctx` carries from `Begin`, `Middleware` or `Handler`, else nil; for an adapter whose framework has no `http.ResponseWriter` to hand out (fiber). |
| `SetRetryAfter(w, err)` | Sets `Retry-After` in whole seconds when `err` carries a retry time. It is for a transport that writes errors in its own format, as authui does. |
| `UIMethod` (plugin interface), [`SignInMethod`](ds:block?id=authhttp-signinmethod-7mx2qd9w), `SignInMethods(a)` | A plugin that offers sign-in buttons to the pages an app renders implements [`UIMethod`](ds:block?id=authhttp-uimethod-3fn8vk2p) (`SignInMethods() []SignInMethod`): each method has an `ID`, a `Kind` for styling, an English `Label`, the operation `Route` it starts (a GET Query that redirects, joined by the page to where `Handler` is mounted) and optionally one `Field` the page asks for first, such as an email for an SSO start. `SignInMethods(a)` collects them in plugin order, for an app's own sign-in page; authui renders them. It lives here, not in authui, so a plugin implements it without importing authui. |
| `RequestOf(r, opts...)` | Converts an `*http.Request` into the core's `auth.Request`: cookie, bearer token or API-key header, client IP, user agent, origin, locale, `Sec-Fetch-Site` (`Client.FetchSite`, acted on only under `auth.WithFetchMetadata`), the host the request came to (`Request.Host`: the `Host` header, or the first `X-Forwarded-Host` entry when the connection is from a `TrustedProxies` network; the core acts on it only under `auth.WithAllowedHosts`), the flow cookie, the device token, the device's other accounts and the client's cached session copy. |
| `Begin(a, r, opts...)` | Attaches `r` and resolves its session, returning the request with its new context. Every adapter starts a request with it. |
| [`HTTPRequest(ctx)`](ds:block?id=authhttp-httprequest-8kq3nw5x) | The `*http.Request` a call arrived on, for an operation, a hook or a handler behind `Middleware` (`r.URL.Query()` gives its query parameters); false for a direct Go call. Its body has been read by the decoder; treat everything in it as client input. Set by `Handler`, `OperationHandler` and `Begin`, so every adapter has it. |
| `WrapWriter(w, r, opts...)` | Returns a writer that applies `r`'s effects just before the first header or byte, and a `finish` function that applies the effects of a handler that wrote nothing and reports how many effects came too late. |
| `ApplyHeaderEffects(w, r, opts...)` | Writes every effect of `r` that can be a header (all kinds except a redirect) and returns how many effects it saw. |
| `ApplyEffects(w, r, effects, opts...)` | Writes the given effects and reports whether one of them was a redirect (302 plus `Location`), in which case the response is complete. |
| `BearerMode(r)` | Reports whether `r` asked for sessions as bearer tokens. |
| `HasCredential(r, opts...)` | Reports whether `r` carries a session cookie or a bearer token at all, without looking it up, for a cheap redirect to the sign-in page before a page renders. Presence is not validity: a forged or expired cookie passes here, so protected actions still run behind `Middleware` and `RequireUser`. |
| `LocaleOf(header)` | The first tag of an `Accept-Language` header, or `""` when it is missing, `*`, longer than 35 characters ([`maxLocaleLen`](ds:block?id=maxlocalelen-2bzbpt7y)) or contains anything besides letters, digits and `-`. |

### Cookies

| Constant | Value | Use |
|---|---|---|
| [`CookieName`](ds:block?id=cookiename-xgdjargz) | `__Host-auth_session` | The session. `__Host-` makes the browser refuse it unless it is Secure, has Path=/ and has no Domain. |
| [`FlowCookieName`](ds:block?id=flowcookiename-rnhn6vw5) | `__Host-auth_flow` | Binds a multi-step flow, such as an OAuth sign-in, to this browser. |
| [`DomainCookieName`](ds:block?id=domaincookiename-y5xjae8s) | `__Secure-auth_session` | The session under `CookieDomain`. |
| [`DomainFlowCookieName`](ds:block?id=domainflowcookiename-pgbydmxs) | `__Secure-auth_flow` | The flow cookie under `CookieDomain`. |
| `CacheCookieName` | `__Host-auth_session_cache` | The client's sealed copy of its session from a snapshot `auth.SessionCache` (`auth.EffectCacheSession`), so the next requests skip the session lookup. Its `Max-Age` is the cache TTL. |
| `DomainCacheCookieName` | `__Secure-auth_session_cache` | The cache cookie under `CookieDomain`. |
| [`DeviceCookieName`](ds:block?id=devicecookiename-8qm3vt2k) | `__Host-auth_device` | The device token a second-factor plugin hands out with `auth.EffectRememberDevice` ("remember this browser"), presented back as `auth.Request.Device`. Set with the effect's expiry; an empty token deletes it. It survives sign-out, because it exists to skip the second factor on the next sign-in. |
| [`DomainDeviceCookieName`](ds:block?id=domaindevicecookiename-3hn7kp9r) | `__Secure-auth_device` | The device cookie under `CookieDomain`. |
| [`AccountCookiePrefix`](ds:block?id=accountcookieprefix-5xw9nr4j) + 12 hex digits | `__Host-auth_account_…` | Under `auth.WithMultiSession`, one cookie per OTHER account signed in on the device (the active one stays in `CookieName`), named by the first 12 hex digits of the token's SHA-256 so one account can be dropped without rewriting the rest; the values are read into `auth.Request.DeviceTokens`. A sign-in moves the previously active token into its own account cookie with the new session's lifetime; a sign-in with a token the device already holds is a switch, which makes it active and deletes its account cookie; `auth.EffectForgetDeviceSession` deletes one; sign-out deletes them all. Automatic when the `Auth` has multi-session on, nothing to pass. |
| `DomainAccountCookiePrefix` | `__Secure-auth_account_…` | The account cookies under `CookieDomain`. |
| `__Host-auth_<name>` | a plugin's | A plugin cookie (`auth.EffectCookie`, recorded with `c.Effects.SetCookie` or `c.SetSignedCookie`), named by the plugin (`auth.CheckCookieName`: never one of the names above) and read back into `auth.Request.Cookie`. Same prefixes, same attributes; `__Secure-` under `CookieDomain`. |

Every cookie is `HttpOnly`, `Secure`, `SameSite=Lax` and `Path=/`: `SameSiteStrict` and `PartitionedCookies` only add, and `CookiePrefix` and `RenameCookie` change only the name behind the browser prefix. Only the escape hatches `WeakenCookies` / `WeakenCookie` turn a protection off, and `Handler` and `Middleware` log [`WarnCookiesWeakened`](ds:block?id=authhttp-warncookiesweakened-3nq8wk5x) at start-up while one is set. A session issued without "remember me" is a browser-session cookie with no Expires; the server still ends it at its expiry. In host-only mode a `__Secure-` cookie is ignored, and under `CookieDomain` a `__Host-` one is, so a sibling subdomain cannot plant a session. Clearing the session (`auth.EffectClearSession`) also clears the cache cookie, and `auth.EffectClearCache` clears it alone. A cached copy recorded before either clear in the same response (a sign-out's own session lookup makes one) is not sent, as a cookie or as `Set-Auth-Session-Cache`; one recorded after it, by a sign-in that follows, is. A stateless session token (`auth.WithStatelessSessions`) is about 400 characters rather than 43; the cookie carries it whole and stays far under the 4 KB a browser accepts.

### Bearer mode

A client that cannot keep cookies (a mobile app, a CLI) sends `Auth-Token-Mode: bearer` when it signs in, then `Authorization: Bearer <token>` on every request.

| Constant | Value | Direction |
|---|---|---|
| [`TokenModeHeader`](ds:block?id=tokenmodeheader-s6xp5wjc) | `Auth-Token-Mode` | request: ask for bearer mode |
| [`TokenModeBearer`](ds:block?id=tokenmodebearer-3p2r26xe) | `bearer` | the value of that header |
| [`SetTokenHeader`](ds:block?id=settokenheader-j7vbxqvy) | `Set-Auth-Token` | response: the issued session token |
| [`SetTokenExpiresHeader`](ds:block?id=settokenexpiresheader-rxwtm4ay) | `Set-Auth-Token-Expires` | response: its expiry, RFC 3339 UTC |
| `SessionCacheHeader` | `Auth-Session-Cache` | request: the cached session copy from an earlier response |
| `SetSessionCacheHeader` | `Set-Auth-Session-Cache` | response: a new cached copy to send back |
| [`DeviceHeader`](ds:block?id=deviceheader-7rt2wq5m) | `Auth-Device` | request: the device token of `DeviceCookieName`, when there is no cookie |
| [`SetDeviceHeader`](ds:block?id=setdeviceheader-4kx8mv3p) | `Set-Auth-Device` | response: a device token to keep (`auth.EffectRememberDevice`); an empty value means forget it |

In bearer mode an issued session arrives only in `Set-Auth-Token`, never as a cookie and never in the JSON body, and a cached copy arrives in `Set-Auth-Session-Cache`. Signing out and clearing the cache set no header, because the client discards its own token and copy. When a request carries both a cookie and a bearer header, the cookie wins, and so does the cache cookie over `Auth-Session-Cache`. The `Bearer` scheme is compared case-insensitively, as RFC 7235 requires, and the token trimmed; `Bearer` alone or another scheme is no credential. A bearer client keeps its own set of accounts under multi-session, so `auth.EffectForgetDeviceSession` writes nothing to it.

### Error JSON

Every error, from every route and helper, has this shape and carries the error's HTTP status:

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

`code` is stable and meant for programs to branch on. `message` is safe to show a user. A message translated by `auth.WithMessages` (for example `i18n.Messages()`) adds `originalMessage`, the declared English text. A rate-limited answer adds `Retry-After`.

An app with its own error contract passes `EncodeErrors(enc)` to `Handler`, `Middleware` and every adapter; the body is then `enc`'s, under the same status and `Retry-After`. `WriteError(w, err)` holds no request and always writes the shape above; call `WriteErrorFor` or `WriteErrorWith` from your own handlers to follow the encoder.

## Tables and columns

None. The package reads and writes nothing itself; every row belongs to the core and the plugins.

## Errors

| Error | Code | Status | When |
|---|---|---|---|
| `ErrMethodNotAllowed` | `auth.method_not_allowed` | 405 | A known route called with the wrong method (`Handler` only). |
| `ErrMissingScope` | `auth.missing_scope` | 403 | `RequireScope` on a principal (a key or a session) without the scope. |
| `ErrNoUser` | (panic value, not JSON) | none | `MustUser` on a request with no user: a wiring bug. |
| `auth.ErrUnknownOperation` | `auth.unknown_operation` | 404 | No route at this path. |
| `auth.ErrBadRequest` | `auth.bad_request` | 400 | A body or query that does not decode into the operation's input. |
| `auth.ErrOriginNotTrusted` | `auth.origin_not_trusted` | 403 | A cookie-authenticated mutation whose Origin (or, without one, Referer) is not trusted. |
| `auth.ErrSignedOut` | `auth.signed_out` | 401 | `RequireUser`, or `RequireScope`, on a request with no principal. |
| `auth.ErrInternal` | `auth.internal` | 500 | Anything that is not an `*auth.Error`, and a session lookup that failed. The detail is logged, never sent. |

## Security notes

| Property | Pinned by |
|---|---|
| The session cookie is `__Host-`, `HttpOnly`, `Secure` and `SameSite=Lax`, and the raw token never appears in a response body. | `TestHandler_IssueSessionSetsAHardenedCookie` |
| A cookie-authenticated mutation from another origin is refused, using Referer when Origin is missing. | `TestHandler_OriginCheckOnCookieMutations` |
| In bearer mode the token travels only in `Set-Auth-Token`. | `TestHandler_BearerModeReturnsTheTokenInAHeader`, `TestHTTP_BearerMode` (integration) |
| Host-only mode ignores a `__Secure-` cookie that a sibling subdomain could have planted, and domain mode ignores the other name. | `TestCookieDomain_NamesDomainAndIgnoresTheOtherPrefix` |
| Under `CookiePrefix` every cookie carries the prefix behind `__Host-`/`__Secure-`, only prefixed cookies are read, a prefix that is not a cookie-name token is refused when the option is built, and gin, echo, fiber, the gqlgen example and authui honour it. | `TestCookiePrefix_RenamesEveryCookieAndReadsOnlyThose`, `TestCookiePrefix_RefusesANonToken`, `TestMount_HonoursTheCookiePrefix` (gin, echo, fiber), `TestGraphQL_HonoursTheCookiePrefix`, `TestHTTPOptions_CookiePrefixIsTheCookieTheseLookUp` |
| `SameSiteStrict` makes every cookie but the flow cookie `Strict`, deletions included, and `PartitionedCookies` adds the attribute without dropping `HttpOnly` or `Secure`; the defaults are unchanged. | `TestSameSiteStrict_StrictEverywhereButTheFlowCookie`, `TestPartitionedCookies_AddsTheAttributeAndKeepsTheRest` |
| An internal error answers 500 with no detail, and the detail is logged. | `TestHandler_ErrorsUseTheirCodeAndStatus` |
| A failed session lookup is a 500, never a silent sign-out. | `TestMiddleware_MissingDatabaseIsNotASignOut` |
| An effect recorded after the response started is logged, not silently lost. | `TestMiddleware_LateEffectIsLogged` |
| A rate-limited request answers 429 with `Retry-After`. | `TestHandler_RateLimitedAnswers429WithRetryAfter`, `TestWriteError_SetsRetryAfterForALimitedError` |
| `RequireScope` answers 401 without a principal (no credential, a revoked key) and 403 for a key or session without the scope. | `TestRequireScope_NoPrincipalIsSignedOut`, `TestRequireScope_SeparatesNoPrincipalFromMissingScope` (integration) |
| The cached session copy travels in a cookie as hardened as the session's, with `Max-Age` of the cache TTL, is never sent once expired, and is cleared with the session; in bearer mode it travels in the headers only. | `TestApplyEffects_CacheSessionCookie`, `TestApplyEffects_CacheSessionInBearerMode`, `TestRequestOf_ReadsTheCachedSession` |
| With a snapshot cache the second request needs no database at all, and sign-out removes the copy. | `TestHTTP_SnapshotCacheSkipsTheLookup` (integration) |
| A 400-character stateless token round-trips through the cookie under 4 KB. | `TestApplyEffects_ALongTokenFitsTheCookie`, `TestHTTP_StatelessSessionEndToEnd` (integration) |
| A forwarded address is believed only from a trusted proxy, the rightmost untrusted entry wins, and text that is not an address is skipped; a bad network refuses to start. | `TestRequestOf_TrustedProxies`, `TestTrustedProxies_RefusesAValueThatIsNotANetwork` |
| `Forwarded` is read only when named and only from a trusted proxy; the rightmost untrusted `for=` wins, a second header line counts as appended, and a client's unterminated quote cannot swallow the proxy's entry. | `TestForwarded_HonouredOnlyBehindTrustedProxies` |
| `ClientIPFunc` decides the address, and an answer that is not an IP falls back to the connection and the proxy rules. | `TestClientIPFunc_OverridesAndFallsBack` |
| Under `EncodeErrors` every error (operation, 404, 405, `RequireUser` behind `Middleware`, a failed `Begin`) is the encoder's body, the status is the library's whatever the encoder writes, `Retry-After` survives an encoder that removes it, and an internal error reaches the encoder without detail. | `TestEncodeErrors_ProblemJSONEverywhereStatusPinned`, `TestEncodeErrors_RateLimitKeepsRetryAfter`, `TestEncodeErrors_InternalErrorsStayOpaqueAndSilentEncoderStillAnswers`, `TestEncodeErrors_ReachesMiddlewareAndRequireUser` (gin, echo, fiber) |
| A form body is refused unless `AcceptForms` is set, and then decodes to the same input as JSON. | `TestHandler_AcceptForms` |
| A trailing slash is a 404 unless `SkipTrailingSlash` is set. | `TestHandler_SkipTrailingSlash` |
| The locale cookie is read only when configured and only if it is a plausible tag. | `TestRequestOf_LocaleCookie` |
| `LocaleFunc` decides first, its answer is reduced like a header, and an empty or unusable answer falls through to the cookie and the header. | `TestRequestOf_LocaleFunc` |
| The reference page is absent unless `Reference` is passed, needs `OpenAPI` (start-up panic without it), names the served document under the prefix, loads the pinned or the named script, carries the per-request nonce attribute-escaped on both script tags, and answers only `GET`. | `TestReference_ServedOnlyWhenAsked` |
| The health route is absent unless `Health()` is passed, answers only `GET`, and touches no database. | `TestHandler_HealthRouteIsOptIn`, `TestHTTP_HealthAndDenyByDefault` (integration) |
| `RequireUserExcept` denies every path not listed, and an exact entry does not open its subtree. | `TestRequireUserExcept_DeniesByDefault`, `TestHTTP_HealthAndDenyByDefault` (integration) |
| `HasCredential` reads the cookie name `CookieDomain` selects and never counts the other prefix. | `TestHasCredential_ReportsPresenceOnly` |
| The body decoder survives arbitrary input. | `FuzzDecode` (`task fuzz`) |
| `ErrorPage` escapes the description, shows `unknown` for a value not shaped like a code, takes the message from the library's declarations, never the link, and refuses an off-site `Redirect`. | `TestErrorPage_RendersTheCode`, `TestErrorPage_Options` |
| `CookieDomainFromBaseURL` takes the domain from the request's checked base URL: a `Host` no rule allows gets the static base URL's domain. | `TestCookieDomainFromBaseURL` |
| A plugin cookie gets the library's attributes whatever the plugin asked, under the same prefixes. | `TestPluginCookie_SetAndRead` |
| Plugin middleware runs in plugin order, only on its paths, and is traced. | `TestPluginMiddleware` |

Limits:
- A request body is capped at 1 MiB ([`maxBodyBytes`](ds:block?id=maxbodybytes-u79t9fxq)).
- The client IP is the connection's remote address. `X-Forwarded-For` and `Forwarded` are not trusted by default, because any client could otherwise pick its own IP and escape per-IP rate limits. An app behind a proxy names it with `TrustedProxies`, or decides itself with `ClientIPFunc`.

## Example

- [examples/quickstart](../examples/quickstart/): email and password on net/http.
- [examples/multi-instance](../examples/multi-instance/): two instances sharing sessions and rate limits.
- [examples/api-keys-and-jwt](../examples/api-keys-and-jwt/): `RequireScope` and bearer tokens.
- [examples/admin-plan](../examples/admin-plan/): `RequireFunc` guarding admin routes.
- https://pkg.go.dev/github.com/ubgo/auth/authhttp

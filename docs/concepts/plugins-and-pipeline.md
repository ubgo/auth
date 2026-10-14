# Plugins and the pipeline

The library has no sign-in method of its own. Every way in — password, email code, phone, passkey, OAuth — is a plugin, and every feature is one operation that reaches your app through one pipeline. This page explains those two ideas, because everything else in the guide rests on them.

## Before you start

- A running quick start (`examples/quickstart`) helps: the ideas below are what its twenty lines of wiring do.
- Nothing here is needed to write a plugin; that is [Extending](../extending/README.md). This page is for the app developer who wires plugins and calls operations.

## Step 1 — Pick plugins: the list is the whole answer

`auth.New` takes a list of plugins, and that list is the complete answer to "what can sign a user in, and what else can an account do". The core keeps users, sessions, verification tokens and the identity rules; a plugin brings an identifier kind (`plugin/email`, `plugin/phone`, `plugin/username`), a credential (`plugin/password`, `plugin/passkey`, `plugin/oauth`, `plugin/magiclink`, `plugin/anonymous`), a second factor (`plugin/twofactor`), or features around accounts (`plugin/organization`, `plugin/admin`, `plugin/apikey`, `plugin/jwt`, `plugin/terms`, `plugin/captcha`, `plugin/handoff`, `plugin/lastlogin`).

<!-- ds:block id=newauth-smwje7vu -->
**newAuth** · [`examples/quickstart/main.go:99-108`](../../examples/quickstart/main.go#L99-L108)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=6b7d2a -->

Order matters a little: plugins run in list order, so their hooks and migrations do too, and a plugin that hooks another names it with `Requires` and comes after it.

Check: `auth.New` refuses a list nobody could use. No sign-in method is `auth: no sign-in method; add a plugin such as password or oauth`; an email kind that may recover an account but has no mailer fails the email plugin's own `Validate`. A refused start is the cheapest possible failure.

## Step 2 — Understand an operation

An operation is one typed function: an input, a `Call` describing who is calling, an output. `plugin/password` defines `password.sign-in` once, and that one definition is `POST /auth/password/sign-in` over HTTP, a mutation in GraphQL, and `pw.SignIn(ctx, …)` from Go. There is no second copy for the Go API that could forget a check.

Every operation carries a kind and a requirement. A `Query` reads and is served as `GET`; a `Mutation` changes state, is served as `POST`, runs in one transaction, and is origin-checked. The requirement is `Public` (sign-in, sign-up), `SignedIn` (most things), `FreshSignIn` (changing a password or an address: the session must have been created or [re-authenticated](sessions.md#prove-it-is-still-you-re-authentication) within the fresh window) or `PendingSecondFactor` (the step that finishes a two-factor sign-in); `SignedInOrPending` accepts either kind of session, for one operation that serves the sign-in step and the signed-in user alike, such as sending a second-factor code.

<!-- ds:block id=core-requirements-tksmmmjf -->
**Public** · [`operation.go:29`](../../operation.go#L29-L29)

```go
"public"
```
<!-- /ds:block hash=b78532 -->

Check: `a.Operations()` lists every operation with its route; `go run ./poc` in `examples/` prints them all without a database.

One kind of operation is wired but not listed: one marked [`SelfServed`](ds:block?id=core-opinfo-selfserved-m4q8xk2w), whose HTTP shape a standard fixes. The OAuth provider's token endpoint is the example: RFC 6749 requires a form body, HTTP Basic client authentication and `{"error": "invalid_grant"}` answers. The plugin serves such an operation from its own handler, which calls `Op.Call`. `a.Operations()` leaves it out, so no transport mounts a second, JSON-shaped copy. `a.Operation(id)` still finds it, hooks and `WithDisabledOperations` can name it, and every call runs the whole pipeline below. The same flag marks an operation with no wire format at all, one only the plugin's own handler or Go API calls: SCIM's `scim.request`, which every SCIM request passes through for its rate rules, and the hand-off plugin's `generate` under `ServerOnly()`. Neither the OpenAPI document nor the generated TypeScript client lists a self-served operation, because every transport would answer it `auth.unknown_operation`.

An operation can leave facts for its hooks that its input does not carry. [`c.Annotate(key, value)`](ds:block?id=core-call-annotate-5p8wv2kq) records one, such as the organization an operation resolved ([`auth.AnnotationOrganization`](ds:block?id=core-annotationorganization-7w3kq9xm)), and [`c.Annotation(key)`](ds:block?id=core-call-annotation-3m6xq8wn) reads it in an After or Finally hook. Values are plain strings, so nothing secret goes in by accident. They live on the call rather than in the transaction, so a Finally hook still reads them after a failure, and an operation called from inside another has a call of its own.

## Step 3 — Know the pipeline order

Every entry point runs the same steps, in this order, and stops at the first failure:

1. Rate limit by client address, so a flood costs one counter increment and nothing else.
2. Origin check, for a mutation that carries a session cookie: a request from an origin that is not the base URL or a trusted origin is refused before any lookup, so a cross-site request learns nothing, not even whether its session is valid.
3. The session, resolved once per request and shared by every operation in it.
4. The requirement.
5. The input decoded and the per-account rate limit counted, both before any transaction, so a failed call cannot roll its own count back.
6. For a mutation, one transaction for everything below; data hooks and plugin writes join it.
7. Hooks before, the operation, hooks after.
8. Effects (set a cookie, clear it, redirect) and messages (a verify mail) reach the client only after the commit.

The transport applies the effects: `authhttp` turns "issue session" into a `Set-Cookie`, or into a `Set-Auth-Token` header for an app that asked for bearer mode. [Sessions](sessions.md) has the details; [Transactions](transactions.md) explains step 6 and 8 from the app's side.

## Step 4 — Call operations from Go

Each plugin exposes a typed method per operation. From a handler, pass the request's context so the call runs as that request, with its session and client and its effects reaching the response; from a job or a test, a plain context runs as a signed-out Go call.

```go
res, err := pw.SignIn(r.Context(), password.SignInRequest{Identifier: in.Email, Password: in.Password})
```

The core's own operations are methods on `*auth.Auth`: `SignOut`, `SignOutAll`, `ListSessions`, `RevokeSession`, `UpdateProfile`. The request's user is `auth.CurrentUser(ctx)` (or `authhttp.MustUser(r)` behind `RequireUser`), and a wired plugin is `auth.PluginOf[*password.Plugin](a)`.

<!-- ds:block id=core-currentuser-g6e2yzqp -->
**CurrentUser** · [`call.go:421-427`](../../call.go#L421-L427)

```go
func CurrentUser(ctx context.Context) (User, bool) {
	st := stateFrom(ctx)
	if st == nil || st.user == nil || st.session == nil || !st.session.usable() {
		return User{}, false
	}
	return *st.user, true
}
```
<!-- /ds:block hash=5bb3f1 -->

<!-- ds:block id=core-pluginof-9ydc98rf -->
**PluginOf** · [`plugin.go:80-88`](../../plugin.go#L80-L88)

```go
func PluginOf[T Plugin](a *Auth) (T, error) {
	var zero T
	for _, p := range a.plugins {
		if typed, ok := p.(T); ok {
			return typed, nil
		}
	}
	return zero, ErrPluginNotRegistered
}
```
<!-- /ds:block hash=6a69e6 -->

Check: a Go call without a request to a `SignedIn` operation is `auth.ErrSignedOut`, exactly as the HTTP route would answer `401`.

## Step 5 — Mount the transport

`authhttp.Handler` serves every operation under a prefix; `authhttp.Middleware` resolves the session for the app's own routes and applies effects; `authhttp.RequireUser` turns a signed-out request into `401`. The gin, echo and fiber adapters and the gqlgen integration wrap the same pieces.

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

<!-- ds:block id=authhttp-handler-3xrumz2e lines=1-18 -->
**Handler** · [`authhttp/authhttp.go:792-842`](../../authhttp/authhttp.go#L792-L842)

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
	}
	if cfg.health {
		routes[cfg.prefix+HealthPath] = map[string]http.Handler{http.MethodGet: http.HandlerFunc(serveHealth)}
	}
	if cfg.openapi != nil {
		// Built once: the operation list is fixed for the life of the Auth.
		routes[cfg.prefix+OpenAPIPath] = map[string]http.Handler{http.MethodGet: serveOpenAPI(marshalOpenAPI(buildOpenAPI(a, *cfg.openapi, cfg)))}
	}
```
<!-- /ds:block hash=8dfb61 -->

<!-- ds:block id=authhttp-middleware-j6kn46zp -->
**Middleware** · [`authhttp/authhttp.go:1695-1720`](../../authhttp/authhttp.go#L1695-L1720)

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
					cfg.logger.Error("auth session lookup failed", "error", err)
				}
				cfg.writeError(w, r, err, auth.ErrorOf(err))
				return
			}
			ew, finish := wrapWriter(w, r, cfg)
			next.ServeHTTP(ew, r)
			if late := finish(); late > 0 {
				cfg.logger.Warn("auth effects recorded after the response started were not applied",
					"count", late, "path", r.URL.Path)
			}
		})
	}
}
```
<!-- /ds:block hash=4e9b1e -->

<!-- ds:block id=authhttp-requireuser-7tfua9sp -->
**RequireUser** · [`authhttp/authhttp.go:1832-1847`](../../authhttp/authhttp.go#L1832-L1847)

```go
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.CurrentUser(r.Context()); !ok {
			// A session with tasks pending is signed in but not usable:
			// 403 auth.session_task_pending tells the client to finish
			// them (GET /session lists them) rather than to sign in.
			if tasks := auth.CurrentSessionTasks(r.Context()); len(tasks) > 0 {
				WriteErrorFor(w, r, &auth.SessionTaskError{Tasks: tasks})
				return
			}
			WriteErrorFor(w, r, auth.ErrSignedOut)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```
<!-- /ds:block hash=3ae383 -->

Check: `curl -s localhost:8081/auth/session` answers `{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}` before anyone signs in.

## What can go wrong

- `auth: no sign-in method; add a plugin such as password or oauth` — the list has no plugin that signs in.
- `auth: plugin dependency not registered: "twofactor" requires "password"` — a plugin needs another one in the list.
- `auth: duplicate plugin name: "email"` — the same plugin twice; keep one.
- `auth.signed_out` (401) — the operation needs a session and the request has none, or it expired.
- `auth.fresh_session_required` (403) — the operation needs a recent sign-in; [re-authenticate](sessions.md#prove-it-is-still-you-re-authentication) and retry.
- `auth.origin_not_trusted` (403) — a cookie-authenticated `POST` from an origin that is not trusted; set `WithBaseURL`, and `WithTrustedOrigins` for a second front end.
- `auth.method_not_allowed` (405) — a `GET` to a mutation or a `POST` to a query.
- `auth.unknown_operation` (404) — a route no plugin registered; check the prefix and the plugin list.

## Next

- [Sessions](sessions.md): what a signed-in request holds, and how it is checked.
- [Configuration](configuration.md): every option `auth.New` takes.
- [Extending](../extending/README.md): writing a plugin of your own.

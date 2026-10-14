# Operations

You will have a feature defined once — a typed function with an input and an output — that is served as an HTTP route, a GraphQL field and a Go method, through one pipeline that applies the rate limits, the origin check, the session requirement and the hooks before your code runs.

## Before you start

- [Plugin anatomy](01-plugin-anatomy.md): operations are declared in the plugin's constructor and listed by `OperationProvider`.
- The example is [`examples/plugin-tables/devices`](../../examples/plugin-tables/devices/devices.go): three operations, one of each requirement a signed-in feature uses. `go test ./plugin-tables/...` in `examples/` runs it; the `referral` plugin in `examples/custom-plugin` has a one-operation version.
- Why one definition: an operation written as an HTTP handler could not run from a CLI, a job or a GraphQL resolver, and a second copy for those would be the one that forgets the rate limit. So the operation records what it needs and what it wants done, and each transport maps that to its protocol.

## Step 1 — Describe the operation with OpInfo

An operation has an id (`<plugin>.<name>`, exported as a constant so another plugin's hook can name it), a kind, a requirement and a path relative to the plugin. The core serves the path at `/<plugin><Path>`; GraphQL exposes a `Query` as a query and a `Mutation` as a mutation.

<!-- ds:block id=core-opinfo-6xnm8pzr lines=1-7 -->
**OpInfo** · [`operation.go:58-114`](../../operation.go#L58-L114)

```go
type OpInfo struct {
	ID      EndpointID
	Kind    OpKind
	Require Requirement
	// Path is relative to the plugin, such as "/sign-in". The core serves it at
	// "/<plugin>/sign-in"; a core operation's path has no plugin segment.
	Path string
```
<!-- /ds:block hash=4ad937 -->

The struct goes on with three flags: [`CrossSiteForm`](ds:block?id=core-opinfo-crosssiteform-7qn3kx8m), [`SelfServed`](ds:block?id=core-opinfo-selfserved-m4q8xk2w) (an operation whose wire format a standard fixes, such as an OAuth token endpoint: the plugin serves it from its own handler, which still calls the typed operation through the whole pipeline, and no transport mounts a JSON copy; also the flag for an operation only your own handler or Go API calls, which then stays out of the OpenAPI document and the generated TypeScript client) and [`SignIn`](ds:block?id=core-opinfo-signin-5vt8kq2m).

<!-- ds:block id=devices-endpoints-jkuxfrv8 -->
**EndpointAdd** · [`examples/plugin-tables/devices/devices.go:46-50`](../../examples/plugin-tables/devices/devices.go#L46-L50)

```go
const (
	EndpointAdd    auth.EndpointID = "devices.add"
	EndpointList   auth.EndpointID = "devices.list"
	EndpointRemove auth.EndpointID = "devices.remove"
)
```
<!-- /ds:block hash=2987ac -->

`Query` reads, `Mutation` changes state. The difference is enforced, not a hint: HTTP serves a query as `GET` and a mutation as `POST`; a mutation opens one transaction for everything in it, which data hooks and plugin writes join; and the origin check applies to mutations only, because that is where a cross-site request could do harm.

One mutation is exempt by declaration: [`CrossSiteForm`](ds:block?id=core-opinfo-crosssiteform-7qn3kx8m) marks a form that another site posts to you, an OAuth provider's `response_mode=form_post` answer. Such a request has no trusted `Origin` and no flow cookie (SameSite Lax keeps it off a cross-site POST), so the pipeline skips the origin check for it, drops whatever credential and flow cookie rode along, and resolves no session: the operation can only read its fields and relay them, typically into a redirect to the GET callback, where the cookie is sent again. It must be `Public` and a `Mutation`; `auth.New` refuses anything else with `ErrBadOperation`. `authhttp` decodes a form body for it without `AcceptForms`, and the OpenAPI document names the form media type.

A sign-in method marks its sign-in operation with [`SignIn: true`](ds:block?id=core-opinfo-signin-5vt8kq2m): every successful call authenticates someone who was not signed in and issues their session. The pipeline does not read it; observers do, so the audit log records your method's sign-ins as `user_signed_in` with no mapping. Leave it false on an operation that signs in only sometimes (a poll that is usually still pending) and on a sign-up, which observers record as its own event.

The requirement is what the call must have before the operation runs, so an operation never needs its own "is anyone signed in" test and cannot forget one:

<!-- ds:block id=core-requirements-tksmmmjf -->
**Public** · [`operation.go:29`](../../operation.go#L29-L29)

```go
"public"
```
<!-- /ds:block hash=b78532 -->

Check: `Path` starts with `/`, `ID` is not empty, `Kind` and `Require` are from the constants. `auth.New` refuses anything else.

## Step 2 — Define the input, the output and the errors

The input and output are plain structs with JSON tags, because every transport encodes them. A session token in a result is an `auth.Token` tagged `json:"-"`; the transport reads the real token from the effect, below. A token the result hands to the caller on purpose (an invite token, a poll token) is an `auth.WireToken`, which encodes as its value in JSON and prints `[redacted]` everywhere else. `auth.New` refuses an output with an `auth.Token` in a field JSON writes (`auth: operation description is not valid: … output field token is an auth.Token …`), because `auth.Token` encodes as `"[redacted]"` and the caller would receive that text.

<!-- ds:block id=devices-addrequest-6jx3zfcj -->
**AddRequest** · [`examples/plugin-tables/devices/devices.go:104-106`](../../examples/plugin-tables/devices/devices.go#L104-L106)

```go
type AddRequest struct {
	Name string `json:"name"`
}
```
<!-- /ds:block hash=966d3d -->

Errors have a stable code, a status and a message for people. A client matches the code and never the message; the status is what HTTP answers; `errors.Is` matches by code, so a copied or wrapped error still matches its sentinel. A plain Go error from an operation is a `500` with no code.

<!-- ds:block id=core-newerror-5gqrhbw2 -->
**NewError** · [`errorcode.go:37-49`](../../errorcode.go#L37-L49)

```go
func NewError(code string, status int, message string) *Error {
	e := &Error{Code: code, Status: status, Message: message}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if prev, dup := registry.byCode[code]; dup {
		if prev.Status != status || prev.Message != message {
			registry.conflicts[code] = append(registry.conflicts[code], e)
		}
		return e
	}
	registry.byCode[code] = e
	return e
}
```
<!-- /ds:block hash=ff8829 -->

<!-- ds:block id=devices-errorgroup-k6gt8gtn -->
**ErrNameInvalid** · [`examples/plugin-tables/devices/devices.go:66-74`](../../examples/plugin-tables/devices/devices.go#L66-L74)

```go
var (
	ErrNameInvalid = auth.NewError("devices.name_invalid", http.StatusBadRequest, "Give the device a name of up to 40 characters.")
	ErrNameTaken   = auth.NewError("devices.name_taken", http.StatusConflict, "You already have a device with that name.")
	ErrTooMany     = auth.NewError("devices.too_many", http.StatusConflict, "Remove a device before adding another.")
	ErrNotFound    = auth.NewError("devices.not_found", http.StatusNotFound, "No such device.")
	// ErrBadMax is a configuration error: auth.New reports it, so a wrong
	// option fails the start instead of refusing every add.
	ErrBadMax = errors.New("devices: the device limit must be at least 1")
)
```
<!-- /ds:block hash=c990b7 -->

Check: the code is prefixed with the plugin's name (`devices.name_taken`), so two plugins cannot collide.

## Step 3 — Define the operation

`auth.Define` binds the description to the function that holds the feature's logic. The function receives the context, the `Call` and the typed input, and returns the typed output. It is the only place the logic exists.

<!-- ds:block id=core-define-jrndwtbj -->
**Define** · [`operation.go:172-174`](../../operation.go#L172-L174)

```go
func Define[In, Out any](info OpInfo, run func(ctx context.Context, c *Call, in In) (Out, error)) *Op[In, Out] {
	return &Op[In, Out]{info: info, run: run}
}
```
<!-- /ds:block hash=7e6603 -->

<!-- ds:block id=devices-new-ebt28tw6 -->
**New** · [`examples/plugin-tables/devices/devices.go:153-162`](../../examples/plugin-tables/devices/devices.go#L153-L162)

```go
func New(opts ...Option) *Plugin {
	p := &Plugin{max: DefaultMax}
	for _, o := range opts {
		o(p)
	}
	p.add = auth.Define(auth.OpInfo{ID: EndpointAdd, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/add"}, p.doAdd)
	p.list = auth.Define(auth.OpInfo{ID: EndpointList, Kind: auth.Query, Require: auth.SignedIn, Path: "/list"}, p.doList)
	p.remove = auth.Define(auth.OpInfo{ID: EndpointRemove, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/remove"}, p.doRemove)
	return p
}
```
<!-- /ds:block hash=0a1d9f -->

The `Call` is what the operation sees of who is calling, the same shape on every transport. `Session` and `User` are nil for a signed-out call; a `SignedIn` operation can rely on both being set.

<!-- ds:block id=core-call-5mhhdsyk -->
**Call** · [`call.go:449-487`](../../call.go#L449-L487)

```go
type Call struct {
	Auth       *Auth
	Op         OpInfo
	Plugin     string
	Transport  Transport
	Client     Client
	Credential Credential
	// Session and User are nil for a signed-out call.
	Session *Session
	User    *User
	Effects *Effects
	// Flow is the client's flow binding; see Request.Flow.
	Flow Token
	// Input is the operation's decoded input, for hooks: a Before hook that
	// restricts sign-up to one mail domain asserts it to the operation's
	// input type. It is a copy; assigning to it changes nothing the
	// operation sees. A Before hook that means to change the input calls
	// SetInput, which is checked against the operation's input type. It is
	// nil until the input is decoded, which is after the rate, origin and
	// session checks.
	Input any

	header func(name string) string
	// ctx is the call's context, for the pipeline's own checks after the
	// operation ran (checkDeviceCap); operations receive ctx as a parameter.
	ctx context.Context
	// redirectOnError is where a failed call sends the browser; see
	// RedirectOnError.
	redirectOnError string
	// inputSet and answered record SetInput and Respond from a Before hook;
	// answer is the value Respond gave.
	inputSet, answered bool
	answer             any
	// annotations are facts the operation recorded for its hooks; see
	// Annotate. A pointer, created with the call by the pipeline, so a copy
	// of the Call (session extras run on one) shares them, and the lock in
	// it is never copied.
	annotations *annotationSet
}
```
<!-- /ds:block hash=0788f5 -->

The operation's body uses the core through `c.Auth`, and inside a mutation every statement joins the mutation's transaction:

<!-- ds:block id=devices-doadd-9uz3f877 -->
**Plugin.doAdd** · [`examples/plugin-tables/devices/devices.go:266-292`](../../examples/plugin-tables/devices/devices.go#L266-L292)

```go
func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in AddRequest) (auth.Done, error) {
	n := utf8.RuneCountInString(in.Name)
	if n == 0 || n > MaxNameLength {
		return auth.Done{}, ErrNameInvalid
	}
	var have int64
	if err := p.a.One(ctx, p.a.Select().Columns(sqlb.Bind(sqlb.Count(), &have)).From(TableDevice).Where(sqlb.Eq(UserID, c.User.ID))); err != nil {
		return auth.Done{}, err
	}
	if have >= int64(p.max) {
		return auth.Done{}, ErrTooMany
	}
	id, err := p.a.NewID(IDPrefix)
	if err != nil {
		return auth.Done{}, err
	}
	_, err = p.a.Exec(ctx, sqlb.NewInsert(p.a.Dialect()).Into(TableDevice).Row(
		sqlb.Set(ID, id), sqlb.Set(UserID, c.User.ID), sqlb.Set(Name, in.Name), sqlb.Set(CreatedAt, p.a.Now()),
	))
	if auth.IsUniqueViolation(err) {
		return auth.Done{}, ErrNameTaken
	}
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}
```
<!-- /ds:block hash=d380a8 -->

Check: a `Mutation` that fails after a write leaves nothing behind; the transaction rolled it back. The sealed `Operation` interface means `auth.Define` is the only way to make one, so nothing can skip the pipeline.

## Step 4 — List the operations, and offer a Go method

`Operations` hands the operations to the transports; a method per operation calls it from Go, through the same pipeline, so a job or a GraphQL resolver is limited and checked exactly like a browser.

<!-- ds:block id=core-operationprovider-7ve9nf64 -->
**OperationProvider** · [`plugin.go:177-179`](../../plugin.go#L177-L179)

```go
type OperationProvider interface {
	Operations() []Operation
}
```
<!-- /ds:block hash=561de1 -->

<!-- ds:block id=devices-operations-aq69swbp -->
**Plugin.Operations** · [`examples/plugin-tables/devices/devices.go:235`](../../examples/plugin-tables/devices/devices.go#L235-L235)

```go
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.add, p.list, p.remove} }
```
<!-- /ds:block hash=dbf381 -->

<!-- ds:block id=devices-add-jykfexuf -->
**Plugin.Add** · [`examples/plugin-tables/devices/devices.go:248-251`](../../examples/plugin-tables/devices/devices.go#L248-L251)

```go
func (p *Plugin) Add(ctx context.Context, name string) error {
	_, err := p.add.Call(ctx, AddRequest{Name: name})
	return err
}
```
<!-- /ds:block hash=7ad92c -->

The Go call takes the request's session and client from the context when `ctx` came from `Auth.WithRequest`, and runs as a signed-out Go call when it did not; its effects reach the request's response. A hook that must not be bypassed by a direct Go call can check `Call.Transport` for `auth.TransportGo`.

Check: `curl -X POST /auth/devices/add` with a session cookie and the app's `Origin` answers `{"ok":true}`; from Go, `p.Add(ctx, "Laptop")` with no request in `ctx` is `auth.ErrSignedOut`.

## Step 5 — Record effects instead of writing headers

An operation that signs a user in must end with a cookie, but it cannot write one: it may be running from a CLI. It records what it wants on `c.Effects` — issue a session, clear it, redirect, bind a flow — and the transport applies the effects after a successful call: a `Set-Cookie`, a token field, a `302`. A failed call's effects are dropped, and a call inside the app's own `Auth.Tx` hands its effects over only when that transaction commits.

The core records the session effect for you in the common case: `Call.SignInProven` signs in the verified owner of an identifier whose control the operation just proved (a code, a link) and records `IssueSessionOf`; `Call.SignInProvenAs` is the same with the profile a first-time user gets (the name they typed), used only when the call creates the user. A sign-in method with a credential of its own calls `c.Auth.CreateSession` and then `c.Effects.IssueSessionOf(sess, tok)`; `plugin/password` is the reference.

A browser flow whose user is on a page, not in a script (an OAuth callback), calls `c.RedirectOnError(url)` before it can fail: a failure from then on answers a redirect to `url` with `?error=<code>` (or `&error=`) instead of a JSON error, and nothing else the failed call recorded reaches the request. An issued session carries `Effect.UserID` and `Effect.SessionID`, so a hook reading `auth.RequestEffects` knows who signed in without the sign-in plugin's result type.

A plugin that keeps a small value in the browser, as better-auth's `ctx.setCookie` does (a second-factor state), records it with `c.Effects.SetCookie(name, value, expiresAt)` and reads it back with `c.Cookie(name)` (or `auth.RequestCookie(ctx, name)` outside a call). It chooses the name ([lower case, at most 32 characters](ds:block?id=core-cookienamepattern-4xk9wq2m), none of the core's own: `session`, `flow`, `session_cache`, `device`, `account_*`), the value and the expiry, never an attribute: authhttp names it beside its own cookies (`__Host-auth_<name>`, under `CookiePrefix` and `CookieDomain`) with the same `HttpOnly`, `Secure`, `Path=/` and `SameSite`. A value the server must trust goes through `c.SetSignedCookie` and `c.SignedCookie`: an HMAC-SHA256 over the name and the value under the key `auth.WithSecret` derives for [`cookies`](ds:block?id=core-keylabelcookies-7nq2wd4k), checked in constant time against the current and every previous secret, so the client can read the value but not change it.

An operation on one of its own rows checks the row belongs to the caller with `c.RequireOwner(ctx, auth.Ownership{Table, ID, Owner}, id)`, better-auth's `requireResourceOwnership`: one indexed read; a missing row and, by default, another user's row both answer `auth.resource_not_found`, so ids cannot be probed. Set `Ownership.Forbidden` (and `NotFound`) to your own errors to tell the two apart as better-auth does.

A plugin that hands a client a value it must not log (a ticket, a key) records it with `c.Effects.Header(name, value)` rather than putting it in the JSON body: authhttp sends the header and lists it in `Access-Control-Expose-Headers`, a CLI or job ignores it, and a Go caller reads it from `auth.RequestEffects`. The tickets plugin in [`examples/plugin-sweeper`](../../examples/plugin-sweeper/README.md) mints a short-lived link and hands it over that way; its insert runs first, and a failed call applies no effect, so a mint that failed hands out nothing:

<!-- ds:block id=tickets-domint-6pz3nw8r -->
**Plugin.doMint** · [`examples/plugin-sweeper/tickets/tickets.go:230-248`](../../examples/plugin-sweeper/tickets/tickets.go#L230-L248)

```go
func (p *Plugin) doMint(ctx context.Context, c *auth.Call, in MintRequest) (MintResult, error) {
	if !strings.HasPrefix(in.Target, "/") || strings.HasPrefix(in.Target, "//") || strings.Contains(in.Target, `\`) {
		return MintResult{}, ErrTargetInvalid // only this site's paths: no open redirect
	}
	id, err := p.a.NewID(IDPrefix)
	if err != nil {
		return MintResult{}, err
	}
	ticket := auth.NewToken()
	expires := p.a.Now().Add(p.ttl)
	if _, err := p.a.Exec(ctx, sqlb.NewInsert(p.a.Dialect()).Into(TableTicket).Row(
		sqlb.Set(ID, id), sqlb.Set(UserID, c.User.ID), sqlb.Set(Hash, auth.HashToken(ticket)),
		sqlb.Set(Target, in.Target), sqlb.Set(ExpiresAt, expires),
	)); err != nil {
		return MintResult{}, err
	}
	c.Effects.Header(HeaderTicket, ticket.Reveal())
	return MintResult{ExpiresAt: expires}, nil
}
```
<!-- /ds:block hash=fffbca -->

Redeeming records a redirect, which authhttp answers with a `302`:

<!-- ds:block id=tickets-doredeem-2kd8vq5m -->
**Plugin.doRedeem** · [`examples/plugin-sweeper/tickets/tickets.go:255-268`](../../examples/plugin-sweeper/tickets/tickets.go#L255-L268)

```go
func (p *Plugin) doRedeem(ctx context.Context, c *auth.Call, in RedeemRequest) (auth.Done, error) {
	var target string
	var expires time.Time
	err := p.a.One(ctx, p.a.Select().Columns(sqlb.Bind(Target, &target), sqlb.Bind(ExpiresAt, &expires)).
		From(TableTicket).Where(sqlb.Eq(Hash, auth.HashToken(in.Ticket.Token()))))
	if errors.Is(err, sqlb.ErrNoRows) || (err == nil && !p.a.Now().Before(expires)) {
		return auth.Done{}, ErrInvalid
	}
	if err != nil {
		return auth.Done{}, err
	}
	c.Effects.Redirect(target)
	return auth.Done{OK: true}, nil
}
```
<!-- /ds:block hash=7a445e -->

Try it (`go run ./plugin-sweeper` in `examples/`, signed up first as its README shows):

```sh
curl -si -b cookies.txt -X POST localhost:8081/auth/tickets/mint -H 'Origin: http://localhost:8081' -d '{"target":"/files/report.txt"}'
curl -si 'localhost:8081/auth/tickets/redeem?ticket=BizjqrBhICjExw_YM4SzDkKc67mqPAEtHME5QyBqORs'
```

```text
HTTP/1.1 200 OK
Access-Control-Expose-Headers: Set-Download-Ticket
Content-Type: application/json
Set-Download-Ticket: BizjqrBhICjExw_YM4SzDkKc67mqPAEtHME5QyBqORs

{"expiresAt":"2026-10-09T03:16:30.854131Z"}
HTTP/1.1 302 Found
Location: /files/report.txt
```

Check: `auth.RequestEffects(ctx)` after a call lists what the transport will apply; the transport's own tests check every `auth.EffectKind` is handled. `TestTickets_GoCallRecordsTheSameEffects` calls the same operation from Go, with no HTTP anywhere, and finds the header effect; `TestTickets_RefusesAnotherSite` finds no ticket header on a refused mint.

## Step 6 — Bound it with rate rules

A `RateLimiter` plugin declares limits per operation, by client address or by the account the input names. The pipeline counts by address before anything else, so a flood costs one counter increment, and by account after the input is decoded and before the transaction opens, so a failed call cannot roll its own count back.

<!-- ds:block id=core-ratelimiter-fw2aw5xj -->
**RateLimiter** · [`ratelimit.go:84-86`](../../ratelimit.go#L84-L86)

```go
type RateLimiter interface {
	RateLimits() []RateRule
}
```
<!-- /ds:block hash=694d5a -->

<!-- ds:block id=core-raterule-m3gp9xc5 -->
**RateRule** · [`ratelimit.go:61-79`](../../ratelimit.go#L61-L79)

```go
type RateRule struct {
	Match  EndpointID
	Key    RateKey
	Limit  int
	Window time.Duration
	// Derive, when set, maps the key's value before counting, so a rule can
	// count a group rather than one value: the first digits of a phone number
	// count every number in a range, the domain of an address counts a whole
	// provider. Optional; a rule without it counts the value itself.
	Derive func(value string) string
	// KeyFunc is what a ByFunc rule counts by, and is required by one; any
	// other key must leave it nil, or New refuses the rule.
	KeyFunc RateKeyFunc
	// Action is what the rule does with a call over Limit: RateBlock (the
	// default, also for ""), RateLog or RateChallenge. New refuses an
	// unknown action, and a RateChallenge rule when no RateChallenger is
	// registered.
	Action RateAction
}
```
<!-- /ds:block hash=399386 -->

<!-- ds:block id=devices-ratelimits-4gjqnrum -->
**Plugin.RateLimits** · [`examples/plugin-tables/devices/devices.go:240-242`](../../examples/plugin-tables/devices/devices.go#L240-L242)

```go
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{Match: EndpointAdd, Key: auth.ByIP, Limit: addLimit, Window: addWindow}}
}
```
<!-- /ds:block hash=bb44be -->

For a `ByIdentifier` rule the input names the account by implementing `Identified`; the password plugin's sign-in request returns the identifier typed, so one account is limited whichever address attacks it.

<!-- ds:block id=core-identified-azphw6e8 -->
**Identified** · [`ratelimit.go:92-94`](../../ratelimit.go#L92-L94)

```go
type Identified interface {
	RateIdentifier() string
}
```
<!-- /ds:block hash=3bb4eb -->

A budget that is neither per address nor per account (per signed-in user, per tenant, per API key, per device) is a [`ByFunc`](ds:block?id=core-ratekey-byfunc-7nq4wz2k) rule: its [`KeyFunc`](ds:block?id=core-ratekeyfunc-3vd8kq6m) derives the key from the call after the input is decoded, the value is hashed like every other key, and an error from it fails the call. See [Rate limits](../concepts/rate-limits.md). The tickets plugin limits minting per signed-in user, whatever address they come from:

<!-- ds:block id=tickets-ratelimits-5nq8wk3d -->
**Plugin.RateLimits** · [`examples/plugin-sweeper/tickets/tickets.go:200-205`](../../examples/plugin-sweeper/tickets/tickets.go#L200-L205)

```go
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{{
		Match: EndpointMint, Key: auth.ByFunc, Limit: MintLimit, Window: MintWindow,
		KeyFunc: func(_ context.Context, c *auth.Call) (string, error) { return c.User.ID, nil },
	}}
}
```
<!-- /ds:block hash=8a8f9d -->

Check: `TestTickets_MintIsLimitedPerUser` mints up to the limit and finds the next one refused with `auth.rate_limited` (429) and a `Retry-After` header.

Check: the refused call is `auth.rate_limited` (429), and `auth.RetryAfter(err)` says how long to wait. Counters live in memory per process until the app passes `auth.WithRateStore` or `auth.WithDBRateStore`; the first counted call logs a warning until it does.

## The pipeline, in order

Every entry point — a transport's `Invoke`, a Go caller's `Call` — runs these steps, and there is no other way to run an operation:

1. Rate limit by address.
2. Origin check, for a mutation with a session cookie: refused before any lookup, so a cross-site request learns nothing, not even whether its session is valid.
3. Session: resolved once per request, then shared by every operation in it.
4. Requirement: `Public`, `SignedIn`, `FreshSignIn`, `PendingSecondFactor` or `SignedInOrPending` (a session, pending or full, for one operation serving both the sign-in step and a signed-in user).
5. Input decoded, rate limit by account.
6. For a mutation with a database, one transaction for everything below.
7. `Before` hooks, the operation, `After` hooks.
8. Effects reach the request, and messages go out, after the commit.

## What can go wrong

- `auth: operation description is not valid: devices "devices.add": path "add" must start with /` — the path, or `empty id`, `unknown kind "…"`, `unknown requirement "…"`.
- `auth: two operations share an id or a route: id "devices.add" is registered by "devices" and by "other"` — or `mutation /devices/add is served by "…" and by "…"`: one id and one route per operation, across every plugin.
- `auth: operation called before auth.New registered its plugin` — the operation was called before the plugin was in `auth.WithPlugins`.
- `auth.signed_out` (401) — the requirement is `SignedIn` and the request has no valid session, or it is pending a second factor.
- `auth.fresh_session_required` (403) — `FreshSignIn`, and the session is older than the fresh window.
- `auth.origin_not_trusted` (403) — a mutation with a session cookie from an origin that is neither the base URL nor in `auth.WithTrustedOrigins`; a missing `Origin` counts as untrusted.
- `auth.bad_request` (400) — the input did not decode.
- `auth.rate_limited` (429) — a rule refused the call; `auth.RetryAfter` gives the window.
- A `500` with no code — the operation returned a plain Go error. Declare the ones a client should see with `auth.NewError`.

## Next

- [Hooks](03-hooks.md): running before and after other plugins' operations.
- [Tables and migrations](05-tables-and-migrations.md): the rows an operation reads and writes.

# API keys: let scripts and integrations act for a user

You will have long-lived keys that a user creates in settings, each with scopes, that a script sends as `Authorization: Bearer ubk_…` to your app's own API. Your routes check the scope, the owner sees when each key was last used, and revoking one ends it on the next request. A client that cannot set that header can send the key in a header you name (`authhttp.APIKeyHeader("X-Api-Key")`) or anywhere else you read with `authhttp.APIKeyFrom(func(r *http.Request) string {…})`; either way the key gets the same checks.

## Before you start

- [First app](../start/first-app.md): an app with a sign-in method (any of [password](password.md), [magic link](magiclink.md), [OAuth](oauth.md)), because keys are created by a signed-in person.
- The plugin is `github.com/ubgo/auth/plugin/apikey`, in the core module. Its README is the [reference](../../plugin/apikey/README.md).
- The runnable program is [`examples/api-keys-and-jwt`](../../examples/api-keys-and-jwt/): a scoped orders API called with keys. The transcript below was captured from it.
- Steps 5 to 10 are also one runnable program, [`examples/api-key-lifecycle`](../../examples/api-key-lifecycle/): live and test keys, list, pause, revoke, a rate limit, a quota, `Verify`, and permissions checked through `accessapikey`, each pinned by an end-to-end test.
- What a key is and is not: a key acts for its owner in your app's routes, with the scopes it was created with. It cannot do anything under `/auth`: change the password, list sessions, mint more keys. That is deliberate; a leaked key must not be able to take the account. A key is shown once, at creation; the database keeps only its SHA-256.

## Step 1 — Declare the scopes and wire the plugin

Scopes are strings your routes check, such as `orders:read`. Declare every one a key may carry; a request for any other is refused at creation, so a typo cannot mint a scope no route checks.

<!-- ds:block id=scopes-ttm5sga6 -->
**Scopes** · [`plugin/apikey/apikey.go:265-267`](../../plugin/apikey/apikey.go#L265-L267)

```go
func Scopes(scopes ...string) Option {
	return func(p *Plugin) { p.scopes = append(p.scopes, scopes...) }
}
```
<!-- /ds:block hash=7ca6b3 -->

<!-- ds:block id=prefix-78234ab4 -->
**Prefix** · [`plugin/apikey/apikey.go:272`](../../plugin/apikey/apikey.go#L272-L272)

```go
func Prefix(prefix string) Option { return func(p *Plugin) { p.prefix = prefix } }
```
<!-- /ds:block hash=c9ce8f -->

<!-- ds:block id=newauth-eczkzgwy -->
**newAuth** · [`examples/api-keys-and-jwt/main.go:176-187`](../../examples/api-keys-and-jwt/main.go#L176-L187)

```go
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			apikey.New(apikey.Scopes(scopeOrdersRead, scopeOrdersWrite)),
			jwt.New(jwt.WithSigningKey(key), jwt.Audience(jwtAudience), jwt.Claims(nameClaim)),
		),
	)
}
```
<!-- /ds:block hash=791822 -->

Check: `auth.New` returns no error. With neither `Scopes` nor `WithPermissions` it fails with "apikey: declare what a key may carry: scopes with apikey.Scopes, permissions with apikey.WithPermissions, or both". An app that decides only by permissions passes `WithPermissions` and no `Scopes`; its keys then carry no scope, and a request for one is refused with `apikey.unknown_scope`.

## Step 2 — Protect your API routes

A route for keys needs a valid credential and then its scope. `authhttp.RequireScope` does both: no credential (or a revoked, expired or unknown key) is `401 auth.signed_out`; a browser session or a key without the scope is `403 auth.missing_scope`.

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

<!-- ds:block id=newhandler-qsj77f3p -->
**newHandler** · [`examples/api-keys-and-jwt/main.go:203-212`](../../examples/api-keys-and-jwt/main.go#L203-L212)

```go
func newHandler(a *auth.Auth, o *orders) http.Handler {
	forKeys := func(scope string, h http.HandlerFunc) http.Handler {
		return authhttp.Middleware(a)(authhttp.RequireScope(scope)(h))
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /api/orders", forKeys(scopeOrdersRead, o.list))
	mux.Handle("POST /api/orders", forKeys(scopeOrdersWrite, o.add))
	return mux
}
```
<!-- /ds:block hash=1caa59 -->

A route that both people in a browser and keys may call uses `RequireUser` instead and asks per request:

<!-- ds:block id=hasscope-zthae65f -->
**HasScope** · [`tokenresolver.go:150-153`](../../tokenresolver.go#L150-L153)

```go
func HasScope(ctx context.Context, scope string) bool {
	scopes, ok := CurrentScopes(ctx)
	return ok && slices.Contains(scopes, scope)
}
```
<!-- /ds:block hash=8be31a -->

<!-- ds:block id=currentscopes-s6bc4b8u -->
**CurrentScopes** · [`tokenresolver.go:137-143`](../../tokenresolver.go#L137-L143)

```go
func CurrentScopes(ctx context.Context) (scopes []string, ok bool) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.APIKeyID == "" {
		return nil, false
	}
	return slices.Clone(st.scopes), true
}
```
<!-- /ds:block hash=8b654d -->

`CurrentScopes` tells "a session, not a key" (`ok` false) apart from "a key with no scopes" (`ok` true, empty list), so an app can let people do everything and keys only what they were given.

Check: `curl localhost:8081/api/orders` with no header answers `401`.

## Step 3 — Create a key

The person signs in, then `POST /auth/apikey/create`. Creating needs a fresh sign-in (one made within the last [10 minutes](ds:block?id=defaultfreshwindow-5mt8jqw7), or `auth.WithFreshWindow`): a key outlives the session that made it, so the person proves it is really them. `expiresInDays` is optional; `0` means never. `expiresIn` gives the expiry in seconds instead (not both: `400 apikey.expiry_conflict`). The per-key limits (`remaining`, refill, rate limit) and `permissions` are server-only: a client cannot send them, and `CreateFor` sets them from Go (Step 7; permissions in Step 10).

<!-- ds:block id=createrequest-mk3ab34c -->
**CreateRequest** · [`plugin/apikey/apikey.go:459-492`](../../plugin/apikey/apikey.go#L459-L492)

```go
type CreateRequest struct {
	// Config names the key configuration (Configuration); "" is
	// DefaultConfig. An unknown one is ErrUnknownConfig.
	Config string `json:"configId,omitempty"`
	Name   string `json:"name,omitempty"`
	// Scopes are the key's scopes; nil (the field left out) takes the
	// configuration's DefaultScopes, an empty list none. omitzero, not
	// omitempty, so a Go client that encodes an empty list still sends it.
	Scopes []string `json:"scopes,omitzero"`
	// Prefix is the key's own prefix after the configuration's, allowed
	// only under AllowKeyPrefix (ErrBadKeyPrefix otherwise).
	Prefix string `json:"prefix,omitempty"`
	// ExpiresInDays is optional; 0 means the key never expires, unless
	// WithExpiry sets a default or a maximum.
	ExpiresInDays int `json:"expiresInDays,omitempty"`
	// ExpiresIn is the expiry in seconds from now, as an alternative to
	// ExpiresInDays (setting both is ErrExpiryConflict). The WithExpiry
	// bounds apply to it measured in days; 0 leaves the choice to ExpiresInDays.
	ExpiresIn int64 `json:"expiresIn,omitempty"`
	// Metadata is a JSON object kept with the key and returned in
	// Key.Metadata; it needs AllowMetadata (ErrMetadataDisabled otherwise).
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// OrganizationID names the organization that owns the key; required by
	// an OrganizationOwned configuration (ErrOrganizationIDRequired) and
	// refused by any other (ErrNotOrganizationConfig). The caller needs the
	// apiKey "create" permission in it.
	OrganizationID string `json:"organizationId,omitempty"`
	// Permissions are the key's resource-to-actions permissions, checked
	// against WithPermissions (ErrBadPermissions); nil takes the
	// configuration's DefaultPermissions. Go only, never read from a client,
	// since permissions are a server-only property: a user must
	// not grant their own key powers the app did not decide.
	Permissions Permissions `json:"-"`
}
```
<!-- /ds:block hash=56e700 -->

```sh
curl -s -c ck.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"name":"importer","scopes":["orders:read","orders:write"],"expiresInDays":90}'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' -d '{"name":"dashboard","scopes":["orders:read"]}'
```

```json
{"user":{"id":"usr_ggbadjf7fyqsz52xzmgxsovd","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"key":{"id":"key_eetlekabc7fzs5fvwrie3wrx","name":"importer","hint":"ubk_SU8V","scopes":["orders:read","orders:write"],"createdAt":"2026-10-01T05:16:21.315247Z","lastUsedAt":null,"expiresAt":"2026-12-30T05:16:21.315247Z"},"secret":"ubk_SU8VcaGQaBXbfbpvRt85kRTSNhb9B6iAMM8G_PjAR9o"}
{"key":{"id":"key_6sjnbm6x6zprqedczvnveskb","name":"dashboard","hint":"ubk_VFWv","scopes":["orders:read"],"createdAt":"2026-10-01T05:16:21.337113Z","lastUsedAt":null,"expiresAt":null},"secret":"ubk_VFWvxSlDCAhib922VYVqD-ec-5RpJQJbgUB6Hf-2spw"}
```

The answer is the only time the key is shown. Store `secret` where the script will read it; the `hint` is what lists show later.

<!-- ds:block id=createresult-94drbcpc -->
**CreateResult** · [`plugin/apikey/apikey.go:498-501`](../../plugin/apikey/apikey.go#L498-L501)

```go
type CreateResult struct {
	Key    Key    `json:"key"`
	Secret string `json:"secret"`
}
```
<!-- /ds:block hash=4c4a50 -->

A scope that was not declared:

```sh
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' -d '{"name":"typo","scopes":["orders:delete"]}'
```

```json
{"error":{"code":"apikey.unknown_scope","message":"A scope in this request does not exist."}}
```

From Go, for the signed-in user of the request in `ctx`:

<!-- ds:block id=plugin-create-frxwwt3z -->
**Plugin.Create** · [`plugin/apikey/apikey.go:595-597`](../../plugin/apikey/apikey.go#L595-L597)

```go
func (p *Plugin) Create(ctx context.Context, in CreateRequest) (CreateResult, error) {
	return p.create.Call(ctx, in)
}
```
<!-- /ds:block hash=b05746 -->

Check: `secret` starts with [`ubk_`](ds:block?id=defaultprefix-rgykkrgm) and `hint` is the prefix plus [4](ds:block?id=hintextra-tm73uvqy) characters of it.

## Step 4 — Use the key from a script

The script sends the key as a bearer token. No cookie, no origin header, no CSRF concern: a browser never attaches a bearer token by itself.

```sh
curl -s -X POST localhost:8081/api/orders -H 'Authorization: Bearer ubk_SU8VcaGQaBXbfbpvRt85kRTSNhb9B6iAMM8G_PjAR9o' -d '{"item":"coffee beans"}'
curl -s localhost:8081/api/orders -H 'Authorization: Bearer ubk_VFWvxSlDCAhib922VYVqD-ec-5RpJQJbgUB6Hf-2spw'
```

```json
{"id":1,"item":"coffee beans"}
{"userId":"usr_ggbadjf7fyqsz52xzmgxsovd","orders":[{"id":1,"item":"coffee beans"}]}
```

The read-only key lists but cannot write; the browser's session is refused on the API; and the key is refused under `/auth`:

```sh
curl -s -X POST localhost:8081/api/orders -H 'Authorization: Bearer ubk_VFWvxSlDCAhib922VYVqD-ec-5RpJQJbgUB6Hf-2spw' -d '{"item":"more"}'
curl -s -b ck.txt localhost:8081/api/orders
curl -s -X POST localhost:8081/auth/apikey/create -H 'Authorization: Bearer ubk_SU8VcaGQaBXbfbpvRt85kRTSNhb9B6iAMM8G_PjAR9o' -d '{"name":"more","scopes":["orders:read"]}'
curl -s localhost:8081/auth/apikey/list -H 'Authorization: Bearer ubk_SU8VcaGQaBXbfbpvRt85kRTSNhb9B6iAMM8G_PjAR9o'
```

```json
{"error":{"code":"auth.missing_scope","message":"This key does not allow this."}}
{"error":{"code":"auth.missing_scope","message":"This key does not allow this."}}
{"error":{"code":"auth.api_key_refused","message":"This cannot be done with an API key."}}
{"error":{"code":"auth.api_key_refused","message":"This cannot be done with an API key."}}
```

An unknown key is simply signed out, the same answer as a revoked or expired one, so a key cannot be probed:

```sh
curl -s localhost:8081/api/orders -H 'Authorization: Bearer ubk_not_a_real_key'
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Check: a request with the key reaches the route as the key's owner (`authhttp.MustUser(r).ID` is the user who created it).

## Step 5 — List and revoke

The owner's list shows every key without its secret, with `lastUsedAt`, which is written at most once a [minute](ds:block?id=usedevery-h6p3zwfn) per key so a busy key does not write on every request:

<!-- ds:block id=key-7qag4n8t -->
**Key** · [`plugin/apikey/apikey.go:506-536`](../../plugin/apikey/apikey.go#L506-L536)

```go
type Key struct {
	ID string `json:"id"`
	// Config is the configuration the key was made under.
	Config string `json:"configId"`
	Name   string `json:"name,omitempty"`
	// Prefix is the key's prefix in clear: the configuration's and, under
	// AllowKeyPrefix, its own. Empty for a key made before migration 0003.
	Prefix     string     `json:"prefix"`
	Hint       string     `json:"hint"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	// Disabled is true while the owner has paused the key (UpdateRequest
	// .Disabled); a disabled key is refused like an unknown one.
	Disabled bool `json:"disabled"`
	// Metadata is the owner's JSON object, or null.
	Metadata json.RawMessage `json:"metadata"`
	// OrganizationID is the owning organization of an organization-owned
	// key, "" for a user's key.
	OrganizationID string `json:"organizationId"`
	// Permissions are the key's permissions (WithPermissions), or null.
	Permissions Permissions `json:"permissions"`
	// Limits are the key's rate limit and quota; Remaining is live.
	Limits Limits `json:"limits"`
	// UpdatedAt is when the key last changed: made, edited, or used (a use
	// stamps it with last_used_at, at most once a minute, or with the
	// counters of a key that has limits). Nil for a key unchanged since
	// before migration 0003.
	UpdatedAt *time.Time `json:"updatedAt"`
}
```
<!-- /ds:block hash=1d4a1d -->

```sh
curl -s -b ck.txt localhost:8081/auth/apikey/list
```

```json
{"keys":[{"id":"key_eetlekabc7fzs5fvwrie3wrx","name":"importer","hint":"ubk_SU8V","scopes":["orders:read","orders:write"],"createdAt":"2026-10-01T05:16:21.315247Z","lastUsedAt":"2026-10-01T05:16:21.460919Z","expiresAt":"2026-12-30T05:16:21.315247Z"},{"id":"key_6sjnbm6x6zprqedczvnveskb","name":"dashboard","hint":"ubk_VFWv","scopes":["orders:read"],"createdAt":"2026-10-01T05:16:21.337113Z","lastUsedAt":"2026-10-01T05:16:21.48163Z","expiresAt":null}]}
```

Revoking deletes the row; the next request with the key is signed out. Revoking an unknown id, or another user's key, is the same `404 apikey.not_found`.

```sh
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/revoke -H 'Origin: http://localhost:8081' -d '{"id":"key_eetlekabc7fzs5fvwrie3wrx"}'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/revoke -H 'Origin: http://localhost:8081' -d '{"id":"key_eetlekabc7fzs5fvwrie3wrx"}'
curl -s localhost:8081/api/orders -H 'Authorization: Bearer ubk_SU8VcaGQaBXbfbpvRt85kRTSNhb9B6iAMM8G_PjAR9o'
```

```json
{"ok":true}
{"error":{"code":"apikey.not_found","message":"Not found."}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

From Go:

<!-- ds:block id=plugin-list-ybrwtmbe -->
**Plugin.List** · [`plugin/apikey/apikey.go:602-605`](../../plugin/apikey/apikey.go#L602-L605)

```go
func (p *Plugin) List(ctx context.Context) ([]Key, error) {
	r, err := p.list.Call(ctx, ListRequest{})
	return r.Keys, err
}
```
<!-- /ds:block hash=1becf6 -->

<!-- ds:block id=plugin-revoke-6h36sj58 -->
**Plugin.Revoke** · [`plugin/apikey/apikey.go:626-629`](../../plugin/apikey/apikey.go#L626-L629)

```go
func (p *Plugin) Revoke(ctx context.Context, id string) error {
	_, err := p.revoke.Call(ctx, RevokeRequest{ID: id})
	return err
}
```
<!-- /ds:block hash=e397ff -->

Check: after the revoke, the API answers `401 auth.signed_out` to the old key.

A settings page with many keys pages and sorts the list: `GET /auth/apikey/list?limit=20&offset=40&sortBy=name&sort=desc` answers `{"keys": […], "total": 57, "limit": 20, "offset": 40}`; `sortBy` is one of `createdAt`, `name`, `lastUsedAt`, `expiresAt`, `sort` is `asc` or `desc`, and a bad value is `400 apikey.bad_list`. Without options the list is the whole set, oldest first, and the Go `List(ctx)` keeps returning the plain slice; `ListKeys(ctx, ListRequest)` returns the page:

<!-- ds:block id=listrequest-h6wn3kqt -->
**ListRequest** · [`plugin/apikey/apikey.go:543-558`](../../plugin/apikey/apikey.go#L543-L558)

```go
type ListRequest struct {
	// Config keeps the keys of one configuration; "" lists them all.
	Config string `json:"configId,omitempty"`
	// OrganizationID lists that organization's keys instead of the
	// caller's own; the caller needs the apiKey "read" permission in it.
	OrganizationID string `json:"organizationId,omitempty"`
	// Limit is the page size; "" or "0" is no limit.
	Limit string `json:"limit,omitempty"`
	// Offset is how many keys to skip; "" is none.
	Offset string `json:"offset,omitempty"`
	// SortBy is one of SortByValues; "" is SortByCreatedAt.
	SortBy string `json:"sortBy,omitempty"`
	// Sort is SortAsc or SortDesc; "" is SortAsc. A sort on a nullable field
	// (lastUsedAt, expiresAt) puts the NULL rows where the engine puts them.
	Sort string `json:"sort,omitempty"`
}
```
<!-- /ds:block hash=fd3719 -->

One key by id, for a detail page, is `GET /auth/apikey/get?id=key_…` (`Plugin.Get(ctx, id)`); another user's key and an unknown id are both `404 apikey.not_found`, so ids cannot be probed.

Check: `TestTokensAPIKey_GetAndListPaging`.

## Step 6 — Rename, pause, re-expire, and label a key

A key that is wrong in one detail no longer has to be revoked and made again. `POST /auth/apikey/update` renames it, gives it a new expiry (under the same `WithExpiry` rules as create), pauses and resumes it, and replaces its metadata. A paused key is refused exactly like an unknown one, so a script whose key was paused sees `401 auth.signed_out`, nothing more (unless the app opted into `apikey.DistinctErrors`, Step 9). Like create, update needs a fresh sign-in: resuming a key or extending its expiry hands out access that outlives the session.

<!-- ds:block id=updaterequest-e6tn4yvb -->
**UpdateRequest** · [`plugin/apikey/limits.go:204-228`](../../plugin/apikey/limits.go#L204-L228)

```go
type UpdateRequest struct {
	ID string `json:"id"`
	// Config, when set, must be the key's configuration (ErrNotFound
	// otherwise). The key's own configuration's rules apply either way.
	Config string `json:"configId,omitempty"`
	// Name renames the key; under RequireName a blank name is refused.
	Name *string `json:"name,omitempty"`
	// ExpiresInDays sets a new expiry from now, under the same WithExpiry
	// rules as create: 0 is "never" unless a default or a maximum applies.
	ExpiresInDays *int `json:"expiresInDays,omitempty"`
	// ExpiresIn sets a new expiry in seconds from now, under the same rules
	// as CreateRequest.ExpiresIn; setting it with ExpiresInDays is
	// ErrExpiryConflict.
	ExpiresIn *int64 `json:"expiresIn,omitempty"`
	// Disabled pauses the key (true) or resumes it (false). A disabled key
	// is refused exactly like an unknown one.
	Disabled *bool `json:"disabled,omitempty"`
	// Metadata replaces the key's metadata; needs AllowMetadata.
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// Scopes replaces the key's scopes, each one declared with Scopes
	// (ErrUnknownScope otherwise); nil leaves them, an empty list clears
	// them (omitzero keeps that empty list on the wire). Widening a key's
	// scopes needs the same fresh sign-in as minting one with them.
	Scopes []string `json:"scopes,omitzero"`
}
```
<!-- /ds:block hash=2f5331 -->

```sh
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/update -H 'Origin: http://localhost:8081' -d '{"id":"key_6sjnbm6x6zprqedczvnveskb","name":"dashboard (paused)","disabled":true}'
curl -s localhost:8081/api/orders -H 'Authorization: Bearer ubk_VFWvxSlDCAhib922VYVqD-ec-5RpJQJbgUB6Hf-2spw'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/update -H 'Origin: http://localhost:8081' -d '{"id":"key_6sjnbm6x6zprqedczvnveskb","disabled":false,"expiresInDays":30}'
```

```json
{"id":"key_6sjnbm6x6zprqedczvnveskb","name":"dashboard (paused)","hint":"ubk_VFWv","scopes":["orders:read"],"createdAt":"…","lastUsedAt":"…","expiresAt":null,"disabled":true,"metadata":null,"limits":{"rateMax":0,"rateWindowSeconds":0,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"id":"key_6sjnbm6x6zprqedczvnveskb","name":"dashboard (paused)","hint":"ubk_VFWv","scopes":["orders:read"],"createdAt":"…","lastUsedAt":"…","expiresAt":"…","disabled":false,"metadata":null,"limits":{"rateMax":0,"rateWindowSeconds":0,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0}}
```

Metadata is a JSON object the owner (or your app) attaches to a key, such as the environment it is for or the integration that made it, returned in `Key.Metadata` and never read by the library. It is off unless you pass `apikey.AllowMetadata()`, so an app that never looks at it does not store whatever a client sends; at most [4096](ds:block?id=maxmetadatalength-n7rc2hwq) bytes, and anything but an object is `400 apikey.bad_metadata`.

From Go, for the signed-in user of the request in `ctx`:

<!-- ds:block id=plugin-update-c3zp7mkd -->
**Plugin.Update** · [`plugin/apikey/limits.go:235-237`](../../plugin/apikey/limits.go#L235-L237)

```go
func (p *Plugin) Update(ctx context.Context, in UpdateRequest) (Key, error) {
	return p.update.Call(ctx, in)
}
```
<!-- /ds:block hash=945fa2 -->

Check: after `disabled: true` the API answers `401` to the key; after `disabled: false` it works again, and `GET /auth/apikey/list` shows `"disabled": false`.

A key's scopes change the same way: `"scopes": ["orders:read", "orders:write"]` replaces them (every scope declared with `apikey.Scopes`, or `400 apikey.unknown_scope`), `"scopes": []` clears them, and the new set applies on the key's next request. Widening a key needs the same fresh sign-in as minting one.

## Step 7 — Throttle keys and give them a quota

A key may carry a rate limit (at most `RateMax` requests in any `RateWindow`) and a quota (`Remaining` uses, optionally reset to `RefillAmount` every `RefillInterval`), enforced when the key is resolved, before your route runs, with guarded writes so two requests at once never exceed either. A key past its rate limit is `429 auth.rate_limited` with a `Retry-After` header, the same answer as the core's own rate rules; one that used up its quota is `429 apikey.usage_exceeded`. Both say why: the key was valid, so the caller already holds it.

<!-- ds:block id=limits-a9fq3wkm -->
**Limits** · [`plugin/apikey/limits.go:104-111`](../../plugin/apikey/limits.go#L104-L111)

```go
type Limits struct {
	RateMax    int
	RateWindow time.Duration
	// Remaining uses; nil means unlimited. In a Key it is the live count.
	Remaining      *int
	RefillAmount   int
	RefillInterval time.Duration
}
```
<!-- /ds:block hash=1bea72 -->

Keys made through the create route take the plugin's `apikey.DefaultLimits`; a key made from Go takes the limits you pass. `CreateFor` is the Go-only way to mint a key for a user without their session: a provisioning job, an import, a key issued when a customer subscribes. The scope list, the cap and the name and expiry rules still apply.

<!-- ds:block id=plugin-createfor-h8wd5qrv -->
**Plugin.CreateFor** · [`plugin/apikey/limits.go:250-266`](../../plugin/apikey/limits.go#L250-L266)

```go
func (p *Plugin) CreateFor(ctx context.Context, userID string, in CreateRequest, l Limits) (CreateResult, error) {
	s, ok := p.config(in.Config)
	if !ok {
		return CreateResult{}, ErrUnknownConfig
	}
	if err := l.validate(); err != nil {
		return CreateResult{}, err
	}
	if _, err := p.core.User(ctx, userID); err != nil {
		return CreateResult{}, err
	}
	o, err := p.creator(ctx, s, userID, in.OrganizationID)
	if err != nil {
		return CreateResult{}, err
	}
	return p.mint(ctx, s, o, in, l, true)
}
```
<!-- /ds:block hash=22e84a -->

<!-- ds:block id=plugin-setlimits-s5yb9nxt -->
**Plugin.SetLimits** · [`plugin/apikey/limits.go:273-292`](../../plugin/apikey/limits.go#L273-L292)

```go
func (p *Plugin) SetLimits(ctx context.Context, id string, l Limits) error {
	if err := l.validate(); err != nil {
		return err
	}
	r, err := p.keyByID(ctx, id)
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	now := p.core.Now()
	set := append(limitAssignments(l.withDefaults()), sqlb.Set(KeyRateCount, int64(0)), sqlb.Set(KeyRateWindowStart, (*time.Time)(nil)), sqlb.Set(KeyLastRefillAt, (*time.Time)(nil)), sqlb.Set(KeyUpdated, &now))
	// The row was just read, so an update that changes nothing means a
	// concurrent revoke, after which there is nothing left to limit.
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableKey).Set(set...).Where(sqlb.Eq(KeyID, id))); err != nil {
		return err
	}
	return p.cacheDrop(ctx, r.hash)
}
```
<!-- /ds:block hash=bf37e2 -->

The key's view shows the live state: `limits.remaining` goes down with each use and comes back at the refill.

```json
{"id":"key_…","name":"metered","hint":"ubk_…","scopes":["orders:read"],"createdAt":"…","lastUsedAt":null,"expiresAt":null,"disabled":false,"metadata":{"plan":"starter"},"limits":{"rateMax":60,"rateWindowSeconds":60,"remaining":1000,"refillAmount":1000,"refillIntervalSeconds":2592000}}
```

A provisioning job that gives each new customer a key with a monthly quota and permissions:

<!-- ds:block id=lifecycle-provisionkey-h2r6tq9m -->
**provisionKey** · [`examples/api-key-lifecycle/main.go:139-146`](../../examples/api-key-lifecycle/main.go#L139-L146)

```go
func provisionKey(ctx context.Context, ak *apikey.Plugin, userID string, quota int) (apikey.CreateResult, error) {
	return ak.CreateFor(ctx, userID, apikey.CreateRequest{
		Config:      configLive,
		Name:        "billing sync",
		Scopes:      []string{scopeOrdersRead},
		Permissions: apikey.Permissions{resourceOrders: {actionRead, actionRefund}},
	}, apikey.Limits{Remaining: &quota, RefillAmount: quota, RefillInterval: quotaPeriod})
}
```
<!-- /ds:block hash=6337ed -->

A test key in the example inherits its configuration's limit of three requests a minute; the fourth is refused with the wait in `Retry-After`:

```sh
for i in 1 2 3 4; do curl -s -i localhost:8081/api/orders -H "Authorization: Bearer $TEST_KEY" | grep -E '^HTTP|^Retry-After|^\{'; done
```

```text
HTTP/1.1 200 OK
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
HTTP/1.1 200 OK
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
HTTP/1.1 200 OK
{"userId":"usr_rynh7os2cbui6yk6c2w7cjwe","orders":[]}
HTTP/1.1 429 Too Many Requests
Retry-After: 60
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

Check: `TestLifecycle_TestKeysAreThrottled` and `TestLifecycle_ProvisionedKeyHasAQuota` in the example; `TestTokensAPIKey_RateLimitAndQuota` in the integration suite walks a 3-per-minute key through its fourth request and a two-use key through its refill; `TestTokensAPIKey_LimitsHoldUnderConcurrency` fires twenty requests at once on Postgres and MySQL and sees exactly `RateMax` pass.

## Step 8 — Verify a key the app received elsewhere

Not every key arrives in an `Authorization` header: a webhook signs its payload with one, a websocket message carries one, a CLI passes one as a flag. `Plugin.Verify(ctx, secret, scopes...)` checks such a key from Go, through the same resolution a bearer request gets, so the key's expiry, disabled flag, rate limit, quota and its owner's standing all apply and the use is counted:

<!-- ds:block id=verification-k9zr4wtm -->
**Verification** · [`plugin/apikey/apikey.go:1186-1194`](../../plugin/apikey/apikey.go#L1186-L1194)

```go
type Verification struct {
	Valid  bool
	Reason error
	Key    *Key
	UserID string
	// OrganizationID is the owner of an organization-owned key, whose
	// UserID is "".
	OrganizationID string
}
```
<!-- /ds:block hash=4261df -->

`Valid` is false for every key problem, with `Reason` saying which the way the API would: `auth.ErrSignedOut` for an unknown, revoked, expired or disabled key (or a banned owner), `auth.ErrRateLimited`, `apikey.ErrUsageExceeded`, and `apikey.ErrScopeMissing` when a scope you asked for is not on the key. The error return is only an infrastructure failure. `Verify` is Go only: it is the app's check, and a client never needs it.

In the example, a webhook receiver checks the key it was handed:

<!-- ds:block id=lifecycle-checkwebhookkey-b7d3nf5x -->
**checkWebhookKey** · [`examples/api-key-lifecycle/main.go:174-183`](../../examples/api-key-lifecycle/main.go#L174-L183)

```go
func checkWebhookKey(ctx context.Context, ak *apikey.Plugin, secret string) (string, error) {
	v, err := ak.Verify(ctx, secret, scopeOrdersWrite)
	if err != nil {
		return "", err
	}
	if !v.Valid {
		return "", v.Reason
	}
	return v.UserID, nil
}
```
<!-- /ds:block hash=e68556 -->

Check: `TestTokensAPIKey_Verify`, and `TestLifecycle_VerifyAKeyFromElsewhere` in the example (a key without the scope is `apikey.ErrScopeMissing`, a revoked one `auth.ErrSignedOut`).

## Step 9 — Live and test keys, a lookup cache, and opt-in behaviours

A product with live and test environments wants two kinds of key that look different, carry different scopes and limits, and live in the same table. Declare each as a configuration; the plugin's own options are the `default` configuration, and each `apikey.Configuration` starts from them, for example `apikey.Configuration("live", apikey.Prefix("sk_live_"), apikey.Scopes("orders:write"))` beside `apikey.Configuration("test", apikey.Prefix("sk_test_"))`:

<!-- ds:block id=configuration-x4kd8pwz -->
**Configuration** · [`plugin/apikey/config.go:113-120`](../../plugin/apikey/config.go#L113-L120)

```go
func Configuration(id string, opts ...Option) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "apikey.Configuration", opts) {
			return
		}
		p.specs = append(p.specs, configSpec{id: id, opts: opts})
	}
}
```
<!-- /ds:block hash=1e9f7e -->

A create names the configuration with `configId` (none means `default`); the key records it, and list, get, update and revoke accept `configId` to keep to one configuration. An unknown `configId` is `400 apikey.unknown_config` rather than a fall back to the default configuration: a typo should not mint a key under the wrong prefix and limits. `ak.VerifyFor(ctx, "live", secret)` checks a key that must be a live one, refusing a test key before its counters move.

The example declares both, with the lookup cache, metadata and permissions on top:

<!-- ds:block id=lifecycle-newauth-w3m7cpzd -->
**newAuth** · [`examples/api-key-lifecycle/main.go:112-132`](../../examples/api-key-lifecycle/main.go#L112-L132)

```go
func newAuth(db *sql.DB, m email.Mailer, ac *access.AccessControl) (*auth.Auth, *apikey.Plugin, error) {
	ak := apikey.New(
		apikey.Scopes(scopeOrdersRead, scopeOrdersWrite),
		apikey.AllowMetadata(),
		apikey.WithCache(apikey.NewMemoryCache(), 0),
		apikey.WithPermissions(accessapikey.New(ac)),
		apikey.Configuration(configLive, apikey.Prefix(prefixLive)),
		apikey.Configuration(configTest, apikey.Prefix(prefixTest),
			apikey.DefaultLimits(apikey.Limits{RateMax: testRateMax, RateWindow: testRateWindow})),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			ak,
		),
	)
	return a, ak, err
}
```
<!-- /ds:block hash=579688 -->

```sh
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"configId":"live","name":"importer","scopes":["orders:read"],"metadata":{"team":"ops"}}'
curl -s -b ck.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"configId":"test","name":"ci","scopes":["orders:read"]}'
```

```json
{"key":{"id":"key_3llc4pzb6c3qmkcy23bkjsa7","configId":"live","name":"importer","prefix":"sk_live_","hint":"sk_live_HkcH","scopes":["orders:read"],"createdAt":"2026-10-09T03:14:31.731803Z","lastUsedAt":null,"expiresAt":null,"disabled":false,"metadata":{"team":"ops"},"organizationId":"","permissions":null,"limits":{"rateMax":0,"rateWindowSeconds":0,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0},"updatedAt":"2026-10-09T03:14:31.731803Z"},"secret":"sk_live_HkcH5tYQZaVpDembINb44tBK7o05mxwWidu6aDOYBxk"}
{"key":{"id":"key_batk7oaxxhtdk42f52p2k5mj","configId":"test","name":"ci","prefix":"sk_test_","hint":"sk_test_FXrZ","scopes":["orders:read"],"createdAt":"2026-10-09T03:14:31.742703Z","lastUsedAt":null,"expiresAt":null,"disabled":false,"metadata":null,"organizationId":"","permissions":null,"limits":{"rateMax":3,"rateWindowSeconds":60,"remaining":null,"refillAmount":0,"refillIntervalSeconds":0},"updatedAt":"2026-10-09T03:14:31.742703Z"},"secret":"sk_test_FXrZfoeJcn3oIbIFzQnRa6r5VSlMkW7eCIMhFWrZEic"}
```

Check: `TestLifecycle_ListRenamePauseRevoke` (an unknown `configId` is `apikey.unknown_config`).

The options that change the rest of the API-key behaviour, each off by default:

| Option | What changes, and the cost |
|---|---|
| `apikey.WithCache(apikey.NewMemoryCache(), 0)` | A key is read from the cache for up to a minute (at most 15) instead of the database. Limits still run against the database. Revoke and update drop the entry, but a key revoked on another instance with an in-process cache works until its entry expires; use a shared store (any `apikey.Cache`) when that matters |
| `apikey.DistinctErrors()` | A refused key answers `401 apikey.key_disabled`, `apikey.key_expired`, `apikey.invalid_owner`, or `apikey.owner_blocked` for a banned owner. Whoever holds a stolen key learns its state, and the 401 applies even on routes that serve anonymous callers |
| `apikey.RejectUnknownKeys()` with a prefix holding a `.` (`apikey.Prefix("sk.live_")`) | A bearer token with the key prefix that is no live key answers `401 apikey.invalid_key` instead of passing through signed out; without `DistinctErrors` a revoked, expired or disabled key and a banned owner's key answer the same code, so the answer still says nothing about why. `auth.New` refuses it with a prefix made only of base64url characters (`ErrPrefixNotDistinct`), because a session token could then start with the prefix and would be refused as a key. The cost: a bad key fails even a route that serves anonymous callers |
| `apikey.DeleteSpentKeys()` | The row goes the next time the key is presented, so the owner no longer sees why it stopped |
| `apikey.DeferUpdates()` | The last-use stamp runs after the check through `auth.WithBackground`'s runner; the counters stay on the request |
| `apikey.StampEveryUse()` | Every use writes `last_used_at` and `updated_at` on the request, guarded on the key's id, so a key revoked while its request was checked is refused even when it has no limits; one write per request |
| `apikey.PreCheck(fn)` | `fn(ctx, key)` runs before the lookup; false refuses the key |
| `apikey.AllowKeyPrefix(32)` | A create may add its own prefix after the configuration's (`sk_live_acme_…`) |
| `apikey.DefaultScopes(...)` | A create without `scopes` gets these; `apikey.DefaultPermissions(...)` does the same for permissions (Step 10) |

Check: `TestTokensAPIKey_Configurations`, `TestTokensAPIKey_Cache`, `TestTokensAPIKey_PreCheckAndDistinctErrors`, `TestTokensAPIKey_DeleteSpentKeys`, `TestTokensAPIKey_DeferUpdates`, `TestP3Tokens_APIKeyStampEveryUse`.

## Step 10 — Keys owned by an organization, and permissions on keys

Both are off by default. An organization-owned key belongs to an organization rather than to the member who made it, so it survives that member leaving or deleting their account: a CI token for the whole team. Mark a configuration with `apikey.OrganizationOwned()`, give it a prefix of its own, and tell the plugin how to ask an organization about a member with `apikey.WithOrganizations`. The core cannot import [`plugin/organization`](organization.md) (its own module), so it asks through a one-method interface:

<!-- ds:block id=organizationowned-b8rn3vqd -->
**OrganizationOwned** · [`plugin/apikey/org.go:90`](../../plugin/apikey/org.go#L90-L90)

```go
func OrganizationOwned() Option { return func(p *Plugin) { p.orgOwned = true } }
```
<!-- /ds:block hash=507097 -->

```go
org := organization.New(organization.WithAccessControl(ac), organization.WithRoles(roles))
ak := apikey.New(apikey.Scopes("deploy"), apikey.WithOrganizations(org),
	apikey.Configuration("team", apikey.Prefix("ubo_"), apikey.OrganizationOwned()))
```

`*organization.Plugin` implements that interface, `APIKeyPermission(ctx, orgID, userID, action) (member, allowed bool, err error)`: whether the user is a member, and whether their role grants `action` on the `apiKey` resource. Build `ac` from `organization.DefaultStatements` plus `apikey.Statements()` (`apiKey: create, read, update, delete`) and grant per role, for example an admin all four and a member `read`; the organization's creator role passes every action. An app with organizations of its own writes that one method, or wraps a function in `apikey.OrganizationsFunc`.

```sh
curl -s -X POST localhost:8080/auth/apikey/create -H 'Content-Type: application/json' \
  -b cookies.txt -d '{"configId":"team","organizationId":"org_…","name":"ci"}'
curl -s 'localhost:8080/auth/apikey/list?organizationId=org_…' -b cookies.txt
```

Get, update and revoke take the key id as before and check the caller's role on the key's organization (`read`, `update`, `delete`). A member without the action gets `403 apikey.organization_permission`; a create or list naming an organization the caller is not in gets `403 apikey.not_organization_member`, while get, update and revoke of such a key answer `404 apikey.not_found`, so a key id cannot be probed. An organization key never signs anyone in, because no one user stands behind it: present it as a bearer token and the request is signed out before its quota moves. Check it where it arrives with `ak.Verify(ctx, secret, scopes...)`, whose `Verification.OrganizationID` names the owner. When the app deletes an organization, delete its keys too, from `organization.Hooks{AfterDeleteOrg: …}` with `ak.DeleteOrganizationKeys(ctx, org.ID)`.

Permissions are a richer alternative to scopes: a key carries a resource-to-actions set (`apikey.Permissions`, the shape of [`plugin/access`](access.md)'s), such as `{"orders": ["read"]}`. Declare the vocabulary with `apikey.WithPermissions(apikey.Vocabulary{"orders": {"read", "write"}})`; the argument is an `apikey.PermissionChecker` (`Check` what a key may carry, `Grants` a check), so a `plugin/access` control plugs in as `accessapikey.New(ac)` and any other model the same way and optionally a default with `apikey.DefaultPermissions(...)`. They are set from Go only (`CreateRequest.Permissions`, which a JSON body never fills, and `ak.SetPermissions(ctx, id, perms)`), because a user must not grant their own key powers the app did not decide. Check them on a route with `ak.Authorize`:

<!-- ds:block id=plugin-authorize-t5kd2wny -->
**Plugin.Authorize** · [`plugin/apikey/org.go:378-395`](../../plugin/apikey/org.go#L378-L395)

```go
func (p *Plugin) Authorize(ctx context.Context, want Permissions) error {
	sess, ok := auth.CurrentSession(ctx)
	if !ok || sess.APIKeyID == "" {
		return ErrPermissionDenied
	}
	r, err := p.keyByID(ctx, sess.APIKeyID)
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	s, _ := p.config(r.configID)
	if !s.grants(r.k.Permissions, want) {
		return ErrPermissionDenied
	}
	return nil
}
```
<!-- /ds:block hash=0d97cf -->

In the example the vocabulary is the app's `plugin/access` statements, adapted by `accessapikey.New(ac)` (see `newAuth` in Step 9), and a refund route asks for one permission:

<!-- ds:block id=lifecycle-statements-q8vn2kxe -->
**statements** · [`examples/api-key-lifecycle/main.go:103`](../../examples/api-key-lifecycle/main.go#L103-L103)

```go
var statements = access.Statements{resourceOrders: {actionRead, actionRefund}}
```
<!-- /ds:block hash=f7bd70 -->

<!-- ds:block id=lifecycle-newhandler-t4kx8b2n -->
**newHandler** · [`examples/api-key-lifecycle/main.go:156-165`](../../examples/api-key-lifecycle/main.go#L156-L165)

```go
func newHandler(a *auth.Auth, ak *apikey.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	api := authhttp.Middleware(a)
	mux.Handle("GET /api/orders", api(authhttp.RequireScope(scopeOrdersRead)(http.HandlerFunc(listOrders))))
	mux.Handle("POST /api/refunds", api(authhttp.RequireFunc(func(r *http.Request) error {
		return ak.Authorize(r.Context(), apikey.Permissions{resourceOrders: {actionRefund}})
	})(http.HandlerFunc(refund))))
	return mux
}
```
<!-- /ds:block hash=566786 -->


or, for a key received elsewhere, with `ak.VerifyPermissions(ctx, secret, perms)`. A key without permissions is refused (`apikey.permission_denied`). So is every check on a key whose stored permissions name a resource or action the vocabulary no longer declares, until the app gives it new permissions with `SetPermissions`; both checkers' `Grants`, called directly, instead ignore such a held entry and deny a check that names it.

A key made in settings carries no permissions, so the refund route refuses it:

```sh
curl -s -X POST localhost:8081/api/refunds -H "Authorization: Bearer $LIVE_KEY"
```

```json
{"error":{"code":"apikey.permission_denied","message":"This key does not allow this."}}
```

Check: `TestR36_OrganizationKeys`, `TestR36_OrganizationKeyDistinct`, `TestR36_KeyPermissions`; `TestLifecycle_PermissionsAndARemovedAction` in the example builds the app a second time on the same database with `refund` removed from the statements, sees the old key refused, and gives it new permissions with `SetPermissions` (an undeclared action is `apikey.ErrBadPermissions`).

## Options you may want

| Option | Use it when |
|---|---|
| `apikey.AllowMetadata()` | Keys should carry a JSON object of the owner's (`400 apikey.metadata_disabled` otherwise) |
| `apikey.DefaultLimits(apikey.Limits{RateMax: 60, RateWindow: time.Minute})` | Every key made from settings should be throttled the same way; `CreateFor` and `SetLimits` set limits per key from Go |
| `POST /auth/apikey/update` | Rename, pause, resume, re-expire or relabel a key instead of revoking and recreating it |
| `apikey.Prefix("acme_")` | You want keys recognisable as yours by secret scanners (at least 3 characters, ending in `_`) |
| `apikey.MaxKeys(n)` | The default cap of 50 keys per account is too low or too high for your integrations |
| `apikey.RequireName()` | Every key in the list must say what it is for |
| `apikey.NameLength(n)` | Names should be cut shorter or allowed longer than 64 runes |
| `apikey.NameBounds(min, max)` | A name outside the bounds should be refused (`400 apikey.bad_name`) rather than cut, because the settings form has its own rules |
| `apikey.HintLength(n)` | The list should show more (up to 8) or fewer (0: the prefix alone) characters of each key |
| `apikey.Generate(fn)` | Keys must follow a particular alphabet or length; `fn` returns the random part (at least 22 characters), the prefix stays |
| `GET /auth/apikey/list?limit=…&offset=…&sortBy=…&sort=…`, `GET /auth/apikey/get?id=…` | The settings page pages, sorts, or opens one key (Step 5) |
| `"scopes"` in an update | A key needs other scopes without being reissued (Step 6) |
| `ak.Verify(ctx, secret, scopes...)` | A key arrives somewhere other than the `Authorization` header (Step 8) |
| `apikey.Configuration(id, ...)` | You need several kinds of key, such as live and test, with their own prefixes and limits (Step 9) |
| `apikey.WithCache(cache, ttl)` | A busy key should not cost a database read per request, and a revoke may take up to the TTL to reach other instances (Step 9) |
| `apikey.WithExpiry(apikey.Expiry{MinDays: 7, MaxDays: 365, DefaultDays: 90})` | Policy: keys must expire, within bounds, and an unspecified expiry gets a default (`400 apikey.expiry_out_of_range` otherwise) |
| `auth sweep` / `a.Sweep` | Expired keys should disappear from the table and the owner's list; the plugin is an `auth.Sweeper` |
| `expiresInDays` in the request, or `expiresIn` in seconds (not both, `400 apikey.expiry_conflict`) | Keys for a contractor or a migration should stop by themselves |
| `authhttp.RequireScope` per route | The route is for keys only |
| `authhttp.RequireUser` + `auth.HasScope` | People and keys share the route |

Limits with defaults: an account holds at most [50](ds:block?id=maxkeysperuser-fkhrbvpa) keys (`409 apikey.too_many`; `apikey.MaxKeys` changes it), and a name is cut to [64](ds:block?id=maxnamelength-89a3u4k8) characters (`apikey.NameLength` changes it).

## Combining with other plugins

- [Admin](admin.md): banning a user stops every key of theirs at once, because the key's owner is looked up on each request.
- [Organizations](organization.md): a user's key carries its owner, and a route that is per organization checks membership the way it would for a session; an `apikey.OrganizationOwned` configuration makes keys the organization owns (Step 10).
- [JWT](jwt.md): the other way a program proves who it acts for, for another service rather than your own API.

## From TypeScript

Use this when the "API keys" page of your app is a frontend. The [typed client](../client/README.md) has the routes as `client.apikey.create`, `list`, `get`, `update` and `revoke`; list `apikey()` in `plugins`. The keys themselves are not used through this client: a script sends a key to your API in the `Authorization` header (Step 4), not to the auth routes.

Create a key and show its secret once. Every field of the input is optional; one left out takes its default (the default configuration and its scopes, no prefix, no expiry):

<!-- ds:block id=tsp-apikey-create-8kw3qn7x -->
**createKey** · [`clients/ts/examples/plugin-account.ts:57-61`](../../clients/ts/examples/plugin-account.ts#L57-L61)

```typescript
export async function createKey(name: string, scopes: string[]): Promise<string | null> {
  const { data, error } = await auth.apikey.create({ name, scopes, expiresInDays: 90 });
  if (error) return null; // auth.fresh_session_required, apikey.unknown_scope, apikey.too_many, ...
  return data.secret;
}
```
<!-- /ds:block hash=03d638 -->

List and revoke. The list carries a hint of each key, never the secret:

<!-- ds:block id=tsp-apikey-revoke-2qm7wk4n -->
**revokeExpiredKeys** · [`clients/ts/examples/plugin-account.ts:65-75`](../../clients/ts/examples/plugin-account.ts#L65-L75)

```typescript
export async function revokeExpiredKeys(): Promise<number> {
  const { data } = await auth.apikey.list({ limit: "100" });
  const now = Date.now();
  let revoked = 0;
  for (const key of data?.keys ?? []) {
    if (key.expiresAt === null || Date.parse(key.expiresAt) > now) continue;
    const { error } = await auth.apikey.revoke({ id: key.id, configId: key.configId });
    if (!error) revoked++;
  }
  return revoked;
}
```
<!-- /ds:block hash=27bd27 -->

`update` renames, pauses (`disabled`), re-expires or re-scopes a key; its fields are `null` when unchanged.

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `auth.fresh_session_required` on create and update (re-authenticate on the held session, as [password's From TypeScript](password.md#from-typescript) shows), `apikey.unknown_scope`, `apikey.name_required`, `apikey.too_many`, `apikey.expiry_out_of_range` and `apikey.expiry_conflict` (both `expiresInDays` and `expiresIn` set), `apikey.metadata_disabled`, `apikey.not_found`, `apikey.no_changes` from an update that changes nothing, and the `apikey.organization_*` codes for keys owned by an organization.

There is no runnable TypeScript example for API keys; the blocks above are type-checked by `task ts:check`, and Steps 3 to 6 show the same calls with curl.

Pitfalls:

- **The secret is in `create`'s answer only.** Show it with a copy button and say it will not be shown again; nothing can read it back.
- **Send `null` for scopes to get the configuration's default scopes, `[]` for none.** The two mean different things on the server.
- **`list` paging fields are strings** (`limit: "100"`), because query inputs travel in the query string.

Every method with its route and types: [TypeScript client reference › apikey](../reference/ts-client.md#apikey).

## What can go wrong

- `401 auth.signed_out` on your API — no `Authorization: Bearer` header, a key that was revoked or expired, a key whose owner was banned, or a key sent in the session cookie (not trusted there).
- `403 auth.missing_scope` "This key does not allow this." — the key lacks the route's scope, or the caller is a browser session on a `RequireScope` route.
- `403 auth.api_key_refused` "This cannot be done with an API key." — a key called an `/auth` operation.
- `403 auth.fresh_session_required` on create — the session is older than the fresh window; the person signs in again.
- `400 apikey.unknown_scope` "A scope in this request does not exist." — a scope not declared with `Scopes`.
- `409 apikey.too_many` "This account has too many keys. Revoke one first."
- `400 apikey.name_required` "Give the key a name." — `apikey.RequireName` is set and the name is blank.
- `400 apikey.expiry_out_of_range` "The expiry is outside what this app allows." — `expiresInDays` or `expiresIn` is negative, outside `apikey.WithExpiry`'s bounds, or 0 ("never") while a maximum is set.
- `400 apikey.expiry_conflict` "Give the expiry in seconds or in days, not both." — the request set both `expiresIn` and `expiresInDays`.
- `404 apikey.not_found` on revoke or update — unknown id or another user's key.
- `400 apikey.no_changes` "Nothing to update." — an update whose fields are all absent.
- `400 apikey.bad_list` "The list options are not valid." — `limit` or `offset` is not a non-negative integer, or `sortBy` / `sort` is not one of the listed values.
- `400 apikey.bad_name` "The name is too short or too long." — `apikey.NameBounds` is set and the name is outside them.
- `500` with `apikey: Generate returned a secret shorter than 22 characters` in the log — the `apikey.Generate` function is too short; an app bug.
- `400 apikey.metadata_disabled` — metadata sent without `apikey.AllowMetadata()`.
- `400 apikey.bad_metadata` — metadata that is not a JSON object, or longer than 4096 bytes.
- `429 auth.rate_limited` "Too many attempts. Wait a moment and try again." with `Retry-After` — the key's `RateMax` for the window is spent; the header says when the window reopens.
- `429 apikey.usage_exceeded` "This key has used up its quota." — `Remaining` reached zero and no refill is due.
- `auth.New` fails with `apikey: Limits pair RateMax with RateWindow and RefillAmount with RefillInterval…` — `DefaultLimits` is half filled; `CreateFor` and `SetLimits` return the same `apikey.ErrBadLimitsValue`.
- `auth.New` fails with `apikey: a scope is non-empty and contains no whitespace` or `apikey: a prefix is at least three characters and ends with _` — configuration.
- `403 apikey.organization_permission` — the member's organization role does not grant that `apiKey` action; `403 apikey.not_organization_member` — the caller named an organization they are not in.
- `400 apikey.organization_id_required` or `400 apikey.not_organization_config` — `organizationId` missing under an `OrganizationOwned` configuration, or sent under one whose keys belong to users.
- `auth.New` fails with `apikey: an OrganizationOwned configuration needs apikey.WithOrganizations` — wire the organization lookup; or with `apikey.bad_permissions` — a `DefaultPermissions` entry the vocabulary does not declare.
- `auth.New` fails with `token prefix "ubk_" of plugin "apikey" overlaps "…"` — another plugin's bearer prefix starts the same way; give one of them another `Prefix`.

## Next

- [JWT](jwt.md): short-lived tokens for another service.
- [Other services](../integrations/other-services.md): verifying those tokens elsewhere.
- [Security](../concepts/security.md): why keys are refused under `/auth`.
- Reference: [plugin/apikey/README.md](../../plugin/apikey/README.md), [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/apikey).

# Extend sessions

You will have chosen where sessions live, put a cache of your own in front of the lookup, and given browsers and apps different lifetimes — each one a value you pass to `auth.New`, with the core keeping every rule.

## Before you start

- [Session rules](07-session-rules.md): what a session is, how it is looked up, and the conditions plugins add to it.
- The examples: [`examples/session-strategies`](../../examples/session-strategies/main.go) runs one app with every built-in store, cache and the lifetime policy, chosen by flag, and has a custom store, `loggingStore`; [`examples/plugin-hooks`](../../examples/plugin-hooks/cache.go) has a custom cache and a plugin's own policy.
- The default needs nothing: sessions are rows in `auth_session`, looked up with one query that joins the user. Change it only for a reason you can name — several instances with no shared database, a hot path that must skip the lookup, an app that must stay signed in for a year.

## Step 1 — Know the shape: what the core keeps, what a store does

A session store only saves and finds. Lifetimes, the sliding expiry, the pending second factor, impersonation and the data hooks stay in the core, so a store cannot get them wrong. A store never sees a raw token, only its SHA-256 hash, so a store cannot leak a usable credential. A store keeps every field of the `Session` it is given, `Data` included — the app's JSON, which `SetData` replaces on its own, leaving the expiry alone — and the conformance suite fails a store that drops one.

<!-- ds:block id=core-sessionstore-jxm3haq9 -->
**SessionStore** · [`sessionstore.go:30-55`](../../sessionstore.go#L30-L55)

```go
type SessionStore interface {
	// Insert saves a new session under its token hash.
	Insert(ctx context.Context, s Session, tokenHash []byte) error
	// Find returns the session whose token hashes to tokenHash and that is
	// still live at now (ExpiresAt after now), or ErrSessionNotFound.
	Find(ctx context.Context, tokenHash []byte, now time.Time) (Session, error)
	// Touch moves the expiry of session id forward to expiresAt, and records
	// lastSeenAt, only if its current expiry is earlier; it reports whether
	// it moved. Of concurrent refreshes the first wins and the rest report
	// false.
	Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error)
	// List returns userID's live, non-pending sessions: newest first, ties by
	// id descending, the same order on every store.
	List(ctx context.Context, userID string, now time.Time) ([]Session, error)
	// Delete ends session id of userID; another user's id matches nothing.
	Delete(ctx context.Context, userID, id string) error
	// DeleteUser ends every session of userID except exceptID ("" = all).
	DeleteUser(ctx context.Context, userID, exceptID string) error
	// Sweep deletes sessions expired before now and reports how many; a
	// store that expires entries by itself returns 0, nil.
	Sweep(ctx context.Context, now time.Time) (int64, error)
	// SetData replaces the app data (Session.Data) of session id; nil
	// clears it. An unknown id is no error. Every other field, the expiry
	// above all, stays as it is.
	SetData(ctx context.Context, id string, data AppData) error
}
```
<!-- /ds:block hash=78e741 -->

The SQL store, the default, also loads the user in the same query, with every plugin's session condition applied. A store that can do that implements `SessionUserFinder`; one that cannot costs a request two queries, and `auth.New` then refuses a session condition that names `auth_session`, because there is no join for it to run in.

<!-- ds:block id=core-sessionuserfinder-mpexgk37 -->
**SessionUserFinder** · [`sessionstore.go:66-71`](../../sessionstore.go#L66-L71)

```go
type SessionUserFinder interface {
	SessionStore
	// FindWithUser is Find plus the user, refused (ErrSessionNotFound) when
	// the user fails any of checks.
	FindWithUser(ctx context.Context, tokenHash []byte, now time.Time, checks []sqlb.Predicate) (Session, User, error)
}
```
<!-- /ds:block hash=030fe8 -->

Check: the built-ins are `auth.NewMemorySessionStore()` (this process only; every deploy signs everyone out) and `redis.NewSessionStore(client)` in `contrib/redis`. `auth.WithStatelessSessions(key)` is a third mode with no store at all: the token carries the session, sealed with the key; `Sessions` and `DeleteSession` for another session answer `auth.ErrSessionsUnavailable`, and rotating the key signs everyone out.

## Step 2 — Write a store and run the conformance suite

Implement the eight methods against your backend, and the optional `SetReauthenticatedAt(ctx, id, at)` of [`auth.SessionReauthStore`](ds:block?id=core-sessionreauthstore-7nd3qp5x) so users can [re-authenticate](../concepts/sessions.md#prove-it-is-still-you-re-authentication) on the session they hold: it records `Session.ReauthenticatedAt` and nothing else, an unknown or ended id is no error, and it must never bring an ended session back. Without it re-authentication answers `auth.reauthentication_unsupported` and users sign in again. The one rule that is easy to get wrong is `Touch`: it moves the expiry only forward, and reports whether it did, so of two concurrent refreshes the first wins and the second does nothing. `SetData` is the other write after `Insert`: it replaces `Session.Data` (an `auth.AppData`, JSON bytes the core has already bounded and compacted) and changes nothing else, and an unknown id is no error. The example store delegates to another store and counts; a real one talks to a key-value service.

The suite in `github.com/ubgo/auth/sessiontest` checks every method's contract — ordering, another user's id matching nothing, `Touch` only-if-later, `Sweep`, expired not found, `Data` kept byte for byte through `Insert`, `Touch` and `SetData`, and `SetReauthenticatedAt` when the store has it — against a fresh store per case. A store must also keep `Session.Tasks`, because a store that drops it fails every sign-in that has a task. The optional `RotateToken`/`FindRotated` of `auth.SessionTokenRotator` enables `WithTokenRotation`; `sessiontest.Run` checks both. Run it in your store's tests before anything else does:

```go
func TestMyStore(t *testing.T) {
	sessiontest.Run(t, func(*testing.T) auth.SessionStore { return newMyStore(t) })
}
```

Then pass the store to `auth.New`:

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithSessionStore(myStore),
	// …
)
```

Check: `go test` passes the eight cases. A store backed by a shared server must return a fresh key prefix or a flushed keyspace from each `open` call, since every case expects an empty store. The suite passes `now` to `Find`, `List` and `Sweep` and never reads a clock of its own; your store must compare the times it is given.

What a non-SQL store gives up: it joins no transaction, so a sign-up that rolls back after creating its session leaves that session in the store with a token nobody holds, until it expires. The SQL store has no such gap. When a session ends, the core tells every `auth.SessionLifecycle` plugin first and the store after, inside the transaction, so a plugin that refuses leaves the session in place in your store too; the plugin's own rows (SQL) roll back if your store then fails.

<!-- ds:block id=core-sessionlifecycle-3vt6nq8z -->
**SessionLifecycle** · [`sessiondata.go:286-297`](../../sessiondata.go#L286-L297)

```go
type SessionLifecycle interface {
	// SessionEnded is one session of userID ending by id: sign-out, revoke,
	// an admin ending it, a device's other account being ended.
	SessionEnded(ctx context.Context, userID, id string) error
	// UserSessionsEnded is every session of userID ending but exceptID,
	// which is "" for all: sign-out everywhere, a password reset, a ban.
	UserSessionsEnded(ctx context.Context, userID, exceptID string) error
	// SessionReplaced is a pending second-factor session (old) becoming the
	// full session (new) at PromoteSession: a new id, the same sign-in.
	// What the plugin kept for old belongs to new now.
	SessionReplaced(ctx context.Context, old, new Session) error
}
```
<!-- /ds:block hash=408176 -->

## Step 3 — Put a cache in front of the lookup

A `SessionCache` lets a request skip the lookup for a short time. The core calls it with its own clock — `now` on `Get`, `until` on `Put` — so a cache keeps no clock, and a test can move time. An entry never outlives the session's expiry, a pending second-factor session is never cached, and sign-out drops the entry.

<!-- ds:block id=core-sessioncache-2gkmh8gk -->
**SessionCache** · [`sessioncache.go:25-36`](../../sessioncache.go#L25-L36)

```go
type SessionCache interface {
	// Get returns the cached session and user for k, valid at now, or
	// ok=false. An error is a failure of the cache itself, not a miss.
	Get(ctx context.Context, k CacheKey, now time.Time) (s Session, u User, ok bool, err error)
	// Put remembers a looked-up session until until. The returned string,
	// when not empty, is handed to the client to send back on later requests
	// as Request.CachedSession; the snapshot cache uses it, a server-side
	// cache returns "".
	Put(ctx context.Context, k CacheKey, s Session, u User, until time.Time) (clientValue string, err error)
	// Drop forgets the entry for this token: sign-out on this device.
	Drop(ctx context.Context, k CacheKey) error
}
```
<!-- /ds:block hash=26cb55 -->

<!-- ds:block id=core-cachekey-mrdw3a5z -->
**CacheKey** · [`sessioncache.go:41-46`](../../sessioncache.go#L41-L46)

```go
type CacheKey struct {
	// TokenHash is the hash of the request's session token.
	TokenHash []byte
	// Client is what the client sent back from an earlier Put, or "".
	Client string
}
```
<!-- /ds:block hash=ebba19 -->

The example wraps the in-process cache and counts hits and misses, which is how an app measures what a cache saves before choosing one:

<!-- ds:block id=hooks-countingcache-8v7wkjw9 -->
**countingCache** · [`examples/plugin-hooks/cache.go:18-21`](../../examples/plugin-hooks/cache.go#L18-L21)

```go
type countingCache struct {
	next         auth.SessionCache
	hits, misses atomic.Int64
}
```
<!-- /ds:block hash=36ab89 -->

Wire it with a TTL. Zero means `auth.DefaultSessionCacheTTL` (a minute); more than `auth.MaxSessionCacheTTL` (fifteen minutes) is clamped to it, because the TTL is how long a ban or a remote sign-out keeps not reaching a device that holds an entry:

<!-- ds:block id=hooks-newauth-9mq2x3bt -->
**newAuth** · [`examples/plugin-hooks/main.go:109-124`](../../examples/plugin-hooks/main.go#L109-L124)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *countingCache, error) {
	g := guard.New(blockedDomains...)
	cache := newCountingCache(auth.NewMemorySessionCache(cacheEntries))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			g,
		),
		auth.WithSessionPolicy(g.SessionPolicy()),
		auth.WithSessionCache(cache, cacheTTL),
	)
	return a, cache, err
}
```
<!-- /ds:block hash=e55d3d -->

Check: in the example's test, three requests after a sign-in count one miss and two hits. The built-ins are `auth.NewSnapshotCache(key)`, which stores nothing on the server and hands the client a sealed copy to send back (the transport carries it in a cookie or the `Auth-Session-Cache` header), `auth.NewMemorySessionCache(n)`, `redis.NewSessionCache(client)`, `auth.NewCompactSessionCache(key)`, whose client copy is signed and readable (base64url JSON and an HMAC bound to the token hash, keyed from `auth.WithSecret` when given no key), and `jwt.NewSessionCache(jw)` from the [JWT plugin](../plugins/jwt.md), whose client copy is a signed, readable JWT a service can verify with the JWKS.

A cache of your own proves itself with one call, `sessiontest.RunCache(t, open)`, which every built-in cache runs: an entry comes back whole for its own token and no other, is used until its expiry and never at or after it, a changed or made-up client copy is a miss rather than an error, and a server-side entry is forgotten by `Drop`.

## Step 4 — Choose lifetimes per client

A `SessionPolicy` chooses a session's lifetime when it is created. The choice is stored with the session (`IdleSeconds`, `RefreshSeconds`, `MaxExpiresAt`), so every later refresh slides by the session's own values: a year-long app session does not shrink to the web default on its first refresh. Zero fields fall back to `auth.SessionConfig`, and `Max` is capped at `auth.MaxSessionLifetime`, 400 days.

<!-- ds:block id=core-sessionlifetime-dd9t2x6a -->
**SessionLifetime** · [`lifetime.go:14-18`](../../lifetime.go#L14-L18)

```go
type SessionLifetime struct {
	Idle         time.Duration
	Max          time.Duration
	RefreshAfter time.Duration
}
```
<!-- /ds:block hash=545852 -->

<!-- ds:block id=core-sessionpolicyinput-tp7tav9x -->
**SessionPolicyInput** · [`lifetime.go:30-41`](../../lifetime.go#L30-L41)

```go
type SessionPolicyInput struct {
	UserID string
	// Credential is how the client presents its token: CredentialCookie for
	// a browser, CredentialBearer for an app, CredentialNone for a Go call
	// with no request in ctx. A request that asked for bearer delivery
	// (Request.Delivery) reports CredentialBearer here too: at sign-in the
	// app has no token yet, and it is the app's lifetime it needs.
	Credential Credential
	Client     Client
	// Transient is "remember me" unticked.
	Transient bool
}
```
<!-- /ds:block hash=1b973d -->

<!-- ds:block id=core-sessionpolicy-wghqdf3p -->
**SessionPolicy** · [`lifetime.go:47`](../../lifetime.go#L47-L47)

```go
type SessionPolicy func(ctx context.Context, in SessionPolicyInput) SessionLifetime
```
<!-- /ds:block hash=c4425a -->

The common case is one lifetime for browsers and one for apps; `auth.ByCredential` is that policy. An app signing in has no token yet, so it says how it wants the token with the `Auth-Token-Mode: bearer` header, which the transport reports as `Request.Delivery`; the policy input then reports a bearer credential:

<!-- ds:block id=core-bycredential-f4r97d2a -->
**ByCredential** · [`lifetime.go:68-75`](../../lifetime.go#L68-L75)

```go
func ByCredential(cookie, bearer SessionLifetime) SessionPolicy {
	return func(_ context.Context, in SessionPolicyInput) SessionLifetime {
		if in.Credential == CredentialBearer {
			return bearer
		}
		return cookie
	}
}
```
<!-- /ds:block hash=5b1881 -->

The example's plugin goes one step further: a session proven by the password alone lives a day, one that passed the PIN gets the client's lifetime. A policy runs after `Init`, with the sign-in's transaction in `ctx`, so it may load a row:

<!-- ds:block id=guard-lifetimes-v6b73gyd -->
**WebLifetime** · [`examples/plugin-hooks/guard/guard.go:228-232`](../../examples/plugin-hooks/guard/guard.go#L228-L232)

```go
var (
	WebLifetime       = auth.SessionLifetime{Idle: 7 * 24 * time.Hour, Max: 365 * 24 * time.Hour}
	AppLifetime       = auth.SessionLifetime{Idle: 90 * 24 * time.Hour, Max: 365 * 24 * time.Hour}
	OneFactorLifetime = auth.SessionLifetime{Idle: 24 * time.Hour, Max: 24 * time.Hour}
)
```
<!-- /ds:block hash=a5d2b1 -->

<!-- ds:block id=guard-sessionpolicy-7n2k4vqd -->
**Plugin.SessionPolicy** · [`examples/plugin-hooks/guard/guard.go:239-248`](../../examples/plugin-hooks/guard/guard.go#L239-L248)

```go
func (p *Plugin) SessionPolicy() auth.SessionPolicy {
	byClient := auth.ByCredential(WebLifetime, AppLifetime)
	return func(ctx context.Context, in auth.SessionPolicyInput) auth.SessionLifetime {
		var hash *string
		if err := p.a.LoadUserColumns(ctx, in.UserID, sqlb.Bind(PINHash, &hash)); err != nil || hash == nil {
			return OneFactorLifetime
		}
		return byClient(ctx, in)
	}
}
```
<!-- /ds:block hash=173f03 -->

Check: `auth.Sessions` shows the lifetime each session got in its `IdleSeconds`. Pending second-factor sessions and impersonation sessions keep their fixed lifetimes whatever the policy says.

## Step 5 — Combine two stores, and revoke stateless tokens

`auth.MirrorSessionStore(primary, secondary)` keeps every session in both: the primary is authoritative, the secondary is the fast copy read first. [`auth.SQLSessionStore()`](ds:block?id=core-sqlsessionstore-8mz4rv6q) names the database store before `auth.New` exists, so the common shape is the database behind Redis:

<!-- ds:block id=core-mirrorsessionstore-4tq9xk2w -->
**MirrorSessionStore** · [`sessionmirror.go:49-51`](../../sessionmirror.go#L49-L51)

```go
func MirrorSessionStore(primary, secondary SessionStore) SessionStore {
	return mirrorSessionStore{primary: primary, secondary: secondary, logger: slog.Default()}
}
```
<!-- /ds:block hash=b587b0 -->

The rule is built so a failing copy can cost speed and never let an ended session in: writes that add or slide (`Insert`, `Touch`) succeed with the primary and log the copy's failure, ends (`Delete`, `DeleteUser`) go to the copy first and fail when it fails, `SetData` and `SetReauthenticatedAt` must reach both, and `List` reads the primary. `sessiontest.Run` passes over a mirror of any two conforming stores, and contrib/redis runs it with Redis on either side.

A stateless session has no row to delete, so its sign-out only clears the cookie. A revocation list gives it per-session revocation:

<!-- ds:block id=core-sessionrevocations-5hv2qm8k -->
**SessionRevocations** · [`sessionrevoke.go:28-33`](../../sessionrevoke.go#L28-L33)

```go
type SessionRevocations interface {
	// Revoke ends session id until until.
	Revoke(ctx context.Context, id string, until time.Time) error
	// Revoked reports whether session id is on the list at now.
	Revoked(ctx context.Context, id string, now time.Time) (bool, error)
}
```
<!-- /ds:block hash=19af61 -->

Wire one with `auth.WithSessionRevocations(auth.NewMemorySessionRevocations())` for one process or `auth.WithSessionRevocations(redis.NewSessionRevocations(client))` for several; a list of your own runs `sessiontest.RunRevocations(t, open)`. Only the session id is stored, until the latest instant any of its tokens could be valid.

[`examples/session-revocation`](../../examples/session-revocation) wires the in-memory list:

<!-- ds:block id=sessionrevocation-options-8vk2mq4d -->
**sessionOptions** · [`examples/session-revocation/main.go:121-129`](../../examples/session-revocation/main.go#L121-L129)

```go
func sessionOptions(key []byte, list auth.SessionRevocations) []auth.Option {
	opts := []auth.Option{auth.WithStatelessSessions(key)}
	if list != nil {
		// Sign-out, revoke and the second-factor promotion add the
		// session's id; every stateless lookup checks it.
		opts = append(opts, auth.WithSessionRevocations(list))
	}
	return opts
}
```
<!-- /ds:block hash=bc8269 -->

Try it: `go run ./session-revocation`, sign up with `-H 'Auth-Token-Mode: bearer'` and keep the `Set-Auth-Token` value, then `GET /me` with it (200), `POST /auth/sign-out` with it (`{"ok":true}`), and `GET /me` again: `{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}`, while `select count(*) from auth_session` is still 0. The [example's README](../../examples/session-revocation/README.md) has the transcript.

Check: after a stateless sign-out with a list, the old token is `auth.signed_out` on every instance that shares the list. In the example, `TestSignOutEndsTheTokenAtOnce` proves it and that another session of the same user survives, and `TestWithoutTheListATokenOutlivesSignOut` proves the same token keeps working without the list.

## What can go wrong

- `auth: operation description is not valid: WithStatelessSessions and WithSessionStore both set` — a deployment has one store or none; choose.
- `auth: operation description is not valid: stateless sessions: auth: seal key is 16 bytes, want 32` — the stateless key is `auth.SealKeySize` bytes.
- `auth: a session check can use only auth_session and auth_user: plugin "x" names table alias "s"; the session lookup has only auth_user (u): the session store does not join it` — with a store that is not a `SessionUserFinder`, or in stateless mode, a plugin's session condition may name `auth_user` only.
- `auth: session cache: …` — the cache's `Get`, `Put` or `Drop` failed. It is a 500, not a sign-out: a failing cache must not sign anyone out, and must not sign anyone in either.
- `auth: look up session: …` — the store's `Find` failed with something other than `auth.ErrSessionNotFound`. Return that sentinel for "not there"; anything else means the store itself failed.
- Sessions that do not list, or `auth.sessions_unavailable` (409) — stateless mode: nothing about a session exists on the server, so only the request's own can be shown or ended.
- A ban that takes a minute to apply — a client-held cache copy (snapshot, compact, JWT), which nothing on the server can drop, or under `auth.WithStatelessRefreshWithoutRead` the read interval. Shorten the TTL, use a server-side cache, or accept the delay you configured. A custom server-side cache implements `auth.SessionCacheUserDropper` (`DropUser`) so ends and bans evict its entries.
- `auth: session mirror: secondary: …` on a sign-out — the copy could not end the session, so nothing was ended; the copy must be reachable to sign out. A `WARN auth: session mirror: the secondary store failed` log line is a copy that missed a write the primary carried.
- `auth: SQLSessionStore is bound by auth.New` — the placeholder was called directly; use the store `a.SessionStore()` returns.
- `auth: session revocations: …` — the list could not be read. The request fails rather than let a possibly revoked session in.
- `WithSessionRevocations needs WithStatelessSessions` — a stored session is ended by deleting it; the list is for tokens the server never stored.

## Next

- [Session rules](07-session-rules.md), if you came here first: conditions and second factors are what a store or a cache must not bypass.
- The `contrib/redis` module: the shared store and cache, and their `sessiontest` run against a real Redis.

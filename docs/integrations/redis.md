# Redis: rate limits, sessions and the session cache across instances

You will have an app whose instances share one set of rate limits counted in Redis, keep their sessions there instead of in the database, and skip the session lookup with a cache every instance sees, so a sign-out on one instance holds on all of them.

## Before you start

- [Rate limits](../concepts/rate-limits.md) and [Sessions](../concepts/sessions.md): what is being counted and stored, and the defaults that need no Redis at all.
- The examples are [`examples/multi-instance`](../../examples/multi-instance/main.go) (two instances on one database; `AUTH_REDIS_ADDR` moves the counters to Redis) and [`examples/session-strategies`](../../examples/session-strategies/main.go) (`-store redis -cache redis`). Both were run against a local Redis at `127.0.0.1:7012` for the transcripts below.
- `go get github.com/ubgo/auth/contrib/redis` (package `redisrate`). It is its own module, so go-redis reaches only the apps that use it. It needs Redis 7 or later (it uses `EXPIRE NX`).
- You may not need it. Sessions in the database are already shared by every instance that shares the database, and `auth.WithDBRateStore()` counts rate limits there too, with no new infrastructure. Reach for Redis when you already run it, when the auth routes are hot enough that a database write per counted request shows, or when instances share no database.

## Step 1 — Know why one process is not enough

Without a rate store, each process counts in memory, so five wrong passwords spread over two instances look like two or three to each, and `auth.New` logs `WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance` at start. The multi-instance example picks the store from the environment:

<!-- ds:block id=ratestore-7z8zumcj -->
**rateStore** · [`examples/multi-instance/main.go:136-147`](../../examples/multi-instance/main.go#L136-L147)

```go
func rateStore(redisAddr string) (auth.Option, error) {
	if redisAddr == "" {
		log.Printf("rate limits: counted in the database table %s", auth.TableNameRateLimit)
		return auth.WithDBRateStore(), nil
	}
	client := redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis at %s does not answer: %w", redisAddr, err)
	}
	log.Printf("rate limits: counted in Redis at %s", redisAddr)
	return auth.WithRateStore(redisrate.New(client)), nil
}
```
<!-- /ds:block hash=b1815c -->

Check: the warning is gone from the log once a store is configured.

## Step 2 — Count rate limits in Redis

`redisrate.New(client)` is an `auth.RateStore` on any go-redis client (`*redis.Client`, `*redis.ClusterClient` or a ring). It counts in fixed windows, one key per limiter key and window, with `INCR` and `EXPIRE NX` in one `MULTI`, so a counter can never be left without its expiry. Pass it to `auth.WithRateStore`:

<!-- ds:block id=new-fgn22edu -->
**New** · [`contrib/redis/redisrate.go:97-100`](../../contrib/redis/redisrate.go#L97-L100)

```go
func New(client redis.Cmdable, opts ...Option) *Store {
	c := newConfig(DefaultKeyPrefix, opts)
	return &Store{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}
```
<!-- /ds:block hash=ac6695 -->

<!-- ds:block id=newauth-5nsvtcd9 -->
**newAuth** · [`examples/multi-instance/main.go:153-163`](../../examples/multi-instance/main.go#L153-L163)

```go
func newAuth(db *sql.DB, m email.Mailer, rates auth.Option) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		rates,
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=dc48ba -->

Check: with `AUTH_REDIS_ADDR=127.0.0.1:7012 go run ./multi-instance`, five wrong passwords spread across the two instances lock the account on both. Instance B saw only two of them, but the sixth attempt is refused there, even with the right password, until the window ends ([`signInAccountLimit`](../plugins/password.md) is 5 in 15 minutes):

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
for port in 8081 8082 8081 8082 8081; do
  curl -s -X POST localhost:$port/auth/password/sign-in -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com","password":"wrong"}'
done
curl -si -X POST localhost:8082/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
{"user":{"id":"usr_6beu52nxyx3apht6svkq36ma","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
HTTP/1.1 429 Too Many Requests
Retry-After: 900
X-Instance: B

{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

The counters are Redis keys, one per limiter key and window, under the prefix:

```sh
redis-cli -p 7012 --scan --pattern 'ubgo:auth:rate:*' | sort
redis-cli -p 7012 GET 'ubgo:auth:rate:password.sign-up|ip|0|127.0.0.1|497455'
redis-cli -p 7012 TTL 'ubgo:auth:rate:password.sign-up|ip|0|127.0.0.1|497455'
```

```text
ubgo:auth:rate:password.sign-in|identifier|1|alice@example.com|1989823
ubgo:auth:rate:password.sign-in|ip|0|127.0.0.1|29847354
ubgo:auth:rate:password.sign-up|identifier|1|alice@example.com|497455
ubgo:auth:rate:password.sign-up|ip|0|127.0.0.1|497455
1
3599
```

Note what the keys hold: the limiter's key is the rule, the kind, the identifier or IP as typed (lower-cased), and the window number. Unlike the database rate store, whose rows hold a hash of the key, the Redis store writes the address and the IP into the key name, where `SCAN` and `MONITOR` show them. Treat the Redis instance as holding personal data until the store hashes its keys as the database store does.

## Step 3 — Keep sessions in Redis

`redisrate.NewSessionStore(client)` is an `auth.SessionStore`. The core keeps every rule (lifetimes, sliding expiry, the pending second factor, impersonation, hooks) and hands the store only the SHA-256 hash of a token, never the token. Pass it to `auth.WithSessionStore`; the session-strategies example does it behind `-store redis`:

<!-- ds:block id=newsessionstore-kxwh5sna -->
**NewSessionStore** · [`contrib/redis/sessions.go:124-127`](../../contrib/redis/sessions.go#L124-L127)

```go
func NewSessionStore(client redis.Cmdable, opts ...Option) *SessionStore {
	c := newConfig(DefaultSessionKeyPrefix, opts)
	return &SessionStore{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}
```
<!-- /ds:block hash=fff1ae -->

<!-- ds:block id=sessionoptions-982a5xp5 lines=14-22 -->
**sessionOptions** · [`examples/session-strategies/main.go:306-350`](../../examples/session-strategies/main.go#L306-L350)

```go
	switch cfg.Store {
	case storeDatabase:
		// Nothing to add: auth_session is the default.
	case storeMemory:
		opts = append(opts, auth.WithSessionStore(auth.NewMemorySessionStore()))
	case storeRedis:
		opts = append(opts, auth.WithSessionStore(redisrate.NewSessionStore(rdb)))
	case storeCustom:
		store := cfg.CustomStore
```
<!-- /ds:block hash=161c6d -->

What Redis holds, under `ubgo:auth:session:` by default:

| Key | Holds | Lives |
|---|---|---|
| `s:<token hash, hex>` | a hash: `exp` and `seen` in unix microseconds, `s` the session as JSON | until the session's expiry |
| `id:<session id>` | the token hash, so `Touch` and `Delete` work by id | until the session's expiry |
| `u:<user id>` | a set of the user's session ids, for the session list and "sign out everywhere" | no TTL; the list prunes ids whose session expired |

Check: sign up with `-store redis -cache redis`, read `/me` and the session list, and look at the keys:

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt localhost:8081/auth/sessions
```

```text
HTTP/1.1 200 OK
Set-Cookie: __Host-auth_session=dJD7aT6cUt3dGS4l-A9JIqi7Qxlu1XmWooPIDekCyMI; Path=/; Expires=Thu, 08 Oct 2026 05:17:57 GMT; HttpOnly; Secure; SameSite=Lax

{"user":{"id":"usr_by6udh6btfb6rtvxlv54a4vs","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_by6udh6btfb6rtvxlv54a4vs","credential":"cookie","expiresAt":"2026-10-08T05:17:57.548549Z"}
{"sessions":[{"id":"ses_ph23ujqrlhtgs2i3nzsoio5a","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-01T05:17:57.548549Z","lastSeenAt":"2026-10-01T05:17:57.548549Z"}]}
```

```sh
redis-cli -p 7012 --scan --pattern 'ubgo:auth:*' | sort
redis-cli -p 7012 TTL ubgo:auth:session:s:34ac399d7e010fb1cb75e2240303ced16599d803e5417d983140b30ce1a8202f
redis-cli -p 7012 HKEYS ubgo:auth:session:s:34ac399d7e010fb1cb75e2240303ced16599d803e5417d983140b30ce1a8202f
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
redis-cli -p 7012 --scan --pattern 'ubgo:auth:session:s:*' | wc -l
```

```text
ubgo:auth:cache:34ac399d7e010fb1cb75e2240303ced16599d803e5417d983140b30ce1a8202f
ubgo:auth:session:id:ses_ph23ujqrlhtgs2i3nzsoio5a
ubgo:auth:session:s:34ac399d7e010fb1cb75e2240303ced16599d803e5417d983140b30ce1a8202f
ubgo:auth:session:u:usr_by6udh6btfb6rtvxlv54a4vs
604799
exp
s
seen
{"ok":true}
0
```

The TTL is the session's seven-day idle lifetime, and the cache key appeared after the first `/me`.

What you give up against the default store: a Redis session joins no database transaction, so a sign-up whose surrounding transaction rolls back can leave a session nobody holds the token of; it expires by itself. And a plugin's session condition (`SessionChecker`) may name only `auth_user` columns, because the user is loaded in its own query; `auth.New` refuses one on `auth_session` with `auth: a session check can use only auth_session and auth_user`.

## Step 4 — Cache the lookup across instances

`redisrate.NewSessionCache(client)` is an `auth.SessionCache`: after one lookup, every instance answers the next requests of that session from Redis for the TTL you pass to `auth.WithSessionCache`, at most [`auth.MaxSessionCacheTTL`](../concepts/sessions.md) (15 minutes). A sign-out or a revocation of the current session drops the entry at once, and so does a revocation made elsewhere: the cache is a [`SessionCacheUserDropper`](ds:block?id=core-sessioncacheuserdropper-7mzq4k2w), so a ban, "sign out everywhere" from another device or a deleted user drops every entry of that user once the write commits ([`EvictCachedSessions`](ds:block?id=core-evictcachedsessions-4hp9xw3n)). The TTL is still capped, because it is the bound when an eviction fails (the failure is logged, not returned) or when a lookup that read the store just before the write puts its entry back. The client holds nothing, so no cookie or header is added; compare the snapshot cache in [Sessions](../concepts/sessions.md), where the client carries a sealed copy and the server holds nothing.

<!-- ds:block id=newsessioncache-6jfraqyb -->
**NewSessionCache** · [`contrib/redis/cache.go:44-47`](../../contrib/redis/cache.go#L44-L47)

```go
func NewSessionCache(client redis.Cmdable, opts ...Option) *SessionCache {
	c := newConfig(DefaultCacheKeyPrefix, opts)
	return &SessionCache{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}
```
<!-- /ds:block hash=b8d515 -->

Check: in the transcript above, the `ubgo:auth:cache:` key appears after the first `/me` and is gone after sign-out.

## Options you may want

| Option | What it does | Default |
|---|---|---|
| `KeyPrefix(p)` | Namespaces the keys, so two apps sharing one Redis do not share state and a test does not see another run's keys. | `ubgo:auth:rate:`, `ubgo:auth:session:`, `ubgo:auth:cache:` per constructor |
| `Clock(now)` | Replaces `time.Now`; tests pass the same clock as `auth.WithClock`. The rate store counts windows with it; the session store and cache take every instant from the core and use the clock only to turn an expiry into a Redis TTL. | `time.Now` |
| Several Redis clusters | Each constructor takes its own client; nothing requires one Redis for all three. | |
| A clean slate | `Clear(ctx)` on any of the three stores deletes every key under its prefix by `SCAN`, for tests and deliberate maintenance; the library never calls it, since clearing the session store signs everyone out. [`Clear(ctx, client, prefix)`](ds:block?id=redis-clear-4kn9xw2t) does the same for a prefix of your own. | |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `auth.internal` (500) on every request, log says `auth: rate store: redisrate: ...` | Redis is unreachable. The limiter fails closed: a failure is never a count of zero, which would read as "under the limit". | Fix the connection; or run without a rate store until it is back. |
| `auth.internal` (500) with `redisrate: read session` in the log | The session store cannot reach Redis. A store failure is a 500, never a silent sign-out. | Same. |
| `auth.New` fails with `WithRateStore and WithDBRateStore both set` | Both options given. | Keep one. |
| `auth.New` fails with `auth: a session check can use only auth_session and auth_user` naming a plugin | A plugin's session condition uses an `auth_session` column, which the Redis store cannot join. | Keep that plugin on the SQL store, or ask its author for a user-only condition. |
| A banned user keeps working for a while | The eviction failed (look for `auth: session cache eviction failed` in the log), or a plugin suspended the user without calling `EvictCachedSessions`. | Fix the Redis connection, or have the plugin call `a.EvictCachedSessions(ctx, userID)`; the entry is gone within the TTL either way. |
| The rate store fails on every hit against an older Redis | `EXPIRE` with the `NX` option needs Redis 7. | Upgrade Redis. |

## Next

- [Sessions](../concepts/sessions.md) for the other stores and caches, including stateless sessions and the snapshot cache that need no Redis.
- [Production](../start/production.md) for running several instances.
- The module's [README](../../contrib/redis/README.md) is the reference for the keys, the options and the tests, including the shared `sessiontest` conformance suite the store passes.

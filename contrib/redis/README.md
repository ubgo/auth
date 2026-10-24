# github.com/ubgo/auth/contrib/redis

Keeps auth's shared state in Redis for an app that runs several instances: rate limits counted once across them, sessions stored off the database, and a session cache that lets every instance skip the session lookup.

## Install

```sh
go get github.com/ubgo/auth/contrib/redis
```

This is its own module, so only apps that use it download go-redis. It brings `github.com/redis/go-redis/v9` and needs Redis 7 or later (it uses `EXPIRE NX`). The package name is `redisrate`. If you do not already run Redis, `auth.WithDBRateStore()` gives shared limits using the auth database, and the default SQL session store shares sessions through it, with no new infrastructure.

## Wire it

From [examples/multi-instance](../../examples/multi-instance/main.go):

```go
import redisrate "github.com/ubgo/auth/contrib/redis"

client := redis.NewClient(&redis.Options{Addr: redisAddr})
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithRateStore(redisrate.New(client)),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)
```

`New` accepts any `redis.Cmdable`: `*redis.Client`, `*redis.ClusterClient` or a ring. The store owns no connection, so closing the client is the app's job. `auth.New` refuses `WithRateStore` together with `WithDBRateStore` (`WithRateStore and WithDBRateStore both set`).

Sessions and the session cache take the same client and options:

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithSessionStore(redisrate.NewSessionStore(client)),
	auth.WithSessionCache(redisrate.NewSessionCache(client), time.Minute),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)
```

`auth.New` refuses `WithSessionStore` together with `WithStatelessSessions`, and a `SessionChecker` plugin whose condition names an `auth_session` column (`auth.ErrBadSessionCheck`): a store other than the SQL one loads the user in its own query, so only `auth_user` conditions can apply.

## Options

The same options apply to `New`, `NewSessionStore`, `NewSessionCache`, `NewSessionRevocations` and `NewStorage`.

| Option | What it does | Default |
|---|---|---|
| `KeyPrefix(p)` | Namespaces the keys, so two apps sharing one Redis do not share state and a test does not see another run's keys. For `NewSessionStore` the default is `"ubgo:auth:session:"` (`DefaultSessionKeyPrefix`), for `NewSessionCache` `"ubgo:auth:cache:"` (`DefaultCacheKeyPrefix`), for `NewSessionRevocations` `"ubgo:auth:revoked:"` (`DefaultRevocationKeyPrefix`). | `"ubgo:auth:rate:"` ([`DefaultKeyPrefix`](ds:block?id=defaultkeyprefix-a9s33p3m)) |
| `Clock(now)` | Replaces `time.Now`; tests pass the same clock as `auth.WithClock`. The rate store counts windows with it. The session store and cache take every instant from the core and use the clock only to turn an expiry into a Redis TTL. | `time.Now` |

## Clearing a store

`Clear(ctx)` on the rate store, the session store and the session cache deletes every key under that store's prefix, and the package-level [`Clear(ctx, client, prefix)`](ds:block?id=redis-clear-4kn9xw2t) does it for any prefix. It walks the keys with `SCAN` in batches of [1000](ds:block?id=redis-scanbatch-6pw3qk8m) and deletes each batch, never `KEYS`, so a large Redis is not blocked by one command. Nothing in the library calls it: a store never deletes what it did not write, and a clear under traffic signs every session out (session store), lets every client through once (rate store) or only refetches (cache). It is for a test that wants a clean slate between cases and for maintenance run on purpose. `SCAN` sees the node the client is connected to: on a Redis Cluster run it through `ForEachMaster`, on a ring once per shard. A Redis failure is returned wrapped `redisrate: clear: ...`.

## How it counts

`Hit(ctx, key, window)` implements `auth.RateStore`. It counts in fixed windows, with one Redis key per limiter key and window: `<prefix><key>|<window number>`. The core hashes the limited value (an email, a phone number, an IP) before it reaches any rate store, so no key holds one in clear. `INCR` and `EXPIRE NX` run in one `MULTI`, so a counter can never be left without its expiry and live forever. Each key expires with its window. The limits, windows and keys themselves come from the plugins' rate rules, not from this package.

## Sessions

`NewSessionStore(client, opts...)` is an `auth.SessionStore`; pass it to `auth.WithSessionStore`. The core keeps every rule (lifetimes, sliding expiry, the pending second factor, impersonation, hooks) and hands the store only the SHA-256 hash of a token, never the token, so the store cannot leak a usable credential.

| Key | Holds | Lives |
|---|---|---|
| `<prefix>s:<token hash, hex>` | a hash: `exp` and `seen` in unix microseconds, `s` the session as JSON | until the session's expiry |
| `<prefix>id:<session id>` | the token hash, so `Touch` and `Delete` work by id | until the session's expiry |
| `<prefix>u:<user id>` | a set of the user's session ids, for `List` and `DeleteUser` | no TTL; `List` prunes ids whose session expired |

`Touch` (the sliding refresh) is one Lua script on the session hash that moves the expiry only when it is earlier, so of concurrent refreshes exactly one moves it. Every command names one key, or a `MULTI` of keys, and no script spans several, so the store runs on a Redis Cluster. `Sweep` returns `0, nil`: Redis expires the keys itself. Times are kept to the microsecond, as the SQL store keeps them. A TTL is computed from this process's clock; when that clock is already past an expiry the key still lives `minTTL` (a minute) rather than vanishing at once, because the core, not the TTL, decides whether a session is live. The store joins no transaction: a rolled-back sign-up can leave a session nobody holds the token of, and it expires by itself.

`NewSessionCache(client, opts...)` is an `auth.SessionCache`; pass it to `auth.WithSessionCache` with a TTL (at most `auth.MaxSessionCacheTTL`, 15 minutes). Each entry lives under `<prefix><token hash, hex>` with the session and user as JSON and a Redis TTL of the remaining time; `Get` also checks the entry's own instant against the core's clock. The client holds nothing, so `Put` returns `""` and no cookie or header is added. Each `Put` also adds the entry's key to a set per user, `<prefix>user:<user id>`, which lives as long as the user's longest entry; `DropUser` (`auth.SessionCacheUserDropper`) deletes the keys in it and the set. The core calls it after a session end, a ban or a user deletion commits (`auth.EvictCachedSessions`), so a revoked or banned user is refused on every instance at the next request. An entry written by a lookup that raced the eviction lives until its TTL, which is why the TTL stays capped. Needs Redis 7 or later (`EXPIRE … GT`).

The store can also be the fast copy in front of the database, with the database authoritative: `auth.WithSessionStore(auth.MirrorSessionStore(auth.SQLSessionStore(), redisrate.NewSessionStore(client)))`. Reads try Redis first and fall back to the database; a Redis failure on a write or a refresh is logged and the request goes on, and one on a sign-out fails the sign-out, so a revoked session never lives on in Redis. See [concepts/sessions](../../docs/concepts/sessions.md).

## One store for everything short-lived

`NewStorage(client, opts...)` is an `auth.SecondaryStorage`: `auth.WithSecondaryStorage(redisrate.NewStorage(client))` keeps sessions (`auth.NewStorageSessionStore`) and rate-limit counters (`auth.NewStorageRateStore`) in Redis through four commands: `GET`, `SET` with a TTL, `DEL`, and `INCR` with `EXPIRE NX` in one `MULTI`, so a counter is never left without its expiry. Keys sit under [`DefaultStorageKeyPrefix`](ds:block?id=redis-defaultstoragekeyprefix-5kq2nw8d) (`ubgo:auth:kv:`) unless `KeyPrefix` says otherwise, and `Clear` deletes them. Use it when one interface is simpler for you than the dedicated `NewSessionStore` and `New`, which store the same data in Redis shapes of their own; verification tokens stay in SQL either way.

## Verification tokens in Redis

`NewVerificationStore(client, opts...)` is an `auth.VerificationStore`: `auth.WithVerificationStore(redisrate.NewVerificationStore(client))` keeps email and reset links, magic links, OAuth state and passkey ceremonies in Redis instead of `auth_verification`. A token is spent with `GETDEL` (Redis 6.2 or later), so of any number of concurrent requests with one token exactly one gets it; `Storage.GetAndDelete` is that command for any other use. An insert is `SET NX` with the token's TTL (`Storage.SetIfAbsent`, `auth.SetIfAbsenter`), so the store refuses a token hash it already holds (`auth.ErrTokenExists`), which is what plugin/oauth's ID-token replay guard claims each accepted token with: on this store, a token claimed by one instance is refused by every other. Each record lives under `<prefix>auth:verification:<purpose>:<token hash, hex>` with a Redis TTL of the token's life; ending every reset link of a user (`ConsumeAllVerifications`) and deleting a user write a cutoff instant under `<prefix>auth:verification-cutoff:…` and `<prefix>auth:verification-id-cutoff:…` keyed by the SHA-256 of the identifier, so no token, email address or user id appears in a key. A cutoff expires after `auth.MinVerificationCutoffTTL` (seven days) or the longest token lifetime the store issued, whichever is longer, so it outlives every token it ends and Redis does not grow. The default prefix is `ubgo:auth:verification:`; `KeyPrefix` overrides it. Redis joins no SQL transaction: a token spent by an operation that then fails stays spent, and `a.Sweep` reports 0 for it because Redis expires every record. The store runs `verificationtest.Run` in `task test:redis`.

## Revoking stateless sessions

`NewSessionRevocations(client, opts...)` is an `auth.SessionRevocations`; pass it to `auth.WithSessionRevocations` beside `auth.WithStatelessSessions`. A stateless sign-out, a revoke by id, ending another account on the device and the second-factor promotion each set one key, `<prefix><session id>`, holding the instant the entry stops mattering in unix microseconds, and every stateless lookup on every instance reads it. The session id is stored, never the token or its hash. A later revoke extends the entry and an earlier one never shortens it, in one Lua script on one key, so it runs on a Redis Cluster. The key's TTL is the remaining time by this process's clock, at least a minute; `Revoked` judges the instant by the core's clock. A Redis failure or a corrupted entry is an error, so the core fails the request instead of letting a possibly revoked session in.

## Tables and columns

None. It writes only Redis keys under the prefixes.

## Errors

A Redis failure is returned as an error wrapped `redisrate: ...`, never as a count of zero, which would read as "under the limit" and let every request through. The core then fails the operation (`auth: rate store: ...`, answered as 500 `auth.internal`), so the limiter fails closed. The session store returns `auth.ErrSessionNotFound` for a hash it does not hold or a session past its expiry, and any Redis failure or corrupted entry as an error, which the core answers as 500 rather than a silent sign-out. The cache answers a failure as an error too, never as a miss or a hit.

## Security notes

| Property | Pinned by |
|---|---|
| Counts go up within a window, restart in the next, and every key carries a TTL no longer than its window. | `TestHit_CountsPerWindowAndExpires` (needs a Redis; set `AUTH_TEST_REDIS_ADDR`, as `task test:redis` does) |
| A Redis failure is an error, not a zero count. | `TestHit_ARedisFailureIsAnError` |
| The session store keeps every contract of `auth.SessionStore` (find by hash, exclusive expiry, `Touch` only forward and once under concurrency, list order, another user's id matches nothing, `DeleteUser` with an exception). | `TestSessionStore_Conforms` (the shared `sessiontest` suite) |
| Every session key expires with its session and `Touch` re-arms the TTLs. | `TestSessionStore_KeysExpireWithTheSession` |
| A stale id is pruned and a corrupted entry is an error, never "not found". | `TestSessionStore_ListPrunesAndRefusesCorruptEntries` |
| Whichever command Redis fails, the store and the cache report it. | `TestSessionStore_EveryFailureIsAnError`, `TestSessionStore_ClosedClient`, `TestSessionCache_ClosedClient` |
| A cache entry is answered until its instant, dropped on demand, and never written once expired. | `TestSessionCache_PutGetDrop` |
| Every entry of a user is filed in the user's set, which never expires before its longest entry, and `DropUser` removes them all and leaves other users' entries. | `TestSessionCache_UserIndex`, `TestSessionCache_Conforms` |
| The revocation list keeps every contract of `auth.SessionRevocations` (revoked until the instant and never at or after it, judged by the core's clock; an earlier revoke never shortens an entry); its key expires with the entry; a corrupted entry and a closed client are errors. | `TestSessionRevocations_Conforms` (the shared `sessiontest.RunRevocations`), `TestSessionRevocations_KeysAndFailures` |
| As a mirror's copy or primary the store still keeps the session store contract, and a Redis copy that is down never fails a sign-in but fails a sign-out. | `TestSessionStore_ConformsAsAMirrorSecondary`, `TestMirror_ADownRedisSecondary` |
| `Clear` removes every key under the store's prefix across several `SCAN` batches and nothing under another prefix; a failing `SCAN` or `DEL` and a closed client are errors. | `TestClear_RemovesOnlyThePrefix`, `TestClear_FailuresAreErrors` |

Limits: fixed windows allow up to twice the limit in a burst that straddles a window boundary. The session store is not transactional with the database. Out of scope for now: a per-user cache version. A client-readable snapshot is `auth.NewCompactSessionCache` in the core, and stateless refresh without the database is `auth.WithStatelessRefreshWithoutRead`; neither needs Redis.

## Example

- [examples/multi-instance](../../examples/multi-instance/): two instances sharing limits. Set `AUTH_REDIS_ADDR` to count them in Redis.
- https://pkg.go.dev/github.com/ubgo/auth/contrib/redis

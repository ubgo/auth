# Session strategies: where sessions live, what skips the lookup, how long they last

One email-and-password app, with every way the library can store and check a session behind three flags. Each choice is a complete wiring an app would copy: the database table (the default), this process's memory, Redis, a store of your own, or no store at all with the token carrying the session; a sealed snapshot the client holds, or a cache in the process or in Redis, in front of the lookup; and lifetimes chosen per client, so a browser signs out after a month and a phone app stays in for a year.

## Run it

```sh
cd examples
go run ./session-strategies                       # sessions in the database
go run ./session-strategies -store stateless      # no session store
go run ./session-strategies -store custom -cache snapshot
go run ./session-strategies -lifetimes by-client
```

Flags: `-store database|memory|redis|custom|stateless`, `-cache none|snapshot|memory|redis`, `-lifetimes default|by-client`. The `redis` choices need `AUTH_REDIS_ADDR` (for example `127.0.0.1:6379`) and refuse to start without it. `stateless` and `snapshot` seal with `AUTH_SESSION_KEY`, 64 hex characters; unset, the program makes a key for this run and warns that every session ends with the process. The database is `session-strategies.db` (SQLite) in the current directory; a `-store` choice other than `database` still uses it for users, and `-store stateless` adds nothing to it per session. Run the tests with `go test ./session-strategies`; the Redis ones say they are skipped unless `AUTH_REDIS_ADDR` is set.

## Which one

| Choice | Each request costs | A revocation (sign-out elsewhere, ban) takes effect | Gives up |
|---|---|---|---|
| `-store database` (default) | one query: `auth_session` joined to `auth_user` | at once | nothing; joins your transactions, so a rolled-back sign-up leaves no session |
| `-store memory` | a map lookup, then the user by primary key | at once, in this process | sessions end on restart and are not shared between instances; the store joins no transaction |
| `-store redis` | one Redis round trip, then the user by primary key | at once, on every instance | joins no transaction; a rolled-back sign-up can leave a session nobody holds the token of, which expires by itself |
| `-store custom` | whatever your store costs, then the user by primary key | as your store says | your store must keep the contract; `sessiontest.Run` checks it |
| `-store stateless` | opening the token, then the user by primary key | bans at once; sign-out-all and password reset at once through `auth_user.sessions_valid_after`; a sign-out on one device only clears that device's cookie | listing sessions beyond the current one and revoking one by one (`auth.sessions_unavailable`); the token is about 400 characters; rotating the key signs everyone out |
| `-cache snapshot` | nothing on a hit: the client sends back a sealed copy, and no store or table is touched | when the entry expires, at most the cache TTL (two minutes here, capped at fifteen by the core) | a cookie or header of about 1.2 KB on every request |
| `-cache memory` | a map lookup on a hit | when the entry expires, in this process | one cache per instance |
| `-cache redis` | one Redis round trip on a hit | when the entry expires, on every instance | a Redis |
| `-lifetimes by-client` | nothing extra: the lifetime is stored with the session | unchanged | nothing |

Pick the default until a measurement says the session query costs too much. Then add a cache: `snapshot` if you run several instances and want no shared state, `memory` for one instance, `redis` when several instances must revoke at the same moment. Move the store to Redis when the sessions table is the database's hottest one. Go stateless when the server should hold nothing per session and you can live without a session list. Choose `by-client` lifetimes as soon as a native app signs in through the same API as the browser.

## Walkthrough

### The default: sessions in the database

The session is a row, the cookie holds its random token, and the session list is the row's own data:

```sh
curl -si -c c.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b c.txt localhost:8081/me
curl -s -b c.txt localhost:8081/auth/sessions
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=dAcl6CmF-Mh7er9ZMzT1xs81rxnad0_ZRI-X-QA4vkI; Path=/; Expires=Wed, 07 Oct 2026 05:51:19 GMT; HttpOnly; Secure; SameSite=Lax

{"user":{"id":"usr_7psa7dni26ypbfa4h4isrmws","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_7psa7dni26ypbfa4h4isrmws","credential":"cookie","expiresAt":"2026-10-07T05:51:19.460611Z"}
{"sessions":[{"id":"ses_3yvb5dlkdedvbole2bgarl2f","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-09-30T05:51:19.460611Z","lastSeenAt":"2026-09-30T05:51:19.460611Z"}]}
```

### Stateless: the token is the session

`go run ./session-strategies -store stateless`. The cookie is now the sealed session itself, and `auth_session` stays empty:

```sh
curl -si -c laptop.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}' | grep '^Set-Cookie'
curl -s -c phone.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
sqlite3 session-strategies.db 'select count(*) from auth_session'
```

```text
Set-Cookie: __Host-auth_session=kUvWnyJn6nOR6eTRfg1CxTpdm7J0JDq9H3fWopr6odmw_BmRBKHkTpCIZz5EWaFa5SVDaOPDOeopAXeG0_M28hlByBFFBLZbIjMR0jAiUJIMjgcfPk4Yk0foBoct3UkFmIsqjVuCCO9tE_0paMM_pAv5r9LdnCFRyvk9wPfoWucaaPO-luLmBa8ob0QLAA3-w8fx_Mae4gNlN7W9BNWJKDJhqjLwMElRKyB9CDJ-RRrJKZ7cfBkpVqd8o9OUMQTCLl_bHshZwXVMGjb_X66eRDYd9mGP5AJJbO3irsyWmh-d0iSwui5mi7qk0cRXXXHABbKUxizlK_aIZflEW-ezXhFaTg; Path=/; Expires=Wed, 07 Oct 2026 05:51:22 GMT; HttpOnly; Secure; SameSite=Lax
{"user":{"id":"usr_bp4ltjoh77utxty3pcx5sua2","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
0
```

The server can describe only the session that asks, and cannot end another one by id, because nothing about the others exists anywhere:

```sh
curl -s -b laptop.txt localhost:8081/auth/sessions
curl -s -b laptop.txt -X POST localhost:8081/auth/sessions/revoke -H 'Origin: http://localhost:8081' -d '{"id":"ses_other"}'
```

```json
{"sessions":[{"id":"ses_kaeunx2ta72cxtnqxvtocdjc","current":true,"impersonated":false,"ip":"","userAgent":"","createdAt":"2026-09-30T05:51:22.469988Z","lastSeenAt":"2026-09-30T05:51:22.469988Z"}]}
{"error":{"code":"auth.sessions_unavailable","message":"Sessions cannot be listed or ended one by one here."}}
```

"Sign out everywhere" still works. From the phone, it sets a cutoff on the user row, and the laptop's token, issued before it, stops opening a session:

```sh
curl -s -b phone.txt -X POST localhost:8081/auth/sign-out-all -H 'Origin: http://localhost:8081'
curl -s -b laptop.txt localhost:8081/me
sqlite3 session-strategies.db 'select sessions_valid_after from auth_user'
```

```text
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
2026-09-30 05:51:22.723507 +0000 UTC
```

A password reset sets the same cutoff, so a stolen token dies with the old password in every store.

### A store of your own, with the snapshot cache in front

`go run ./session-strategies -store custom -cache snapshot`. The custom store is [`logstore.go`](logstore.go): it delegates to the in-memory store and logs every call, so the log shows exactly when the core reaches the store. The first request after sign-up looks the session up once and hands the client a sealed copy; the next requests send the copy back and reach nothing:

```sh
curl -s -c c.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -si -b c.txt -c c.txt localhost:8081/me | grep '^Set-Cookie\|^{'
curl -s -b c.txt localhost:8081/me
curl -s -b c.txt localhost:8081/me
```

```text
{"user":{"id":"usr_sfu5argaemq4kofqcvhv2ead","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
Set-Cookie: __Host-auth_session_cache=9puLmbiPqpDpyFBA0zpVNRzSP4ufzZFOd_scgpmW2T3Ex7JPI5x3UvYktsqYy2YBTFOLwCyqu_Hxak1u_fztpreIHvqVZJ5lc1m6nKbmZC4Phvt1nmsFSH1ENHbuYSK5WcvWhNK_KoFHOtgU3mGbJ2fZkX7pEVW3KPDMAno5goc8096pQQDqMbYePcVvSPyP5IXPf0rEkBVytoJIGjh6DVYESjNj3sgKZdh42lJyiaRdp9qkQymgHN5oFEaAJy7y6Ttc5fX1gvLO8WHTQwTa3ZoJuMqT5_aVE4wL4BFEV0AZf7pJ-AHl312CSLVFR4EBKDtDnEjXs8UgCacZ03MWaIiJ2X7XG3qokelchbcB2XlX9pvxb4-HGH7Jk0hbXT-POZDr4idITluMU39TKnI1olu6EAcIE_3QU82nUOXCrwLHarpk8ucGBF3VWcMStKQy4tifduK95XlZEMxepEKb4pj06A3Bm5ktwA3KE5f-qkNdBjTW77ldaj9xXia72IUUddaT9OsK7Rg5FK6sq9-Wvm_NFnx3KpM3lR6P_rb8Tpw_8E5r8SnZtHYk_uiR4Ud0eAFDyJiMhrRChef3HJii5J55NFxxstY9L1-bWaPjSNGxLd_Qkv-8BXYhR2wnihDn009XUB2WBhYclLngeqpZRrlTUs3qVF19O0_PuhjX9c2QTJaXh9KbNQWDeZh8pxYsHfWPX6H50gNwm7IXXswfTJXfLu4f63sU6f4vTrpE5PCwkz0wphqLEA-eOVc4NDghs-wltO6bXSk0WncU9zF-WMX58mOHGu0MTgaSNkubBy5sBFzPPFWeVdePfnifll-LIdTXz9rtrhPLEQ85I82UKLazAv_d6ySpdbiKqt0QsQ8mO59mPxLVUXt-cFqa9omKsiCEnDSc1yQLwCRgjETATRUxqrXlW4b8DpZ04DlHoroAZPo5gQ; Path=/; Expires=Wed, 30 Sep 2026 05:53:23 GMT; Max-Age=120; HttpOnly; Secure; SameSite=Lax
{"id":"usr_sfu5argaemq4kofqcvhv2ead","credential":"cookie","expiresAt":"2026-10-07T05:51:23.81146Z"}
{"id":"usr_sfu5argaemq4kofqcvhv2ead","credential":"cookie","expiresAt":"2026-10-07T05:51:23.81146Z"}
{"id":"usr_sfu5argaemq4kofqcvhv2ead","credential":"cookie","expiresAt":"2026-10-07T05:51:23.81146Z"}
```

The server log shows one insert at sign-up, one find for the first `/me`, and nothing for the two that followed:

```text
2026/09/30 11:21:23 session store: insert ses_gsxtxzehrdjko4wztigltotw for usr_sfu5argaemq4kofqcvhv2ead
2026/09/30 11:21:23 session store: find
2026/09/30 11:21:23 session store: delete ses_gsxtxzehrdjko4wztigltotw
```

The delete is the sign-out, which also clears the client's copy:

```sh
curl -si -b c.txt -c c.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081' | grep '^Set-Cookie\|^{'
```

```text
Set-Cookie: __Host-auth_session_cache=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-auth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
{"ok":true}
```

The snapshot is sealed with the session key, bound to the token it was made for, and worth nothing with any other token. A snapshot that is still valid answers for a session that was revoked or banned elsewhere until it expires, which is why the TTL is short and capped. In bearer mode the same copy travels in `Auth-Session-Cache` and `Set-Auth-Session-Cache` headers.

### Lifetimes per client

`go run ./session-strategies -lifetimes by-client`. A browser session slides for a week; an app's for ninety days. The choice is made when the session is created and stored with it, so every later refresh honours it:

```sh
curl -s -b c.txt localhost:8081/me
curl -si -D app.txt -X POST localhost:8081/auth/password/sign-in -H 'Auth-Token-Mode: bearer' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}' | grep '^Set-Auth'
curl -s -H "Authorization: Bearer t4QNhTKVYWFQR6Jp3nDzEaXsX9VlmEVPQ7oRqUQM-V8" localhost:8081/me
```

```text
{"id":"usr_jaq4gfnqwrfcwttorvlk2ync","credential":"cookie","expiresAt":"2026-10-07T05:54:18.483135Z"}
Set-Auth-Token: t4QNhTKVYWFQR6Jp3nDzEaXsX9VlmEVPQ7oRqUQM-V8
Set-Auth-Token-Expires: 2026-12-29T05:54:18Z
{"id":"usr_jaq4gfnqwrfcwttorvlk2ync","credential":"bearer","expiresAt":"2026-12-29T05:54:18.592828Z"}
```

## The code

Every wiring is one option, chosen in `sessionOptions`:

```go
case storeMemory:
	opts = append(opts, auth.WithSessionStore(auth.NewMemorySessionStore()))
case storeRedis:
	opts = append(opts, auth.WithSessionStore(redisrate.NewSessionStore(rdb)))
case storeCustom:
	opts = append(opts, auth.WithSessionStore(newLoggingStore(auth.NewMemorySessionStore(), log.Default())))
case storeStateless:
	opts = append(opts, auth.WithStatelessSessions(cfg.Key))
```

```go
case cacheSnapshot:
	opts = append(opts, auth.WithSessionCache(auth.NewSnapshotCache(cfg.Key), cacheTTL))
case cacheMemory:
	opts = append(opts, auth.WithSessionCache(auth.NewMemorySessionCache(memoryCacheEntries), cacheTTL))
case cacheRedis:
	opts = append(opts, auth.WithSessionCache(redisrate.NewSessionCache(rdb), cacheTTL))
```

```go
opts = append(opts, auth.WithSessionPolicy(auth.ByCredential(webLifetime, appLifetime)))
```

A store of your own implements `auth.SessionStore`: seven methods, no raw tokens (only their hashes), and the contract in the interface's documentation. [`logstore.go`](logstore.go) is one that delegates; `TestCustomStore` runs it through `sessiontest.Run`, the same suite the SQL, memory and Redis stores pass, so a rule it broke would be named before it shipped.

`main_test.go` drives every store the same way (sign up, `/me`, sign out, refused), adds Redis when `AUTH_REDIS_ADDR` is set, and pins each promise: stateless leaves `auth_session` empty, answers `auth.sessions_unavailable` for another session's id, and ends the laptop's session when the phone signs out everywhere; the snapshot and memory caches answer three requests with one store lookup, counted through the logging store; a bearer sign-in gets the app lifetime and a cookie the web one; a bad flag, a missing Redis address and a malformed key are refused.

## Limits

- A store other than the database joins no transaction: with `-store memory|redis|custom`, a sign-up whose surrounding transaction rolls back can leave a session whose token nobody holds. It expires by itself.
- Under a cache, a revocation made elsewhere reaches a device holding a valid entry only when the entry expires; keep the TTL short.
- Stateless sessions list no IP or user agent: those stay out of the token, which the client carries on every request.
- The Redis choices were run against a local Redis at 127.0.0.1:7012; the transcripts above use the database, stateless and custom stores.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithSessionStore`, `NewMemorySessionStore`, `WithStatelessSessions`, `WithSessionCache`, `NewSnapshotCache`, `NewMemorySessionCache`, `WithSessionPolicy`, `ByCredential`, `SessionLifetime`
- [`sessiontest`](https://pkg.go.dev/github.com/ubgo/auth/sessiontest): `Run`, the contract suite for a store of your own
- [`contrib/redis`](https://pkg.go.dev/github.com/ubgo/auth/contrib/redis): `NewSessionStore`, `NewSessionCache`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `CacheCookieName`, `SessionCacheHeader`, `TokenModeHeader`
- Related: [multi-instance](../multi-instance) (rate limits shared the same way), [quickstart](../quickstart).

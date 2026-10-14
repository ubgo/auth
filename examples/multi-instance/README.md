# Several instances sharing rate limits

Two instances of one app behind a load balancer, on one database. Sessions already live in the database, so a cookie from one instance works on the other. Rate limits do not, by default: each process counts in memory, so five wrong passwords spread over two instances look like two or three to each. `auth.WithDBRateStore()` moves the counters into the database, and the limits hold across every instance.

## Run it

```sh
cd examples
go run ./multi-instance
```

Instance A listens on `http://localhost:8081` and instance B on `http://localhost:8082`, both with the public URL `http://localhost:8081` (the load balancer's). They are two `*auth.Auth` values in one process so the demo is one command; in production each is its own process on its own machine, and the code is the same. The database is `multi-instance.db` (SQLite). Run the tests with `go test ./multi-instance`.

## Walkthrough

The log says where the counters are:

```text
2026/09/29 13:48:29 rate limits: counted in the database table auth_rate_limit
2026/09/29 13:48:29 instance A listening on localhost:8081
2026/09/29 13:48:29 instance B listening on localhost:8082
```

Sign up on A, then use the cookie on B. Every response names the instance that answered in `X-Instance`:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -si -b cookies.txt localhost:8082/me
```

```text
{"user":{"id":"usr_4xmjvx3cv2fjv64qh2feimjo","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
HTTP/1.1 200 OK
Content-Type: application/json
X-Instance: B

{"id":"usr_4xmjvx3cv2fjv64qh2feimjo","hello":"Alice"}
```

Five wrong passwords, round-robin across the two instances. The request `Origin` is the public URL whichever instance receives it:

```sh
for port in 8081 8082 8081 8082 8081; do
  curl -s -X POST localhost:$port/auth/password/sign-in -H 'Origin: http://localhost:8081' \
    -d '{"identifier":"alice@example.com","password":"wrong"}'
done
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

B has seen only two of them, but the sixth attempt is refused there, even with the right password, until the 15-minute window ends:

```sh
curl -si -X POST localhost:8082/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 900
X-Instance: B

{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

The counters are rows, one per key and window. Keys are hashed, so the table never holds an address or an IP:

```sh
sqlite3 multi-instance.db 'SELECT hits, expires_at FROM auth_rate_limit'
```

```text
1|2026-09-29 09:00:00 +0000 UTC
1|2026-09-29 09:00:00 +0000 UTC
6|2026-09-29 08:19:00 +0000 UTC
6|2026-09-29 08:30:00 +0000 UTC
```

Finished windows are deleted as the store runs, and by `a.Sweep` or `auth sweep` on an `*auth.Auth` built with the same option (see the [cli](../cli) example).

## Redis instead

A database write per counted request is fine for most apps. If you already run Redis, or the auth routes are hot, count there instead with [`contrib/redis`](https://pkg.go.dev/github.com/ubgo/auth/contrib/redis), a separate module so go-redis reaches only apps that import it. This example switches when `AUTH_REDIS_ADDR` is set:

```sh
AUTH_REDIS_ADDR=127.0.0.1:6379 go run ./multi-instance
```

```go
client := redis.NewClient(&redis.Options{Addr: redisAddr})
return auth.WithRateStore(redisrate.New(client)), nil
```

`TestMultiInstance_Redis` runs the same proof against Redis when `AUTH_REDIS_ADDR` is set, and is skipped otherwise.

## The code

Every instance gets the same plugins, the same database and the same store; the store option is the only line that differs from a single-instance app:

```go
auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithDBRateStore(), // or auth.WithRateStore(redisrate.New(client))
	auth.WithPlugins(email.New(...), password.New()),
)
```

`main_test.go` proves it both ways: with the database store, a session from A works on B and five wrong passwords alternating between A and B get the sixth refused on B; with two in-memory stores (the default), the same six attempts are all answered as wrong passwords, because each instance counted only its own.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithDBRateStore`, `WithRateStore`, `NewMemoryRateStore`, `TableNameRateLimit`
- [`contrib/redis`](https://pkg.go.dev/github.com/ubgo/auth/contrib/redis) (`redisrate`): `New`, `KeyPrefix`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), whose sign-in allows 5 attempts per account in 15 minutes and 20 per IP in a minute
- One instance: [quickstart](../quickstart). Migrating once per deploy: [cli](../cli).

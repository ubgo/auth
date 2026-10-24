# Session tuning: lifetimes, extras, addresses, a KV store and stateless switches

One email-and-password app that turns the session knobs the defaults leave alone. Every wiring shares a tighter lifetime than the default (30 minutes idle, 12 hours at most, the expiry written at most every 5 minutes) and app data returned with every session. Flags then turn on the rest: no IP addresses kept, sessions in a key-value store instead of the `auth_session` table, reads that never slide the expiry, and the stateless-token switches.

| Option | What it changes | Default without it |
|---|---|---|
| `auth.WithSession(auth.SessionConfig{...})` | idle timeout, hard lifetime, how often an active session's expiry is written | `auth.DefaultSessionConfig`: 7 days idle, 30 days at most, written at most daily |
| `auth.WithSessionExtras(fn)` | adds `extras` to `GET /auth/session` | no `extras` field |
| `auth.WithDeviceSessionExtras()` | runs the same function for every account in `GET /auth/device-sessions` (needs `WithMultiSession`) | no `extras` in the device list |
| `auth.WithoutIPTracking()` | sessions keep no client address; the user agent is still kept | the address is stored and listed |
| `auth.WithSecondaryStorage(kv)` | sessions and rate-limit counters live in your key-value store | sessions in `auth_session`, counters in process memory |
| `auth.WithDeferredSessionRefresh()` | a read reports `needsRefresh` instead of sliding; `POST /auth/session/refresh` slides | every lookup slides when due |
| `auth.WithStatelessVersion(n)` | stateless tokens carry `n`; raising it signs everyone out without a new key | version 0 |
| `auth.WithStatelessRefreshWithoutRead(d)` | a stateless request uses the token's copy of the user for `d` after the last read | every request loads the user |

## Run it

```sh
cd examples
go run ./session-tuning                           # lifetimes + extras, sessions in the database
go run ./session-tuning -no-ip                    # keep no IP address with a session
go run ./session-tuning -kv                       # sessions and rate counters in a key-value store
go run ./session-tuning -deferred                 # reads never slide; the client asks for it
go run ./session-tuning -stateless -version 1     # sealed tokens; raise -version to sign everyone out
go run ./session-tuning -stateless -read-every 2m # stateless, the user loaded once per 2 minutes
```

It creates `session-tuning.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081` (`PORT` changes it; the output below was captured on 8097). A stateless run seals tokens with `AUTH_SESSION_KEY` (64 hex characters); unset, it uses a random key, so every session ends when the process does. Mail is printed to the log instead of sent. Run the tests with `go test ./session-tuning`.

## The code

The lifetime, the extras function and the switches are each one declaration in `main.go`:

- `sessionConfig` is the `auth.SessionConfig` passed to `WithSession`. Set all three fields: a field left at zero is not filled from the default (see below).
- `sessionExtras` returns the app's own struct. Its signature is `auth.SessionExtras`, whose result is only ever JSON-encoded.
- `switches` turns each flag into its option, one line per switch, so an app copies the lines it wants.
- `memoryKV` is a complete `auth.SecondaryStorage` over a map: `Get`, `Set`, `Delete` and a fixed-window `Increment`. An adapter over Redis, Memcached or a cloud KV implements the same four methods.

## Walkthrough

Sign up. The answer sets the session cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8097/auth/password/sign-up -H 'Origin: http://localhost:8097' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"user":{"id":"usr_wrnprox5oklekk4o7j5b7myp","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

`GET /auth/session` carries the extras, and the expiry is 30 minutes away, not 7 days:

```sh
curl -s -b cookies.txt localhost:8097/auth/session
```

```json
{"user":{"id":"usr_wrnprox5oklekk4o7j5b7myp","name":"","image":""},"expiresAt":"2026-10-09T03:58:49.449551Z","extras":{"plan":"free","signedInAt":"2026-10-09T03:28:49.449551Z"}}
```

The account switcher's list carries them too, under `WithDeviceSessionExtras`:

```sh
curl -s -b cookies.txt localhost:8097/auth/device-sessions
```

```json
{"sessions":[{"id":"ses_oaketcdtbbgiuzabqvpibpge","user":{"id":"usr_wrnprox5oklekk4o7j5b7myp","name":"","image":""},"active":true,"expiresAt":"2026-10-09T03:58:49.449551Z","extras":{"plan":"free","signedInAt":"2026-10-09T03:28:49.449551Z"}}]}
```

The session list shows the address the session was created from:

```sh
curl -s -b cookies.txt localhost:8097/auth/sessions
```

```json
{"sessions":[{"id":"ses_oaketcdtbbgiuzabqvpibpge","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:28:49.449551Z","lastSeenAt":"2026-10-09T03:28:49.449551Z"}]}
```

Run with `-no-ip`, sign up again, and the same list keeps no address. The user agent is still there, so the list can still say which browser a session belongs to:

```json
{"sessions":[{"id":"ses_fvluymzkhby3bx5u2hxzzupe","current":true,"impersonated":false,"ip":"","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:28:51.120071Z","lastSeenAt":"2026-10-09T03:28:51.120071Z"}]}
```

Stateless tokens and their version. Start with a fixed key and sign up:

```sh
export AUTH_SESSION_KEY=$(openssl rand -hex 32)
go run ./session-tuning -stateless
curl -s -c cookies.txt -X POST localhost:8097/auth/password/sign-up -H 'Origin: http://localhost:8097' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}' > /dev/null
curl -s -b cookies.txt localhost:8097/auth/session
```

```json
{"user":{"id":"usr_dbapntzpvmmbarjcrzp3s7xj","name":"","image":""},"expiresAt":"2026-10-09T03:59:00.298923Z","extras":{"plan":"free","signedInAt":"2026-10-09T03:29:00.298923Z"}}
```

Restart with `-version 1` and the same key. The token was sealed under version 0, so it no longer opens: everyone is signed out, and nobody had to rotate the key:

```sh
go run ./session-tuning -stateless -version 1
curl -s -b cookies.txt localhost:8097/auth/session
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## What the tests prove

`main_test.go` runs every wiring end to end over an HTTPS test server, SQLite in a temp dir and a clock the test moves:

- `TestSlidingLifetime`: a session used after `RefreshAfter` slides to `IdleTimeout` from now; one left idle past `IdleTimeout` is signed out; one used every 15 minutes still ends at `MaxLifetime`.
- `TestExtras`: `GET /auth/session` and `GET /auth/device-sessions` both carry `{"plan":"free","signedInAt":...}`.
- `TestIPTracking`: the stored session and the list hold `127.0.0.1` by default and an empty address under `WithoutIPTracking`; the user agent is kept in both.
- `TestSecondaryStorage`: after sign-up the key-value store holds one `auth:session:` key and a rate counter, `auth_session` holds no row, and sign-out removes the key.
- `TestDeferredRefresh`: after `RefreshAfter` a read answers `"needsRefresh":true` with the old expiry; `POST /auth/session/refresh` slides it.
- `TestStatelessVersion`: a redeploy with a higher version refuses the old token; a new sign-in works.
- `TestStatelessReadEvery`: a "sign out everywhere" ends a stateless token on its next request by default; under `WithStatelessRefreshWithoutRead(2m)` the token keeps working until the interval since its last read has passed.

## What can go wrong

- **A partial `SessionConfig`.** A field left at zero keeps `DefaultSessionConfig`'s value: `auth.SessionConfig{IdleTimeout: time.Hour}` changes the idle timeout and keeps the 30-day hard lifetime. A negative field fails `auth.New` with `auth.ErrBadSessionConfig`.
- **The first request after a stateless sign-in always loads the user.** The sign-in token carries no copy of the user; the first request reads it and reseals the token with the copy. `WithStatelessRefreshWithoutRead` starts saving queries from the second request.
- **`WithStatelessVersion` without `WithStatelessSessions`** fails `auth.New`, and so does a negative version.
- **`WithDeviceSessionExtras` without `WithMultiSession` and `WithSessionExtras`** fails `auth.New`.
- **`WithSecondaryStorage` and a later `WithSessionStore` or `WithRateStore`:** the later option replaces its half.
- **A cookie jar drops a cookie whose expiry is past by the real clock**, so a test that sets the library's clock to a fixed date in the past sees every request signed out. The tests start their clock at the real time.

## Next

- [Sessions](../../docs/concepts/sessions.md): stores, caches, stateless tokens and lifetimes.
- [Configuration](../../docs/concepts/configuration.md): every option with its default.
- [session-strategies](../session-strategies): the same app with every session store and cache.
- [account-settings](../account-settings): the device list, switching and revoking sessions.

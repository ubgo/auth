# Session revocation: end a stateless session at once

Stateless sessions keep nothing on the server: the token is the session, sealed with a key, and `auth_session` stays empty. The price is that a sign-out can only clear the cookie, so a copy of the token taken before (a stolen cookie, a phone that was lost) keeps working until it expires. A revocation list closes that gap: `auth.WithSessionRevocations` makes sign-out, revoking a session and the second-factor promotion put the session's id on the list, and every stateless lookup refuses an id on it. This example uses the in-memory list; several instances share `contrib/redis`'s.

## Run it

```sh
cd examples
go run ./session-revocation
```

It creates `session-revocation.db` (SQLite, users only) and listens on `http://localhost:8081` (`PORT` moves it). `AUTH_SESSION_KEY` is the sealing key, 64 hex characters, the same on every instance; unset, the program makes a key for this run and warns that every session ends with the process. Run the tests with `go test ./session-revocation`.

The transcript below was captured with `PORT=18431`, because 8081 was taken on the machine that ran it.

```text
2026/10/09 15:56:39 WARN AUTH_SESSION_KEY is not set: using a random key for this run, so every session ends when the process does
2026/10/09 15:56:39 listening on http://localhost:18431
```

## Walkthrough

Sign up in bearer mode, so the token is easy to keep and replay. It is about 350 characters, because it carries the session:

```sh
curl -si -X POST localhost:18431/auth/password/sign-up -H 'Auth-Token-Mode: bearer' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}' | grep -i '^Set-Auth-Token'
```

```text
Set-Auth-Token: R90T3lxiFTOAnF1Fjb1dMVqyBBL_4W-7E1koZ2alWwbivRNUch6WrGd3KZ4IaDMyODZ1DuGbRPiOl3m4Pg01E6zWVWr41CcmJHkamv44emdfIN5MxegY417JPFm-g5f8IKFbzh3-m0OcrwfmEgl0QJGK20V4mm6rCTcnHFb77OoHptk4P_kjlv5BF7E7ydUZvcMaoMxOuou8DsQNVGqh1KMKHawMUVYG4GBs5bjRy990YzFGj0PL7hKReXvR0dA6BlohrJNAn9KcWdwjhLYcK1GwL6YiZgAzn2aCtcfUZe5miFjdt-mFIFw9S0dYRBO9dAsEaDo72n59-V9_U06viXkbPA
Set-Auth-Token-Expires: 2026-10-16T10:26:41Z
```

The token works, sign-out answers ok, and the same token is refused afterwards, although nothing about the session was ever stored:

```sh
curl -s localhost:18431/me -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:18431/auth/sign-out -H "Authorization: Bearer $TOKEN"
curl -s localhost:18431/me -H "Authorization: Bearer $TOKEN"
sqlite3 session-revocation.db 'select count(*) from auth_session'
```

```text
{"id":"usr_uj5xbcdckle7zzz3r4sthcta"}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
0
```

Without the list, the third request would answer `200` until the token expired; `TestWithoutTheListATokenOutlivesSignOut` pins that.

## The code

<!-- ds:block id=sessionrevocation-options-8vk2mq4d -->
**sessionOptions** · [`examples/session-revocation/main.go:121-129`](main.go#L121-L129)

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

The list stores the session id, never the token, until the latest instant any token of that session could still be valid, so it stays small. A failure to read it fails the request rather than let a possibly revoked session in. A list of your own implements `auth.SessionRevocations` (`Revoke`, `Revoked`) and runs `sessiontest.RunRevocations` in its tests.

`main_test.go` runs the same wiring on `httptest` in bearer mode: a token copied before sign-out is `auth.signed_out` after it, another session of the same user keeps working, `auth_session` stays empty, the same flow without the list leaves the token working, and a malformed `AUTH_SESSION_KEY` is refused.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithStatelessSessions`, `WithSessionRevocations`, `NewMemorySessionRevocations`, `SessionRevocations`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `TokenModeHeader`, `SetTokenHeader`
- Related: [session-strategies](../session-strategies) compares every session store, stateless included; the guide is [docs/extending/08-extend-sessions.md](../../docs/extending/08-extend-sessions.md) Step 5.

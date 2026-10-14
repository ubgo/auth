# JWT session: a token on every session read, and a session cache that is a JWT

A single-page app that calls another service needs a token for it. With `jwt.IssueOnSession()`, every `GET /auth/session` answers a fresh short-lived JWT in the `Set-Auth-JWT` header, so the page never makes a separate `POST /auth/jwt/token` call. With `jwt.NewSessionCache(jw)` as the session cache, the client's copy of its session (the cookie that lets most requests skip the session lookup) is a JWT signed by the same plugin instead of a sealed blob. A stand-in service at `/reports` verifies tokens with the published keys and no database.

## Run it

```sh
cd examples
go run ./jwt-session
```

It creates `jwt-session.db` (SQLite) and listens on `http://localhost:8081` (`PORT` moves it). Set `JWT_SIGNING_KEY` to an Ed25519 seed (32 bytes, base64url without padding) so tokens survive a restart; unset, a key is generated for the run and the log says so. Run the tests with `go test ./jwt-session`.

The transcripts below were captured with `PORT=8091`, because 8081 was taken on the machine that ran them.

```text
2026/10/09 15:54:51 JWT_SIGNING_KEY is not set: signing with a new key; tokens stop verifying when the process restarts
2026/10/09 15:54:51 listening on http://localhost:8091
```

## Walkthrough

Sign up, then read the session. The answer carries the token, exposed to scripts on another origin, and sets the cache cookie:

```sh
curl -s -c c.txt -X POST localhost:8091/auth/password/sign-up -H 'Origin: http://localhost:8091' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -si -b c.txt -c c.txt localhost:8091/auth/session
```

```text
HTTP/1.1 200 OK
Access-Control-Expose-Headers: Set-Auth-JWT
Set-Auth-Jwt: eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IldLdmFVSkZIT1RCYVM1cWsifQ.eyJhdWQiOiJyZXBvcnRzIiwiZXhwIjoxNzkxNTQxNzkyLCJpYXQiOjE3OTE1NDE0OTIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA5MSIsImp0aSI6IkZMR0tSMzVIUlFGV0tKRTczNUhDT1NVNkZEIiwibmJmIjoxNzkxNTQxNDkyLCJzaWQiOiJzZXNfZ254ZGRoN2t2NGNrenk1emR5M243Nnd2Iiwic3ViIjoidXNyXzZrdXBjNzJhZTY2b2hya2d6anh1cXBlcCJ9.FuD-nEzg7rMTZ2sfXGtX78GtM7fqdAbayOovNjpngLW6fIDTCMwd5mQAJ1U713scl-FLfBQYcke8P_fMWwX_Bg
Set-Cookie: __Host-auth_session_cache=eyJhbGciOiJFZERTQSIsInR5cCI6InViZ28tYXV0aC5zZXNzaW9uLWNhY2hlK2p3dCIs…; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax
{"user":{"id":"usr_6kupc72ae66ohrkgzjxuqpep","name":"","image":""},"expiresAt":"2026-10-16T10:24:52.455572Z"}
```

(Go writes header names in canonical form, so curl prints `Set-Auth-Jwt`; header names are case-insensitive. The cookie value is shortened here.)

The other service accepts the token (`TOKEN` holds the `Set-Auth-Jwt` value) and reads the user and session from it:

```sh
curl -s localhost:8091/reports -H "Authorization: Bearer $TOKEN"
```

```json
{"user":"usr_6kupc72ae66ohrkgzjxuqpep","session":"ses_gnxddh7kv4ckzy5zdy3n76wv"}
```

The cache cookie is a JWT too, with the header `typ` `ubgo-auth.session-cache+jwt`, so a verifier of access tokens refuses it; sent to `/reports` it answers `{"error":"token not accepted"}` and the log says why:

```text
2026/10/09 15:54:52 reports: jwt: token is not valid: type "ubgo-auth.session-cache+jwt"
```

The session is read from that copy, not from the database. Delete every session row and `/me` still answers until the copy expires (one minute here); sign-out clears the copy and the session ends:

```sh
sqlite3 jwt-session.db 'delete from auth_session'
curl -s -b c.txt localhost:8091/me
curl -s -c c.txt -b c.txt -X POST localhost:8091/auth/sign-out -H 'Origin: http://localhost:8091'
curl -s -b c.txt localhost:8091/me
```

```text
{"id":"usr_6kupc72ae66ohrkgzjxuqpep","name":""}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

That is the trade of any client-held cache: a revocation made elsewhere (a ban, a sign-out from another device) takes up to the cache TTL to reach a client holding a copy. And unlike the sealed `auth.NewSnapshotCache`, the claims are signed, not encrypted: whoever holds the cookie can read the session's IP address and user agent.

## The code

<!-- ds:block id=jwtsession-newjwt-4hq8mz2c -->
**newJWT** · [`examples/jwt-session/main.go:127-133`](main.go#L127-L133)

```go
func newJWT(key ed25519.PrivateKey) *jwt.Plugin {
	return jwt.New(
		jwt.WithSigningKey(key),
		jwt.Audience(audience),
		jwt.IssueOnSession(),
	)
}
```
<!-- /ds:block hash=48d9cd -->

<!-- ds:block id=jwtsession-newauth-v7kx3pw9 -->
**newAuth** · [`examples/jwt-session/main.go:139-150`](main.go#L139-L150)

```go
func newAuth(db *sql.DB, jw *jwt.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			jw,
		),
		auth.WithSessionCache(jwt.NewSessionCache(jw), cacheTTL),
	)
}
```
<!-- /ds:block hash=9fd615 -->

The report service holds only the public keys, the issuer and the audience; a real one fetches the keys with `jwt.NewRemoteKeys` from `/auth/jwt/jwks`:

<!-- ds:block id=jwtsession-newverifier-2nd6tq8r -->
**newVerifier** · [`examples/jwt-session/main.go:167-169`](main.go#L167-L169)

```go
func newVerifier(jw *jwt.Plugin) jwt.Verifier {
	return jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: baseURL, Audience: audience}
}
```
<!-- /ds:block hash=233f5a -->

`main_test.go` runs the same wiring behind an `httptest` TLS server: a signed-out session read carries no token; a signed-in one carries a token the report service accepts for the same user and session, with the header exposed; the cache cookie is a JWT of the cache type that the report service refuses; `/me` answers from the copy after the session row is deleted; sign-out clears the copy; and a fixed `JWT_SIGNING_KEY` gives the same key every start.

## What this used

- [`plugin/jwt`](https://pkg.go.dev/github.com/ubgo/auth/plugin/jwt): `IssueOnSession`, `SetJWTHeader`, `NewSessionCache`, `SessionCacheType`, `Verifier`, `KeysFromJWKS`, `PublicKeys`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithSessionCache`
- Related: [api-keys-and-jwt](../api-keys-and-jwt) mints tokens with `POST /auth/jwt/token`; [jwt-keys](../jwt-keys) rotates keys and verifies from a remote key set; [session-strategies](../session-strategies) compares every session cache. The guide is [docs/plugins/jwt.md](../../docs/plugins/jwt.md) Steps 12 and 13.

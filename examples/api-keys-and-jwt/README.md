# API keys and JWTs: programs acting for a user

Two ways a program, rather than a person in a browser, proves who it acts for. A script calls this app's API with an API key that carries scopes. Another service receives a short-lived JWT minted from a session and verifies it with the app's published public keys, without ever touching the auth database.

## Run it

```sh
cd examples
go run ./api-keys-and-jwt
```

It creates `api-keys-and-jwt.db` (SQLite), serves the app on `http://localhost:8081` and a second program, the report service, on `http://localhost:8082`. Set `JWT_SIGNING_KEY` to a 32-byte Ed25519 seed (base64url, no padding) to keep the signing key across restarts; unset, a new one is generated and the log says so. Run the tests with `go test ./api-keys-and-jwt`.

```text
2026/09/29 13:49:08 JWT_SIGNING_KEY is not set: signing with a new key; tokens stop verifying when the process restarts
2026/09/29 13:49:09 app listening on http://localhost:8081
2026/09/29 13:49:09 report service listening on http://localhost:8082 with 1 key(s) from /auth/jwt/jwks
```

The report service fetched the key set from the app over HTTP at start, exactly as a service in another process would.

## Walkthrough: API keys

Sign up in the browser, then mint two keys. A key is shown once, in the `secret` field; the list afterwards shows only its hint. Creating a key needs a fresh sign-in.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"name":"importer","scopes":["orders:read","orders:write"]}'
curl -s -b cookies.txt -X POST localhost:8081/auth/apikey/create -H 'Origin: http://localhost:8081' \
  -d '{"name":"dashboard","scopes":["orders:read"]}'
```

```json
{"user":{"id":"usr_ke6u3yguqjooukau3jg6iu6k","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"key":{"id":"key_gxpvagbksdswlb3eegjgthqs","name":"importer","hint":"ubk_bLoU","scopes":["orders:read","orders:write"],"createdAt":"2026-09-29T08:19:09.841503Z","lastUsedAt":null,"expiresAt":null},"secret":"ubk_bLoUtSCKNyt09sjplq__WhZ0XVgBpghdjzQLm1ovePQ"}
{"key":{"id":"key_jicodxgoldrdmx6x3g7iopst","name":"dashboard","hint":"ubk_TuXu","scopes":["orders:read"],"createdAt":"2026-09-29T08:19:09.866692Z","lastUsedAt":null,"expiresAt":null},"secret":"ubk_TuXuq-6poXJrj_xMF45Wi919rJkpVTD-Ofs7JvxRbFE"}
```

A script with the read-write key places an order; the read-only key can list orders but not place one:

```sh
curl -s -X POST localhost:8081/api/orders -H 'Authorization: Bearer ubk_bLoUtSCKNyt09sjplq__WhZ0XVgBpghdjzQLm1ovePQ' -d '{"item":"coffee beans"}'
curl -s localhost:8081/api/orders -H 'Authorization: Bearer ubk_TuXuq-6poXJrj_xMF45Wi919rJkpVTD-Ofs7JvxRbFE'
curl -s -X POST localhost:8081/api/orders -H 'Authorization: Bearer ubk_TuXuq-6poXJrj_xMF45Wi919rJkpVTD-Ofs7JvxRbFE' -d '{"item":"more"}'
```

```json
{"id":1,"item":"coffee beans"}
{"userId":"usr_ke6u3yguqjooukau3jg6iu6k","orders":[{"id":1,"item":"coffee beans"}]}
{"error":{"code":"auth.missing_scope","message":"This key does not allow this."}}
```

The API is for keys, so the browser's own session is refused there. And a key acts only in the app's routes: it cannot manage the account, for example to mint itself more keys.

```sh
curl -s -b cookies.txt localhost:8081/api/orders
curl -s -X POST localhost:8081/auth/apikey/create -H 'Authorization: Bearer ubk_bLoUtSCKNyt09sjplq__WhZ0XVgBpghdjzQLm1ovePQ' -d '{"name":"more","scopes":["orders:read"]}'
```

```json
{"error":{"code":"auth.missing_scope","message":"This key does not allow this."}}
{"error":{"code":"auth.api_key_refused","message":"This cannot be done with an API key."}}
```

The owner sees when each key was last used, and revoking one ends it at once:

```sh
curl -s -b cookies.txt localhost:8081/auth/apikey/list
curl -s -b cookies.txt -X POST localhost:8081/auth/apikey/revoke -H 'Origin: http://localhost:8081' -d '{"id":"key_gxpvagbksdswlb3eegjgthqs"}'
curl -s localhost:8081/api/orders -H 'Authorization: Bearer ubk_bLoUtSCKNyt09sjplq__WhZ0XVgBpghdjzQLm1ovePQ'
```

```json
{"keys":[{"id":"key_gxpvagbksdswlb3eegjgthqs","name":"importer","hint":"ubk_bLoU","scopes":["orders:read","orders:write"],"createdAt":"2026-09-29T08:19:09.841503Z","lastUsedAt":"2026-09-29T08:19:09.905701Z","expiresAt":null},{"id":"key_jicodxgoldrdmx6x3g7iopst","name":"dashboard","hint":"ubk_TuXu","scopes":["orders:read"],"createdAt":"2026-09-29T08:19:09.866692Z","lastUsedAt":"2026-09-29T08:19:09.919355Z","expiresAt":null}]}
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## Walkthrough: a JWT for another service

The signed-in browser asks for a token. It lives five minutes by default and never longer than the session it came from:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/jwt/token -H 'Origin: http://localhost:8081'
curl -s localhost:8081/auth/jwt/jwks
```

```json
{"token":"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IkY1TWJsV3lnNGRfWmJpN3gifQ.eyJhdWQiOiJyZXBvcnRzIiwiZXhwIjoxNzkwNjcwMjUwLCJpYXQiOjE3OTA2Njk5NTAsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSIsImp0aSI6IjZWSENVSVNQNkxURE5JVFVWSU9USEU3UzJKIiwibmFtZSI6IkFsaWNlIiwibmJmIjoxNzkwNjY5OTUwLCJzaWQiOiJzZXNfc2J4YW5yNWIycnl0eHpqYXA2cWQyeHB2Iiwic3ViIjoidXNyX2tlNnUzeWd1cWpvb3VrYXUzamc2aXU2ayJ9.wLp2kjkqGyU2GeZcJQMiAtsc9XVzmC_WwRDTFYdd-T6Ft0IEkokVFi_pqBk7dHDm4sjK5KmPTLpq5NJSugT4Bg","expiresAt":"2026-09-29T08:24:10.006099Z"}
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"6CzPaBwZd8EEZqCpD08B4uHFlxc2Jywc7IT1jB_NLx8","kid":"F5MblWyg4d_Zbi7x","use":"sig","alg":"EdDSA"}]}
```

Its payload, decoded (`cut -d. -f2 | tr '_-' '/+' | base64 -D | jq -c .`): the app is the issuer, the report service the audience, and `name` is the app's own claim.

```json
{"aud":"reports","exp":1790670250,"iat":1790669950,"iss":"http://localhost:8081","jti":"6VHCUISP6LTDNITUVIOTHE7S2J","name":"Alice","nbf":1790669950,"sid":"ses_sbxanr5b2rytxzjap6qd2xpv","sub":"usr_ke6u3yguqjooukau3jg6iu6k"}
```

The report service accepts it, and refuses the same token with its signature changed:

```sh
curl -s localhost:8082/report -H "Authorization: Bearer $JWT"
curl -s localhost:8082/report -H "Authorization: Bearer ${JWT%??}AA"
```

```json
{"subject":"usr_ke6u3yguqjooukau3jg6iu6k","name":"Alice","expiresAt":"2026-09-29T08:24:10Z"}
{"error":"invalid token"}
```

```text
2026/09/29 13:49:10 report: refused: jwt: token is not valid: signature
```

## The code

The key plugin declares every scope a key may carry, so a typo cannot mint a scope no route checks; the jwt plugin names the audience and adds one claim:

```go
apikey.New(apikey.Scopes(scopeOrdersRead, scopeOrdersWrite)),
jwt.New(jwt.WithSigningKey(key), jwt.Audience(jwtAudience), jwt.Claims(nameClaim)),
```

Each API route needs a valid credential, then its own scope:

```go
forKeys := func(scope string, h http.HandlerFunc) http.Handler {
	return authhttp.Middleware(a)(authhttp.RequireScope(scope)(h))
}
mux.Handle("GET /api/orders", forKeys(scopeOrdersRead, o.list))
mux.Handle("POST /api/orders", forKeys(scopeOrdersWrite, o.add))
```

`RequireScope` answers a caller with no valid credential (a revoked or expired key included) 401 `auth.signed_out`, and a browser session or a key without the scope 403 `auth.missing_scope`. A route both people and keys use swaps `RequireScope` for `RequireUser` and asks `auth.HasScope(ctx, scope)` per request.

The other service needs only the key set, the issuer and itself as audience. `Verify` accepts only EdDSA, so a token with `alg: none` or an HMAC algorithm is refused:

```go
v := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: jwtAudience}
c, err := v.Verify(tok) // c.Subject is the user id, c.Extra["name"] the app claim
```

A JWT cannot be withdrawn once issued; its short life is its revocation. Sessions and API keys are checked on every request instead, so revoking them takes effect at once.

Limits of this example: orders are kept in memory, and the report service fetches the key set once at start; a real one refetches when it meets an unknown key id after a rotation (`jwt.PreviousKeys` keeps publishing the old key meanwhile).

## What this used

- [`plugin/apikey`](https://pkg.go.dev/github.com/ubgo/auth/plugin/apikey): `New`, `Scopes`, the `create`, `list` and `revoke` routes
- [`plugin/jwt`](https://pkg.go.dev/github.com/ubgo/auth/plugin/jwt): `New`, `WithSigningKey`, `Audience`, `Claims`, `Verifier`, `KeysFromJWKS`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Middleware`, `RequireScope`, `MustUser`, `WriteError`
- Related: [quickstart](../quickstart) for the sign-in part, [organizations](../organizations) for per-organization roles.

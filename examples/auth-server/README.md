# Standalone auth server: pages, routes and JWTs, nothing else

One process that owns the users and sessions and serves only authentication: the ready-made pages (sign-in, sign-up, password reset, verification, settings), the JSON routes with their OpenAPI document and a health route, and the JWT plugin. Every other service of the product verifies the JWTs it mints against its published keys and never touches the auth database. A second program, an API service, shows the verifying side.

## Run it

```sh
cd examples
go run ./auth-server
```

It creates `auth-server.db` (SQLite), serves the auth server on `http://localhost:8081` and the API service on `http://localhost:8082`. Set `JWT_SIGNING_KEY` to a 32-byte Ed25519 seed (base64url, no padding) to keep the signing key across restarts; unset, a new one is generated and the log says so. Mail is printed to the log instead of sent. Run the tests with `go test ./auth-server`.

```text
2026/10/02 21:21:05 JWT_SIGNING_KEY is not set: signing with a new key; tokens stop verifying when the process restarts
2026/10/02 21:21:06 auth server listening on http://localhost:8081
2026/10/02 21:21:06 api service listening on http://localhost:8082 with 1 key(s) from /auth/jwt/jwks
```

The API service fetched the key set from the auth server over HTTP at start, exactly as a service in another process would.

## Walkthrough

Open `http://localhost:8081/` in a browser: it sends you to the sign-in page, and the sign-up page is a link away. The same with curl, posting the sign-up form the way the page does, with the auth server's `Origin`; the answer is a redirect to the home page and a session cookie:

```sh
O='Origin: http://localhost:8081'
curl -s -i -c cookies.txt -X POST localhost:8081/signup -H "$O" \
  --data-urlencode 'name=Alice' --data-urlencode 'identifier=alice@example.com' \
  --data-urlencode 'password=correct horse battery staple' | grep -i '^HTTP\|^Location'
curl -s -b cookies.txt localhost:8081/ | head -4
```

```text
HTTP/1.1 303 See Other
Location: /
<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acme ID</title>
<h1>Hello, Alice</h1>
```

A client of the product turns the session into a JWT for the other services. The token is five minutes long by default, carries the auth server as `iss`, the product as `aud` (`acme-api`), the user id as `sub` and the user's name as an app claim:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/jwt/token -H "$O" -d '{}'
```

```json
{"token":"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IkVZZUs1eS1CN3JoMTFPWHQifQ.eyJhdWQiOiJhY21lLWFwaSIsImV4cCI6MTc5MDk1NjU2NiwiaWF0IjoxNzkwOTU2MjY2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODEiLCJqdGkiOiJGRUlER1JSTzdLQ0Q2R0s0S0NGMkdVQUdRWiIsIm5hbWUiOiJBbGljZSIsIm5iZiI6MTc5MDk1NjI2Niwic2lkIjoic2VzX3RjbzZobGxlYmF0dnY1ZTI1NWRnZ2d2NiIsInN1YiI6InVzcl96azZldDdtZXRwbWN1bmJ5ZTJ2a2E0eHAifQ.WdZCIFKIwPF61WDk6CNI1G0i03ZxgUTeYZIGv4g2rQJ7ym1IaDbT9rznEEmWtJvYfFHs2ECgSu_eaTUMXmMbCg","expiresAt":"2026-10-02T15:56:06.310616Z"}
```

The API service accepts it on the strength of the published keys alone, and refuses a request without one:

```sh
TOKEN=eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IkVZZUs1eS1CN3JoMTFPWHQifQ...   # the token above
curl -s localhost:8082/api/profile -H "Authorization: Bearer $TOKEN"
curl -s -i localhost:8082/api/profile | grep -i '^HTTP\|error'
```

```text
{"subject":"usr_zk6et7metpmcunbye2vka4xp","name":"Alice","expiresAt":"2026-10-02T15:56:06Z"}
HTTP/1.1 401 Unauthorized
{"error":"invalid token"}
```

The keys the API service trusts, the OpenAPI document a client generator reads, and the health route a deploy checks are all public on the auth server:

```sh
curl -s localhost:8081/auth/jwt/jwks
curl -s localhost:8081/auth/openapi.json | head -12
curl -s localhost:8081/auth/ok
```

```text
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"JQdo4c3jYmTIr7prewKW8UR1OejTo6t3yM_NR7cegVo","kid":"EYeK5y-B7rh11OXt","use":"sig","alg":"EdDSA"}]}
{
  "components": {
    "schemas": {
      "Error": {
        "description": "Every failure, whatever the status: a stable code to match on and a message for people.",
        "properties": {
          "error": {
            "properties": {
              "code": {
                "type": "string"
              },
              "message": {
{"ok":true}
```

## The code

The whole auth server is one handler: the pages at the root, the JSON routes under `/auth` with OpenAPI and health switched on because this server has clients that are not its own code, and one home page:

```go
mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.Health(),
	authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: appName, Version: "1", Servers: []string{baseURL}})))
mux.Handle("/", authui.Handler(a, authui.AppName(appName), authui.AfterSignIn(homePath)))
```

The plugin list is email, password and jwt. The API service is `jwt.Verifier` behind one route, with the auth server as issuer and the product as audience; it has no session store, no auth tables and makes no call to the auth server per request. `main_test.go` drives the whole flow and proves a tampered token and a token for another audience are refused.

What changes against the embedded shape: cookies belong to the auth server's host, so a product page on another origin calls the routes cross-origin ([SPA frontends](../spa-cross-origin)) or uses the pages; and a revoked session's tokens live until `exp` (see [other services](../../docs/integrations/other-services.md)).

## What this used

- [`authui`](https://pkg.go.dev/github.com/ubgo/auth/authui): `Handler`, `AppName`, `AfterSignIn`, `PathLogin`, `PathSettings`, `PathLogout`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Prefix`, `Health`, `OpenAPI`, `OpenAPIInfo`, `Middleware`, `CurrentUser`
- [`plugin/jwt`](https://pkg.go.dev/github.com/ubgo/auth/plugin/jwt): `New`, `WithSigningKey`, `Audience`, `Claims`, `Verifier`, `KeysFromJWKS`, `JWKS`
- Related: [api-keys-and-jwt](../api-keys-and-jwt) (the embedded shape with API keys), [ready-made-pages](../ready-made-pages).

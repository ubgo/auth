# OAuth provider: let other apps and MCP clients sign in with your app

Your app as an OAuth 2.1 authorization server and OpenID Connect provider, with an MCP server it issues tokens for. A third-party client registers itself, sends a user here to sign in and consent, exchanges the code with its PKCE verifier, and gets an access token, a refresh token and an ID token. The MCP server accepts the access token; a resource server in another process introspects it. An invoices API in a second process verifies its own tokens with only the provider's public keys, a web app signs its user out through the provider, and a client that hosts a metadata document uses its URL as its `client_id` with no registration.

The guide that walks through it: [docs/plugins/oauthprovider.md](../../docs/plugins/oauthprovider.md).

## Run it

```sh
cd examples
export AUTH_SECRET=$(openssl rand -base64 32)
go run ./oauth-provider
```

It creates `oauth-provider.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. ID tokens are signed with a key from `JWT_SIGNING_KEY` (32 bytes, base64url without padding), or with a new key each start. `AUTH_SECRET` (at least 32 bytes) signs the sign-out confirmation cookie. Mail is printed to the log instead of sent. Run the tests with `go test ./oauth-provider`: they play a whole client against an HTTPS test server.

## Walkthrough

Discovery names every endpoint under the issuer:

```sh
curl -s localhost:8081/.well-known/openid-configuration | jq "{issuer, authorization_endpoint, token_endpoint, registration_endpoint, jwks_uri}"
```

```json
{
  "issuer": "http://localhost:8081",
  "authorization_endpoint": "http://localhost:8081/oauth2/authorize",
  "token_endpoint": "http://localhost:8081/oauth2/token",
  "registration_endpoint": "http://localhost:8081/oauth2/register",
  "jwks_uri": "http://localhost:8081/oauth2/jwks"
}
```

An MCP client calling the MCP server without a token is told where to find the provider:

```sh
curl -si -X POST localhost:8081/mcp
```

```text
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Www-Authenticate: Bearer scope="mcp:tools", resource_metadata="http://localhost:8081/.well-known/oauth-protected-resource/mcp"

{"jsonrpc":"2.0","error":{"code":-32000,"message":"Authentication required."},"id":null}
```

```sh
curl -s localhost:8081/.well-known/oauth-protected-resource/mcp
```

```json
{"resource":"http://localhost:8081/mcp","authorization_servers":["http://localhost:8081"],"bearer_methods_supported":["header"],"scopes_supported":["mcp:tools"],"dpop_signing_alg_values_supported":["EdDSA","ES256","ES512","PS256","RS256"]}
```

It registers itself, with no session, as a public native client (no secret, PKCE required):

```sh
curl -s localhost:8081/oauth2/register -H 'Content-Type: application/json' -d '{
  "client_name":"Desktop MCP client","redirect_uris":["http://127.0.0.1:33418/callback"],
  "token_endpoint_auth_method":"none","application_type":"native",
  "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
  "scope":"openid profile email offline_access mcp:tools"}' | jq '{client_id, public, require_pkce}'
```

```json
{
  "client_id": "oac_ogewizq6nrlo4etugdo4fjxr",
  "public": true,
  "require_pkce": true
}
```

It sends the browser to authorize with a PKCE challenge and `resource=http://localhost:8081/mcp`. Signed out, the browser lands on the login page:

```text
Location: /login?client_id=oac_ogewizq6nrlo4etugdo4fjxr&code_challenge=mmLOCfFmXuGNd8RTPBeQban0aHJdFAFAWxUCqWFwIus&code_…
```

Alice signs up there, the login page resumes authorize, and authorize sends her to the consent page:

```sh
O='Origin: http://localhost:8081'
curl -s -c jar -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -si -b jar "localhost:8081/oauth2/authorize?…" | grep Location
```

```text
Location: /consent?client_id=oac_ogewizq6nrlo4etugdo4fjxr&code_challenge=mmLOCfFmXuGNd8RTPBeQban0aHJdFAFAWxUCqWFwIus&cod…
```

The consent page posts her answer with the signed query it was given (`$Q`), and the answer is the client's callback with the code:

```sh
curl -s -b jar -X POST localhost:8081/auth/oauthprovider/consent -H "$O" -d "{\"oauth_query\":\"$Q\",\"accept\":true}"
```

```json
{
  "redirect_to": "http://127.0.0.1:33418/callback?code=uboc_r0WAG8hjcd31fXlFqjG6sKzT7V-qzSb0aqw5VuDbyGo&iss=http%3A%2F%2Flocalhost%3A8081&state=st-1"
}
```

The client exchanges the code with its verifier:

```sh
curl -s localhost:8081/oauth2/token -d grant_type=authorization_code -d code=$CODE \
  -d redirect_uri=http://127.0.0.1:33418/callback -d code_verifier=$VERIFIER -d client_id=$CLIENT_ID -d resource=http://localhost:8081/mcp
```

```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email offline_access mcp:tools",
  "access_token": "eyJhbGciOiJFZERTQSIsInR5…",
  "refresh_token": "ubor_5PLkdIg…",
  "id_token": "eyJhbGciOiJFZERTQSIsInR5…"
}
```

Userinfo and the MCP server accept the access token:

```sh
curl -s localhost:8081/oauth2/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"
curl -s -X POST localhost:8081/mcp -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{"email":"alice@example.com","email_verified":false,"name":"Alice","sub":"usr_zcvw7pa32jgsjjfwaezsaytj"}
{"user_id":"usr_zcvw7pa32jgsjjfwaezsaytj","client_id":"oac_ogewizq6nrlo4etugdo4fjxr","scopes":["openid","profile","email","offline_access","mcp:tools"]}
```

A resource server in another process gets a client that may introspect any token, then checks the token; after the client revokes its refresh token, the whole family is inactive:

```sh
go run ./oauth-provider resource-server
curl -s -u "$RS_ID:$RS_SECRET" localhost:8081/oauth2/introspect -d token=$ACCESS_TOKEN | jq '{active, client_id, sub, aud}'
curl -s localhost:8081/oauth2/revoke -d token=$REFRESH_TOKEN -d token_type_hint=refresh_token -d client_id=$CLIENT_ID -w "%{http_code}\n"
curl -s -u "$RS_ID:$RS_SECRET" localhost:8081/oauth2/introspect -d token=$ACCESS_TOKEN
```

```text
client_id=oac_jutoc55mx6i5fghct2yc4w4p
client_secret=ubos_MmWfxip…
{
  "active": true,
  "client_id": "oac_ogewizq6nrlo4etugdo4fjxr",
  "sub": "usr_zcvw7pa32jgsjjfwaezsaytj",
  "aud": "http://localhost:8081/mcp"
}
200
{"active":false}
```

### A token for an API in another process

The invoices API is another program: no database, no provider, only the provider's key set. Start it beside the provider; without a token it answers with the challenge:

```sh
go run ./oauth-provider invoices-api   # listens on localhost:8082
curl -si localhost:8082/api/invoices
```

```text
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer scope="invoices:read"
Content-Length: 0
```

A client runs the same code flow as above with `scope=openid invoices:read` and `resource=http://localhost:8082/api/invoices`, at authorize and at the exchange. The access token is a JWT for that API:

```json
{
  "aud": [
    "http://localhost:8082/api/invoices",
    "http://localhost:8081/oauth2/userinfo"
  ],
  "scope": "openid invoices:read",
  "client_id": "oac_hv66vrecakejx233udsc6qg3",
  "sub": "usr_jixnmwcbahpwkltz4hh3suxi"
}
```

The API checks it against `http://localhost:8081/oauth2/jwks` and answers:

```sh
curl -s localhost:8082/api/invoices -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{"user_id":"usr_jixnmwcbahpwkltz4hh3suxi","invoices":[{"id":"inv_1","amount":40},{"id":"inv_2","amount":900}]}
```

### Sign out from the client

Register the web app, which may end sessions and has one post-logout URI (it is public, so the secret is empty):

```sh
go run ./oauth-provider web-app
```

```text
client_id=oac_vbtqa2iasikwogrhh5iaw4oz
client_secret=
```

After Alice signs in to it through the code flow, the web app holds her ID token. On "Sign out" it sends the browser to the end-session endpoint with that token as the hint; her session ends and the browser goes back to the web app with its state:

```sh
curl -si -b jar -c jar "localhost:8081/oauth2/end-session?id_token_hint=$ID_TOKEN&post_logout_redirect_uri=https%3A%2F%2Finvoices.example.com%2Fsigned-out&state=st-1" -H 'Accept: text/html'
curl -s -b jar localhost:8081/auth/session
```

```text
HTTP/1.1 302 Found
Location: https://invoices.example.com/signed-out?state=st-1
Set-Cookie: __Host-auth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-auth_session_cache=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-auth_oauth_logout_confirmation=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Without the hint nothing ends: the browser is asked to confirm, and the confirmation state goes into a signed cookie:

```sh
curl -si -b jar "localhost:8081/oauth2/end-session?client_id=$WEB_ID&post_logout_redirect_uri=https%3A%2F%2Finvoices.example.com%2Fsigned-out" -H 'Accept: text/html'
```

```text
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Security-Policy: default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
Content-Type: text/html; charset=utf-8
Set-Cookie: __Host-auth_oauth_logout_confirmation=eyJzZXNzaW9uSWQiOi…; Path=/; Expires=Fri, 09 Oct 2026 10:28:59 GMT; HttpOnly; Secure; SameSite=Lax

<!doctype html><html><head><meta charset="utf-8"><title>Confirm logout</title></head><body><main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method="post" data-oidc-logout-confirmation action="http://localhost:8081/oauth2/end-session/confirm"><button type="submit" name="action" value="confirm">Confirm logout</button></form></main></body></html>
```

### A client that describes itself

A client may skip registration and use the https URL of a metadata document it hosts as its `client_id`. The provider fetches the document only from public addresses, so this part is shown by the test, which serves the document from a local HTTPS server and passes `CIMDFetch` to reach it.

## What the test checks

`TestOAuthProvider_ThirdPartyClientEndToEnd` does all of the above over HTTPS, and also verifies the ID token against `/oauth2/jwks` (issuer, audience, nonce), refreshes (a new pair; the old refresh token is spent), and replays the code (refused). `TestOAuthProvider_DenyReachesTheClient` denies consent and the callback gets `error=access_denied` with the client's `state`. `TestSigningKey_FromTheEnvironment` reads the key from the environment and refuses a malformed one. `TestOAuthProvider_TokenForAnotherAPI` gets a token for the invoices API and calls it on a separate server; a token for the MCP server is refused with `invalid_token`, one without `invoices:read` with `insufficient_scope`. `TestOAuthProvider_WebAppSignsTheUserOut` shows the confirmation page without a hint (the session stays) and signs Alice out with one. `TestOAuthProvider_ClientMetadataDocument` authorizes a client whose id is its document's URL, and refuses a document that sets `skip_consent`.

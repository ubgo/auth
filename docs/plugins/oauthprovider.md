# OAuth provider: let other apps sign in with your app

You will have an OAuth 2.1 authorization server and OpenID Connect provider inside your app. Another application (a partner's web app, your own mobile app, a CLI, an MCP client) registers itself, sends its users to you to sign in and consent, and gets back an authorization code, then an access token, a refresh token and an ID token. Your API, or an MCP server, accepts those access tokens. It is better-auth's `oauth-provider` plugin.

Use this plugin when third parties, or your own separate apps, need user-delegated access to your API, a "Sign in with <your app>" button, or an MCP server that MCP clients can connect to. Don't use it to sign users into your own app (use a sign-in method), to sign them in with Google or GitHub (that is [OAuth sign-in](oauth.md), the client side), for a script acting as its owner ([API keys](apikey.md)), or for an AI agent with per-capability grants ([agent auth](agentauth.md)).

## Before you start

- An app with a sign-in method, as in [your first app](../start/first-app.md): users sign in to approve a client.
- The [JWT plugin](jwt.md), or any other `oauthprovider.Signer`. It signs ID tokens and JWT access tokens, and its public keys are published at the provider's key-set URL.
- A deployment secret (`auth.WithSecret`, at least 32 random bytes): the sign-out confirmation in [Step 9](#step-9--sign-the-user-out-from-the-client) travels in a signed cookie. The example reads it from `AUTH_SECRET`.
- The module: `go get github.com/ubgo/auth/plugin/oauthprovider`. It depends on the core module and sqlb only. Its [README](../../plugin/oauthprovider/README.md) is the reference for every option, endpoint and error.
- The example program this guide is built from, with a `main_test.go` that plays a third-party MCP client through every step and a `README.md` with the same transcript: [`examples/oauth-provider`](../../examples/oauth-provider/).

## Step 1 — Wire the provider

The provider needs an issuer: the URL that names your app in every ID token and starts every endpoint URL in discovery. It must be https, or http on a loopback host while you develop. It also needs a login page, and usually a consent page. The example declares two protected resources, its MCP server and an invoices API that runs in another process ([Step 8](#step-8--tokens-for-an-api-verified-elsewhere)), links every client that registers itself to both, opens registration to callers without a session, which is how MCP clients register, and accepts clients that describe themselves with a metadata document ([Step 10](#step-10--let-clients-describe-themselves-cimd)). `CacheResources(0)` keeps the resource policies in memory for [a minute](ds:block?id=oauthprovider-resourcecache-ttl-5vq8mz2k), so issuing a token does not read them from the database each time:

<!-- ds:block id=newprovider-oauthprovider-example -->
**newProvider** · [`examples/oauth-provider/main.go:213-226`](../../examples/oauth-provider/main.go#L213-L226)

```go
func newProvider(jw *jwt.Plugin, cimd ...oauthprovider.CIMDOption) *oauthprovider.Plugin {
	return oauthprovider.New(jw,
		oauthprovider.Issuer(baseURL),
		oauthprovider.LoginPage(loginPath),
		oauthprovider.ConsentPage(consentPath),
		oauthprovider.Scopes(append(slices.Clone(oauthprovider.DefaultScopes), scopeMCPTools, scopeInvoicesRead)...),
		oauthprovider.ProtectedResource(mcpURL, scopeMCPTools),
		oauthprovider.ProtectedResource(invoicesURL, scopeInvoicesRead),
		oauthprovider.RegistrationDefaultResources(mcpURL, invoicesURL),
		oauthprovider.MCP(),
		oauthprovider.CacheResources(0),
		oauthprovider.ClientIDMetadataDocuments(append(slices.Clone(cimd), oauthprovider.CIMDProfileMCP())...),
	)
}
```
<!-- /ds:block hash=ddc616 -->

The scopes are the OpenID ones ([`DefaultScopes`](ds:block?id=oauthprovider-defaultscopes-k3n8vq2m)) plus your own. The jwt plugin is the signer here. Give it the same issuer, and list it before the provider:

<!-- ds:block id=newauth-oauthprovider-example -->
**newAuth** · [`examples/oauth-provider/main.go:235-245`](../../examples/oauth-provider/main.go#L235-L245)

```go
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey, secret []byte, cimd ...oauthprovider.CIMDOption) (*auth.Auth, *oauthprovider.Plugin, error) {
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(baseURL))
	op := newProvider(jw, cimd...)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), jw, op),
	)
	return a, op, err
}
```
<!-- /ds:block hash=ad824b -->

A signer is anything with `Sign(ctx, jwt.SignRequest)` and `PublicKeys() jwt.JWKS`: the jwt plugin, or your own type around a KMS or an HSM. One that is not a plugin needs no registration, and the jwt plugin's own token route is then not mounted at all.

Mount the provider's handler for discovery and the protocol endpoints, beside the library's routes and your two pages:

<!-- ds:block id=newhandler-oauthprovider-example -->
**newHandler** · [`examples/oauth-provider/main.go:251-262`](../../examples/oauth-provider/main.go#L251-L262)

```go
func newHandler(a *auth.Auth, op *oauthprovider.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/.well-known/", op.Handler())
	mux.Handle(oauthprovider.DefaultBasePath+"/", op.Handler())
	mux.Handle("GET "+loginPath, loginPage(op))
	mux.HandleFunc("GET "+consentPath, consentPage)
	mux.Handle(mcpPath, op.RequireToken(oauthprovider.RequireOptions{
		Resource: mcpURL, Scopes: []string{scopeMCPTools}, JSONRPC: true,
	})(http.HandlerFunc(mcpServer)))
	return mux
}
```
<!-- /ds:block hash=12c088 -->

`op.Handler()` serves discovery, authorize, token, userinfo, introspection, revocation, registration, end-session and the key set under [`/oauth2`](ds:block?id=oauthprovider-defaultbasepath-p2v6mz9c) (`BasePath` moves it), in the form the RFCs require: form bodies, HTTP Basic client authentication, and `{"error": "invalid_grant"}` answers. Underneath, each endpoint is an operation marked [`SelfServed`](ds:block?id=core-opinfo-selfserved-m4q8xk2w). It runs the same pipeline as every other operation, but no other transport mounts it. If `authhttp.Handler` uses options such as a cookie prefix, pass the same ones to `op.Handler`, so the authorize endpoint reads the same session. The provider's user-facing operations (consent, the client registry, the consent list) are ordinary operations under `/auth/oauthprovider/`.

Check: discovery names every endpoint under the issuer.

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

## Step 2 — Register clients

There are three ways in, from most to least trusted.

From Go, at deploy time or in an admin screen, with `op.CreateClient`. The example registers a resource server this way: a confidential client of another process that checks tokens by introspection. `IntrospectAny` lets it see tokens issued to every client; any other client sees only its own. The secret is in this answer only:

<!-- ds:block id=registerresourceserver-oauthprovider-example -->
**registerResourceServer** · [`examples/oauth-provider/main.go:270-278`](../../examples/oauth-provider/main.go#L270-L278)

```go
func registerResourceServer(ctx context.Context, op *oauthprovider.Plugin) (oauthprovider.Registration, error) {
	return op.CreateClient(ctx, oauthprovider.ClientSpec{
		ClientMetadata: oauthprovider.ClientMetadata{
			Name:       resourceServerName,
			GrantTypes: []string{oauthprovider.GrantClientCredentials},
		},
		IntrospectAny: true,
	})
}
```
<!-- /ds:block hash=de881a -->

```sh
go run ./oauth-provider resource-server
```

```text
client_id=oac_jutoc55mx6i5fghct2yc4w4p
client_secret=ubos_MmWfxip…
```

A first-party client of yours gets `SkipConsent: true`, so your users are never asked. A browser or mobile app cannot keep a secret: register it with `AuthMethod: oauthprovider.AuthMethodNone`, and it gets no secret and must use PKCE.

By a signed-in user, for clients they own, through `POST /auth/oauthprovider/create-client`, which needs a fresh sign-in. The owner lists, updates, rotates and deletes their own clients only (`/auth/oauthprovider/clients`, `update-client`, `rotate-secret`, `delete-client`).

By the client itself, with dynamic client registration (RFC 7591) at `/oauth2/register`. It is closed until you pass `AllowDynamicRegistration`; a caller without a session needs `AllowUnauthenticatedRegistration` too, and `MCP()` turns on both. The example's MCP client registers as a public native client:

```sh
curl -s localhost:8081/oauth2/register -H 'Content-Type: application/json' -d '{
  "client_name":"Desktop MCP client","redirect_uris":["http://127.0.0.1:33418/callback"],
  "token_endpoint_auth_method":"none","application_type":"native",
  "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
  "scope":"openid profile email offline_access mcp:tools"}'
```

```json
{
  "client_name": "Desktop MCP client",
  "redirect_uris": [
    "http://127.0.0.1:33418/callback"
  ],
  "grant_types": [
    "authorization_code",
    "refresh_token"
  ],
  "response_types": [
    "code"
  ],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile email offline_access mcp:tools",
  "application_type": "native",
  "client_id": "oac_ogewizq6nrlo4etugdo4fjxr",
  "public": true,
  "skip_consent": false,
  "require_pkce": true,
  "introspect_any": false,
  "enable_end_session": false,
  "disabled": false,
  "created_at": "2026-10-09T03:08:56.944568Z",
  "updated_at": "2026-10-09T03:08:56.944568Z",
  "client_id_issued_at": 1791515336,
  "client_secret_expires_at": 0
}
```

Only `redirect_uris` is required. `client_name`, `grant_types`, `response_types`, `token_endpoint_auth_method` and `scope` may be left out, and the provider fills in its defaults (grants `authorization_code`, plus `refresh_token` when it serves it; response type `code`; `client_secret_basic`; an empty `scope`, which allows every scope the provider supports; an empty name). The answer always carries all five, empty or not, with the values the client got, as RFC 7591 section 3.2.1 requires. In Go the input is `oauthprovider.ClientMetadata` and the answer's `Client` embeds `oauthprovider.RegisteredMetadata`, the same fields with the defaulted ones always present; `oauthprovider.RegisteredMetadata(m)` converts one to the other.

A redirect URI is matched as an exact string, never by prefix. A web client (the default `application_type`) needs https; a `native` one may also use http on `localhost`, `127.0.0.1` or `[::1]`, or a reverse-domain private-use scheme such as `com.example.app:/cb`. A client registered without an owner, as here, can only be managed from Go.

Check: `TestOAuthProvider_ThirdPartyClientEndToEnd` registers the client with no session and gets a client id and no secret.

## Step 3 — Build the login and consent pages

A signed-out browser at `/oauth2/authorize` lands on your login page with the authorize parameters in the query. The page signs the user in with any of your sign-in methods, then sends the browser back to `op.ResumeURL(r.URL.Query())`, the authorize URL rebuilt from that query:

<!-- ds:block id=loginpage-oauthprovider-example -->
**loginPage** · [`examples/oauth-provider/main.go:369-377`](../../examples/oauth-provider/main.go#L369-L377)

```go
func loginPage(op *oauthprovider.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := loginPageData{Resume: op.ResumeURL(r.URL.Query()), Prefix: authPrefix}
		if err := loginPageTemplate.Execute(w, data); err != nil {
			log.Printf("login page: %v", err)
		}
	})
}
```
<!-- /ds:block hash=7e11cd -->

<!-- ds:block id=loginpagetemplate-oauthprovider-example -->
**loginPageTemplate** · [`examples/oauth-provider/main.go:340-355`](../../examples/oauth-provider/main.go#L340-L355)

```go
var loginPageTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<form id="f"><input name="identifier" type="email"> <input name="password" type="password"> <button>Sign in</button></form>
<pre id="out"></pre>
<script>
const resume = {{.Resume}};
document.getElementById("f").onsubmit = async (e) => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.target));
  const res = await fetch("{{.Prefix}}/password/sign-in", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  if (res.ok) { location.href = resume; return; }
  document.getElementById("out").textContent = (await res.json()).error.message;
};
</script>
`))
```
<!-- /ds:block hash=63c6fa -->

A user who has not yet consented to this client and these scopes lands on your consent page with a signed copy of the same parameters. The page shows the client from `GET /auth/oauthprovider/public-client?client_id=…` and posts the user's answer with the query unchanged:

<!-- ds:block id=consentpagehtml-oauthprovider-example -->
**consentPageHTML** · [`examples/oauth-provider/main.go:385-405`](../../examples/oauth-provider/main.go#L385-L405)

```go
const consentPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Allow access</title>
<p><b id="client"></b> asks for: <span id="scope"></span></p>
<button id="allow">Allow</button> <button id="deny">Deny</button>
<script>
const q = new URLSearchParams(location.search);
document.getElementById("scope").textContent = q.get("scope");
fetch("` + authPrefix + `/oauthprovider/public-client?client_id=" + encodeURIComponent(q.get("client_id")))
  .then(r => r.json()).then(c => document.getElementById("client").textContent = c.client_name);
const answer = async (accept) => {
  const res = await fetch("` + authPrefix + `/oauthprovider/consent", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({oauth_query: location.search.slice(1), accept}),
  });
  location.href = (await res.json()).redirect_to;
};
document.getElementById("allow").onclick = () => answer(true);
document.getElementById("deny").onclick = () => answer(false);
</script>
`
```
<!-- /ds:block hash=93cb4a -->

The query is signed and validated again in full, so the page cannot widen anything: a changed query is refused with `oauthprovider.invalid_signature`. `scope` in the body grants fewer scopes than were asked for, and a scope outside the request is `invalid_scope`. A denial sends the client `error=access_denied` with its `state`. The user's consents are listed at `/auth/oauthprovider/consents` and withdrawn with `/auth/oauthprovider/revoke-consent`, which also revokes the tokens issued under them.

Check: `TestOAuthProvider_DenyReachesTheClient` posts `accept: false` and the client's callback gets `error=access_denied&state=st-1`.

## Step 4 — Run the code flow with PKCE

The client makes a PKCE verifier and its S256 challenge, and sends the browser to authorize with `resource` naming the MCP server it wants a token for. Signed out, the browser is sent to the login page:

```sh
curl -si "localhost:8081/oauth2/authorize?response_type=code&client_id=…&redirect_uri=…&scope=…&state=st-1&nonce=n-1&code_challenge=…&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp" | grep Location
```

```text
Location: /login?client_id=oac_ogewizq6nrlo4etugdo4fjxr&code_challenge=mmLOCfFmXuGNd8RTPBeQban0aHJdFAFAWxUCqWFwIus&code_…
```

Alice signs up on that page, and the same authorize URL now asks for her consent:

```sh
O='Origin: http://localhost:8081'
curl -s -c jar -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -si -b jar "localhost:8081/oauth2/authorize?…" | grep Location
```

```text
Location: /consent?client_id=oac_ogewizq6nrlo4etugdo4fjxr&code_challenge=mmLOCfFmXuGNd8RTPBeQban0aHJdFAFAWxUCqWFwIus&cod…
```

She allows it, and the answer sends the browser to the client's callback with the code, the `state` and the issuer (`iss`, RFC 9207):

```sh
curl -s -b jar -X POST localhost:8081/auth/oauthprovider/consent -H "$O" -d "{\"oauth_query\":\"$Q\",\"accept\":true}"
```

```json
{
  "redirect_to": "http://127.0.0.1:33418/callback?code=uboc_r0WAG8hjcd31fXlFqjG6sKzT7V-qzSb0aqw5VuDbyGo&iss=http%3A%2F%2Flocalhost%3A8081&state=st-1"
}
```

The client checks `state` and `iss`, then posts the code with its verifier to the token endpoint. A public client sends only its `client_id`; a confidential one authenticates with HTTP Basic, a form secret or a `private_key_jwt` assertion, whichever it registered:

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

The access token lives [one hour](ds:block?id=oauthprovider-defaultaccessttl-h4k9zt3p) (`AccessTokenTTL`) and the code [ten minutes](ds:block?id=oauthprovider-defaultcodettl-r5m2qw8x) (`CodeTTL`). Because `resource` was sent, the access token is a JWT (type [`at+jwt`](ds:block?id=oauthprovider-accesstokentype-k9w2mq4x)) whose `aud` is the MCP server; without it, it is an opaque `uboa_…` string. A refresh token (`ubor_…`) comes only when `offline_access` was granted, and an ID token only with `openid`.

A code works once. Presenting it again is `invalid_grant`, and it also revokes every token the first exchange issued, because only a thief would hold an old code. A refresh rotates the same way: every refresh token works once, and a spent one revokes its whole family.

Check: `TestOAuthProvider_ThirdPartyClientEndToEnd` drives this flow over HTTP, refreshes, and replays the code last.

## Step 5 — Verify the ID token and read userinfo

The ID token is signed by the signer and carries `iss`, `aud` (the client), `sub`, `nonce`, `auth_time` and the claims the scopes release. A client verifies it with the keys at `/oauth2/jwks`; in Go that is `jwt.Verifier{Keys: jwt.KeysFromJWKS(keys), Issuer: issuer, Audience: clientID}`, with `jwt.NewRemoteKeys` to fetch and cache the set. Userinfo answers the same claims for the access token:

```sh
curl -s localhost:8081/oauth2/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{
  "email": "alice@example.com",
  "email_verified": false,
  "name": "Alice",
  "sub": "usr_zcvw7pa32jgsjjfwaezsaytj"
}
```

A JWT access token for a resource also names the userinfo endpoint as an audience when it carries `openid`, so the same token works at both. `Claims(fn)` adds your own claims to the ID token and userinfo.

## Step 6 — Guard an MCP server

An MCP client finds your provider from the MCP server's protected-resource metadata (RFC 9728). `ProtectedResource` declares the server's URL and scopes, the handler serves its metadata, and `op.RequireToken` guards the route: the token must be live, issued for that resource, and carry the scopes. Inside, `oauthprovider.TokenFrom` hands over what it verified:

<!-- ds:block id=mcpserver-oauthprovider-example -->
**mcpServer** · [`examples/oauth-provider/main.go:426-434`](../../examples/oauth-provider/main.go#L426-L434)

```go
func mcpServer(w http.ResponseWriter, r *http.Request) {
	at, ok := oauthprovider.TokenFrom(r.Context())
	if !ok {
		http.Error(w, "no token", http.StatusUnauthorized) // unreachable behind RequireToken
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mcpAnswer{UserID: at.UserID, ClientID: at.ClientID, Scopes: at.Scopes}) // a client that hung up cannot be told
}
```
<!-- /ds:block hash=022448 -->

A call without a token gets the challenge an MCP client follows, with a JSON-RPC error body because `JSONRPC` is set:

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

The client reads that document, finds the issuer, registers (Step 2) and runs the code flow (Step 4). With its token the call goes through:

```sh
curl -s -X POST localhost:8081/mcp -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{
  "user_id": "usr_zcvw7pa32jgsjjfwaezsaytj",
  "client_id": "oac_ogewizq6nrlo4etugdo4fjxr",
  "scopes": [
    "openid",
    "profile",
    "email",
    "offline_access",
    "mcp:tools"
  ]
}
```

A token without the scope is 403 with `error="insufficient_scope"`, and a token issued for no resource, or for another one, is 401. `RequireOptions.ChallengeScopes` names other scopes in the 401 (say, `offline_access` too) than the ones the route checks.

An MCP server in another process uses `oauthprovider.ResourceGuard` instead: `Issuer`, `Audience` (the MCP server's URL), `Keys` (`jwt.NewRemoteKeys(issuer+"/oauth2/jwks", nil).Lookup`) for JWT access tokens, and `IntrospectURL` with a resource-server client for opaque ones. An introspected token that names no audience is refused unless `AllowMissingAudience` is set. `oauthprovider.ProtectedResourceMetadata` builds the RFC 9728 document for such a server.

Check: `TestOAuthProvider_ThirdPartyClientEndToEnd` calls `/mcp` without a token, with the token, and after revocation.

## Step 7 — Introspect and revoke

Your own API, in the same process, verifies an access token without a round trip: `op.VerifyAccessToken(ctx, token)` returns the user, the client, the scopes and the resource, and `t.HasScope("invoices:read")` checks one. Access tokens are not sessions: `authhttp.Middleware` does not accept them, or a third-party client a user approved for `openid` could call every route of your app as that user.

A resource server in another process introspects (RFC 7662) with the client from Step 2:

```sh
curl -s -u "$RS_ID:$RS_SECRET" localhost:8081/oauth2/introspect -d token=$ACCESS_TOKEN
```

```json
{
  "active": true,
  "scope": "openid profile email offline_access mcp:tools",
  "client_id": "oac_ogewizq6nrlo4etugdo4fjxr",
  "sub": "usr_zcvw7pa32jgsjjfwaezsaytj",
  "token_type": "access_token",
  "exp": 1791518937,
  "iat": 1791515337,
  "iss": "http://localhost:8081",
  "aud": "http://localhost:8081/mcp"
}
```

The client revokes its refresh token (RFC 7009). That ends the whole family, the access token with it:

```sh
curl -s localhost:8081/oauth2/revoke -d token=$REFRESH_TOKEN -d token_type_hint=refresh_token -d client_id=$CLIENT_ID -w "%{http_code}\n"
curl -s -u "$RS_ID:$RS_SECRET" localhost:8081/oauth2/introspect -d token=$ACCESS_TOKEN
```

```text
200
{"active":false}
```

Revoking a JWT access token takes effect at once in this process (`VerifyAccessToken`, `RequireToken`, introspection). A resource server that verifies JWTs offline sees it only when the token expires, so keep `AccessTokenTTL` short for those.

## Step 8 — Tokens for an API verified elsewhere

When the API that receives tokens runs in another process and should not call the provider for every request, declare it with another `ProtectedResource(url, scopes...)` and link clients to it. The example's invoices API listens on its own port, and `newProvider` in Step 1 declares it next to the MCP server and links every self-registered client to both (`RegistrationDefaultResources(mcpURL, invoicesURL)`); a client created with `CreateClient` is linked per client instead. The client sends `resource=<url>` at authorize and again at the token exchange. The access token is then a JWT (`typ: at+jwt`) whose `aud` names that URL, and the userinfo endpoint too when the client asked for `openid`.

The API needs no database and no `Plugin`. `oauthprovider.ResourceGuard` checks each token against the provider's published keys, the issuer, its own URL as the audience, and the scopes it requires. `jwt.NewRemoteKeys` fetches the key set once and again when a token names a key it does not hold, so a key rotation needs no deploy:

<!-- ds:block id=invoicesapi-oauthprovider-example -->
**invoicesAPI** · [`examples/oauth-provider/main.go:321-333`](../../examples/oauth-provider/main.go#L321-L333)

```go
func invoicesAPI(keys *jwt.RemoteKeys) http.Handler {
	guard := oauthprovider.ResourceGuard{
		Issuer:   baseURL,
		Audience: invoicesURL,
		Keys:     keys.Lookup,
		Scopes:   []string{scopeInvoicesRead},
	}
	return guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := oauthprovider.GuardedTokenFrom(r.Context()) // always set behind the guard
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(invoicesAnswer{UserID: tok.Subject, Invoices: sampleInvoices}) // a client that hung up cannot be told
	}))
}
```
<!-- /ds:block hash=7b5813 -->

The test gets a token for the invoices API and calls it on a separate server, which answers with the user's invoices. A token issued for the MCP server is refused with 401 `invalid_token`, because its audience is the MCP server; a token without `invoices:read` is refused with 403 `insufficient_scope`. A `ResourceGuard` with `IntrospectURL`, `ClientID` and `ClientSecret` set also accepts opaque tokens by introspection, and `Force: true` introspects JWTs too, so a revoked token is refused at once rather than when it expires.

A client may ask for several resources at once (repeat `resource`); the token then names each in `aud`. Resources declared in configuration are written with `op.SeedResources(ctx, mode, seeds...)` after migrations (`SeedInsertOnly`, `SeedMerge`, `SeedOverwrite`), and `op.PatchResource` changes only the named fields.

## Step 9 — Sign the user out from the client

A client that signs its users in through your app usually wants to sign them out through it too, so that "Sign out" in the client also ends the session at the provider. Create it with `EnableEndSession: true` and the URIs it may send the browser back to:

<!-- ds:block id=registerwebapp-oauthprovider-example -->
**registerWebApp** · [`examples/oauth-provider/main.go:286-296`](../../examples/oauth-provider/main.go#L286-L296)

```go
func registerWebApp(ctx context.Context, op *oauthprovider.Plugin) (oauthprovider.Registration, error) {
	return op.CreateClient(ctx, oauthprovider.ClientSpec{
		ClientMetadata: oauthprovider.ClientMetadata{
			Name:                   webAppName,
			RedirectURIs:           []string{webAppRedirect},
			PostLogoutRedirectURIs: []string{webAppSignedOut},
			AuthMethod:             oauthprovider.AuthMethodNone,
		},
		EnableEndSession: true,
	})
}
```
<!-- /ds:block hash=15183b -->

On sign-out the client sends the browser to `/oauth2/end-session?id_token_hint=<its ID token>&post_logout_redirect_uri=<registered>&state=<its value>`. When the hint names the browser's session, the provider ends it, clears the session cookie and redirects to the post-logout URI with the client's `state`. A URI the client never registered is not used: the browser sees a success page that says so. Without a hint, or with one for a different user, the browser is shown a confirmation page instead, so a link on another site cannot sign anyone out silently; the user's click on that page posts to `/oauth2/end-session/confirm`. The confirmation state travels in a signed cookie, so this step needs `auth.WithSecret` (the example reads it from `AUTH_SECRET`). Without one, `auth.New` refuses a trusted client with `EnableEndSession`, `CreateClient` and `UpdateClient` refuse it with `oauthprovider.ErrNoSecret`, and discovery leaves out `end_session_endpoint`; `AllowPublicClientPrelogin` and `PostLogin` are refused at start-up the same way, since both sign. A client with a `backchannel_logout_uri` also gets a logout token when the user's session ends anywhere.

Only a browser navigation (one that accepts HTML) can be shown the confirmation page; a request without a valid hint from anything else is refused with `invalid_request`. The test runs both paths: the confirmation page leaves Alice signed in, and the hinted request signs her out and lands on `https://invoices.example.com/signed-out?state=st-1`.

## Step 10 — Let clients describe themselves (CIMD)

Many MCP clients identify themselves with a client ID metadata document instead of registering: the `client_id` is the https URL of a JSON document the client hosts, holding the same metadata as a registration plus its own URL. `oauthprovider.ClientIDMetadataDocuments(...)` accepts such ids; `newProvider` in Step 1 turns it on with `CIMDProfileMCP()`, which also requires `client_name` and `redirect_uris` as the MCP specification does. A document like this is all the client needs:

<!-- ds:block id=desktopdocument-oauthprovider-example -->
**desktopDocument** · [`examples/oauth-provider/main_test.go:372-386`](../../examples/oauth-provider/main_test.go#L372-L386)

```go
func desktopDocument(t *testing.T, clientID string) string {
	t.Helper()
	doc, err := json.Marshal(metadataDocument{ClientID: clientID, ClientMetadata: oauthprovider.ClientMetadata{
		Name:            "Desktop agent",
		RedirectURIs:    []string{clientRedirect},
		ApplicationType: applicationNative,
		AuthMethod:      oauthprovider.AuthMethodNone,
		GrantTypes:      []string{oauthprovider.GrantAuthorizationCode},
		ResponseTypes:   []string{responseCode},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(doc)
}
```
<!-- /ds:block hash=fba59d -->

The provider fetches the document the first time the id reaches authorize, stores it as a client, and fetches it again after [an hour](ds:block?id=oauthprovider-defaultcimdrevalidate-h3w8kq5n) (`CIMDRevalidate`). From then on the consent page's `public-client` call shows the document's name. A document is refused when it claims anything only the server may decide, in either spelling (`skip_consent` or `skipConsent`, `client_secret`, `resources`, …): the test's second document sets `skip_consent` and authorize answers 400. `CIMDOriginBoundFields` chooses which URLs must sit on the document's own origin (by default `client_uri` and the post-logout URIs); a `jwks_uri` always must. A document needs only one grant the provider serves, and one without redirect URIs keeps only the grants that need none. `op.ValidateCIMDDocument(url, body)` runs the same checks from Go.

Documents are fetched only from public addresses, with no redirects, within 5 seconds and 5 KB. That makes the provider fetch URLs a caller chooses, so admit only hosts you trust with `CIMDAllow(func(clientID string) bool)` when you can. The test's document is served by a local test server, which the default fetcher refuses as not public, so the test passes `CIMDFetch` with a fetcher that reaches it; replace the fetcher only in tests or behind an egress proxy that applies the same rules.

## Step 11 — Client keys at a URL, and other algorithms

A `private_key_jwt` client may register `jwks_uri` instead of an inline `jwks` (never both): an https URL on an origin the app trusts. The provider fetches the set on first use from public addresses only (`ClientJWKSFetch` replaces the fetcher in tests), keeps it 5 minutes, serves it up to 10 minutes while the client's host is down, and fetches it again when an assertion fails to verify, at most every 30 seconds, so a client that rotated its keys is not locked out. Assertions may use any of `EdDSA`, `RS256`/`384`/`512`, `PS256`/`384`/`512` and `ES256`/`384`/`512`, and need no `typ` header; an RSA key with no `alg` verifies under any RSA algorithm, an EC key only under its curve's.

DPoP proofs take better-auth's list (`EdDSA ES256 ES512 PS256 RS256`); `DPoPSigningAlgorithms(...)` replaces it. A DPoP-bound token is presented with the `DPoP` scheme and a proof; `RequireToken` and userinfo check both.

## Step 12 — Storage and minting hooks

`HashStoredSecrets(fn)` replaces SHA-256 for every stored client secret, code, access and refresh token (an HMAC with a pepper from your secret store, say; 32 bytes, deterministic). `GenerateAccessToken` and `GenerateRefreshToken` replace the random parts. `op.IssueTokens(ctx, IssueRequest{GrantType: …})` mints a token set outside the token endpoint for a grant your app runs itself, `op.HashToken` gives the stored hash of a token, and `op.ConsumeClientAssertion` checks and spends a client assertion at your own endpoint. `WithGrant` adds a whole extension grant to the token endpoint; the [device authorization grant](deviceauth.md) is one, through the `oauthdevice` module.

## Step 13 — better-auth's answers, and the opt-ins that relax a default

Error codes and the userinfo answer follow better-auth (`invalid_redirect`, `invalid_user`, `not_found`, `unsupported_prompt_select_account`, 400 `invalid_scope` without `openid`). Where better-auth is less strict, its behaviour is an opt-in that logs a warning at every start: `RevokeAccessTokenOnly()` (revoking an access token keeps its refresh token), `RefuseJWTRevocation()` (`unsupported_token_type` for a live JWT access token), `EncryptClientSecrets(enc)` (a recoverable copy of each secret, read with `op.RevealClientSecret`) and `RefreshReplay(enc)` (a reused refresh token gets the first answer again inside `RefreshReuseInterval`). `enc` is an authenticated cipher (AES-GCM) under a key from your secret store. Only turn one on when a client depends on it.

## Try it

Run the example and the transcript above is what you get, one step at a time:

```sh
cd examples
export AUTH_SECRET=$(openssl rand -base64 32)
go run ./oauth-provider
```

The test plays the whole client, from registration to revocation, against an HTTPS test server:

```sh
go test ./oauth-provider/
```

```text
ok  	github.com/ubgo/auth/examples/oauth-provider	1.035s
```

## Options you may want

| Situation | Option | What it changes |
|---|---|---|
| Your own apps should never show a consent screen | `ClientSpec{SkipConsent: true}` | Authorize issues the code at once |
| Third parties register themselves | `AllowDynamicRegistration()` | Opens `/oauth2/register` to signed-in users; the client gets an owner |
| MCP clients, which register with no session | `MCP()`, or `AllowUnauthenticatedRegistration()` | Anonymous registration, plus a refresh reuse window for clients that refresh concurrently |
| Clients that registered themselves must reach your MCP server | `RegistrationDefaultResources(url)` | Links each new client to the resource; without it, authorize answers `invalid_target` |
| Any client may ask for any resource | `EnforcePerClientResources(false)` | Drops the client-resource link check |
| Fewer database reads per token | [`CacheResources(ttl)`](ds:block?id=oauthprovider-cacheresources-8xk2wq4n) | Keeps resource policies in this process for `ttl` (0 is one minute, at most 15); this instance's own writes are seen at once, another instance's after `ttl`. Default off: every issuance reads the resource's row |
| The same, shared by every instance | [`CacheResourcesIn(kv, ttl)`](ds:block?id=oauthprovider-cacheresourcesin-4nw7qk2z) | Keeps them in any `auth.SecondaryStorage` (contrib/redis's `NewStorage`, or the one given to `auth.WithSecondaryStorage`), so a write on any instance drops the entry for all; a failing store is logged and the database is read |
| An API in another process checks tokens | `ClientSpec{IntrospectAny: true}` on its client | It may introspect tokens issued to every client |
| Short-lived tokens for offline verification | `AccessTokenTTL(d)` | Default [one hour](ds:block?id=oauthprovider-defaultaccessttl-h4k9zt3p) |
| Refresh tokens that end sooner | `RefreshTokenTTL(d)` | Default [30 days](ds:block?id=oauthprovider-defaultrefreshttl-b8x3nq6v) |
| Endpoints somewhere other than `/oauth2` | `BasePath("/oidc")` | Every protocol path and discovery value |
| Extra claims in ID tokens and userinfo | `Claims(fn)` | Adds what `fn` returns for the user and scopes |
| Different rate limits | `RateLimit(endpoint, limit, window)`, `NoDefaultRateLimits()` | Per-IP limits on token, authorize, introspect, revoke, register, userinfo, end-session |
| Signing keys in a KMS or HSM | your own `oauthprovider.Signer` passed to `New` | Signs ID tokens and JWT access tokens and publishes the keys |

## From TypeScript

The protocol side of this plugin is not called through the [typed client](../client/README.md): `/oauth2/authorize`, `/oauth2/token`, userinfo, introspection and the discovery documents are standard OAuth 2.1 and OpenID Connect endpoints that a relying party reaches with its own OAuth library, and the authorize step is a browser navigation. The client covers the pages of your app that the provider sends a browser to, and the user's own management pages: list `oauthprovider()` in `plugins`.

The consent page (Step 3). It shows the client from `publicClient`, posts the answer (the client adds the signed query the page was given as `oauth_query`, from `location.search`), and navigates to `redirect_to`:

<!-- ds:block id=tsp-oauthprovider-consent-4kq8wm2x -->
**onConsentPage** · [`clients/ts/examples/plugin-protocols.ts:16-26`](../../clients/ts/examples/plugin-protocols.ts#L16-L26)

```typescript
export async function onConsentPage(ask: (clientName: string, scope: string) => Promise<boolean>): Promise<void> {
  const query = new URLSearchParams(location.search);
  const client = await auth.oauthprovider.publicClient({ client_id: query.get("client_id") ?? "" });
  if (client.error) return; // auth.signed_out: the login page comes first
  const accept = await ask(client.data.client_name, query.get("scope") ?? "");
  // Without scope the consent grants every scope the client asked for; a
  // space-separated subset in scope narrows it. The client posts the signed
  // query back itself (oauth_query, from location.search).
  const { data } = await auth.oauthprovider.consent({ accept });
  if (data) location.assign(data.redirect_to);
}
```
<!-- /ds:block hash=11bfc0 -->

A "connected apps" page lists the user's consents and revokes one:

<!-- ds:block id=tsp-oauthprovider-consents-7wn3kx5q -->
**disconnectApp** · [`clients/ts/examples/plugin-protocols.ts:31-37`](../../clients/ts/examples/plugin-protocols.ts#L31-L37)

```typescript
export async function disconnectApp(clientName: string): Promise<boolean> {
  const { data } = await auth.oauthprovider.listConsents();
  const consent = (data?.consents ?? []).find((c) => c.client_name === clientName);
  if (!consent) return false;
  const { error } = await auth.oauthprovider.revokeConsent({ client_id: consent.client_id });
  return error === null;
}
```
<!-- /ds:block hash=5a373a -->

Registering clients from a developer page is `createClient` (a fresh session; its answer carries the `client_secret` once, and every defaulted field: the input `OauthproviderClientMetadata` needs only `redirect_uris`), with `listClients`, `getClient`, `updateClient`, `rotateSecret` and `deleteClient` beside it. The login page needs nothing from this namespace: it signs the user in with any sign-in plugin and navigates to the resume URL (Step 3).

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `oauthprovider.invalid_signature` and `oauthprovider.invalid_request` on the consent post (a query that was changed, expired or is for another user: start the authorization again from the client), `oauthprovider.not_found`, `oauthprovider.invalid_client_metadata` on registration, `oauthprovider.registration_closed`, `auth.fresh_session_required` on `createClient`, `updateClient` and `rotateSecret`.

There is no runnable TypeScript example for the provider's pages; the blocks above are type-checked by `task ts:check`, and the example's consent page in Step 3 runs the same calls with `fetch`.

Pitfalls:

- **Post `oauth_query` exactly as it arrived.** It is a signed copy of the authorize parameters; reordering or re-encoding it breaks the signature.
- **Navigate to `redirect_to`, never `fetch` it.** It is the client's redirect URI with the code (or the error) and belongs to another site.
- **Field names here are the protocol's snake_case** (`client_id`, `redirect_uris`, `oauth_query`), unlike the camelCase of the other namespaces, because the Go types follow RFC 7591 and the OAuth parameters.

Every method with its route and types: [TypeScript client reference › oauthprovider](../reference/ts-client.md#oauthprovider).

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `auth.New`: jwt plugin's Issuer must equal the provider's | `jwt.Issuer` differs from `oauthprovider.Issuer`, or it is unset and the BaseURL differs | Pass the same string to both |
| `auth.New`: a signer is required (`ErrNoJWT`) | No signer was passed to `New`, or the signer is a plugin (`jw`) that is missing from `WithPlugins` or listed after the provider | Pass a signer; list `jw` before `op` |
| `auth.New`: Issuer is required (`ErrNoIssuer`) | Not an absolute https URL (http only on a loopback host), or it has a query or fragment | Use the app's public origin |
| `auth.New`: no identifier can recover an account | The password plugin with `email.New(email.Login())` alone | Add `email.Recover()`, or pass `password.WithoutRecovery()` |
| Registration answers `invalid_redirect_uri` for `http://127.0.0.1:…/callback` | A loopback http URI is allowed only for `"application_type": "native"`; the default is `web` | Register the client as native, or use https |
| Registration answers 403 `registration_closed` | Registration is closed, or open only to signed-in users and the caller has no session | `AllowDynamicRegistration`, or `MCP()` for anonymous clients |
| The callback gets `error=invalid_target` | The client asked for a `resource` it is not linked to, or one never declared with `ProtectedResource` | `RegistrationDefaultResources`, or link the client; declare the resource |
| Authorize answers `invalid_client` or `client_disabled` instead of redirecting (an HTML page for a browser) | The client is unknown or an admin disabled it | Check the `client_id`; enable the client |
| Authorize answers `invalid_redirect` instead of redirecting | A redirect URI that is not registered exactly (a trailing slash counts) | Register the exact URI the client sends |
| The callback gets `error=invalid_request` for `offline_access` | No PKCE challenge: a refresh token needs one unless a confidential client sends `openid` and a `nonce` | Send `code_challenge` |
| The client's callback gets `error=consent_required` | No `ConsentPage`, or `prompt=none` without a stored consent | Set `ConsentPage`, or make the client `SkipConsent` |
| Consent answers `oauthprovider.invalid_signature` | The consent page changed the query it was sent | Post `location.search` back unchanged; narrow with `scope` |
| `invalid_client` at the token endpoint | Wrong secret, a disabled client, or the wrong method (Basic versus form) for the registered `token_endpoint_auth_method` | Use the registered method |
| Userinfo and the MCP server answer 401 right after a successful exchange | The client exchanged the same code twice; the second exchange revoked what the first issued | Exchange each code once |
| `invalid_grant` on a refresh | The refresh token was already used, so the family was revoked | Start again from authorize, or allow `RefreshReuseInterval` for clients that refresh concurrently |
| `invalid_target` at the token endpoint | A different `resource` at the exchange than at authorize | Send the same value |
| A resource disabled, changed or deleted on one instance still issues tokens on another | `CacheResources` keeps the policy in each process for its TTL; only the instance that wrote drops it at once | Use `CacheResourcesIn` with a shared store, wait out the TTL, lower it, or leave the cache off |
| `oauthprovider: resource cache get` warnings in the log | The store given to `CacheResourcesIn` is failing | Fix the store; meanwhile every issuance reads the database, so nothing is refused |
| `auth.New`: the CacheResources TTL is between 0 and 15m0s (`ErrBadResourceCacheTTL`) | A negative TTL, or one above `MaxResourceCacheTTL` | Pass 0 for the default, or at most 15 minutes |
| `auth.New` or `CreateClient` fails with `oauthprovider: auth.WithSecret is required by this feature`, or `/oauth2/end-session` answers `invalid_request` and discovery has no `end_session_endpoint` | No `auth.WithSecret`: the end-session confirmation, the pre-login lookup and the post-login gate all sign | Pass a secret of at least 32 random bytes |
| `/oauth2/end-session` answers `invalid_client` | The client was not created with `EnableEndSession: true`, or the hint's client is gone | Enable it on the client |
| The post-logout redirect does not happen; a page says it was not registered | `post_logout_redirect_uri` is not one of the client's `PostLogoutRedirectURIs`, exactly | Register the exact URI |
| Your API answers 401 `invalid_token` for a token that works elsewhere | The token was issued for another `resource` (its `aud`), was opaque (no `resource` asked), or the guard's `Issuer` differs | Ask for `resource=<the API's URL>`; set `IntrospectURL` for opaque tokens |
| Authorize answers `invalid_client` for an https `client_id` | `ClientIDMetadataDocuments` is off, the document could not be fetched (not a public address, a redirect, over 5 KB, not 200 JSON), `CIMDAllow` said no, or the document sets a member only the server decides | Serve the document publicly; remove the forbidden member |
| Authorize answers 429 `temporarily_unavailable` for a metadata document | The CIMD fetch governor refused: too many fetches in flight or in the last minute | Retry; raise `CIMDPolicy` limits |
| `invalid_client` with a `private_key_jwt` assertion | The `aud` is not the endpoint or issuer URL, `exp` is more than 5 minutes ahead, the `jti` was used before, or the key's `alg` (or curve) is not the header's | Fix the assertion; mint a fresh `jti` per request |

## Next

- [JWT](jwt.md) for the signing key and its rotation.
- [Device authorization](deviceauth.md) for CLIs and TVs that get these tokens without a browser on the device, with [`examples/device-oauth-tokens`](../../examples/device-oauth-tokens/).
- [Agent auth](agentauth.md) when the client is an AI agent that needs per-capability grants.
- [Errors](../concepts/errors.md) for every `oauthprovider.*` code.
- [Security](../concepts/security.md) for how the pipeline's checks apply to the provider's endpoints.

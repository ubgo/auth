# Other services: verify the app's JWTs anywhere

You will have a second service, in Go or in another language, that accepts requests from your users on the strength of a JWT your app issued, verifying it against the app's published key set and nothing else: no shared database, no call back to the app per request.

## Before you start

- [JWT](../plugins/jwt.md): the app issues tokens at `POST /auth/jwt/token` and publishes its keys at `GET /auth/jwt/jwks`.
- The runnable program is [`examples/api-keys-and-jwt`](../../examples/api-keys-and-jwt/): the app on `:8081`, a report service in Go on `:8082`. The Python transcript below was run against the same app.
- What a token contains: the header names the algorithm ([`EdDSA`](ds:block?id=algorithm-j38g35tv) by default, an RSA algorithm (`RS256`, or `RS384`, `RS512`, `PS256`, `PS384`, `PS512`) or an ECDSA one (`ES256`, `ES384`, `ES512`) when the app signs with such a key) and the key id; the payload carries `iss` (the app), `aud` (the service the token is for), `sub` (the user id), `sid` (the session id), `iat`, `nbf`, `exp`, `jti`, optionally `act` (the admin behind an impersonation) and the app's own claims. The key set is a standard JWKS: Ed25519 keys (`kty` [`OKP`](ds:block?id=keytypeokp-cx2p5h5q), `crv` [`Ed25519`](ds:block?id=curveed25519-w6kd4wru)) by default, `kty RSA` or `kty EC` (`crv P-256`, `P-384` or `P-521`) for the others. When the app uses `jwt.RemoteJWKS`, fetch the key set from the URL it gives you instead of `/auth/jwt/jwks`.

## Step 1 — Fetch the key set

At start, `GET <app>/auth/jwt/jwks`. Cache it. Refetch when a token names a `kid` you do not have: that is how a rotation reaches you.

```sh
curl -s localhost:8081/auth/jwt/jwks
```

```json
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"diSpY9DKkrGLiMhlb2k0IiBOpktf0t_ruBoHWYqv9qQ","kid":"EcBxSHhHD7H9yOWh","use":"sig","alg":"EdDSA"}]}
```

## Step 2 — Verify in a Go service

The plugin ships a verifier that needs no JWT library:

<!-- ds:block id=verifier-ny5srdz8 -->
**Verifier** · [`plugin/jwt/verify.go:31-48`](../../plugin/jwt/verify.go#L31-L48)

```go
type Verifier struct {
	// Keys maps key ids to public keys; build it with KeysFromJWKS or add
	// keys with KeyID.
	Keys map[string]crypto.PublicKey
	// Lookup finds a key Keys does not hold, such as one published after a
	// rotation; RemoteKeys.Lookup fetches the issuer's JWKS. Nil means Keys
	// is the whole set.
	Lookup   func(kid string) (crypto.PublicKey, bool)
	Issuer   string
	Audience string
	// Types are the JWS "typ" headers accepted; nil accepts "JWT" only, as
	// before. An OAuth resource server verifying access tokens sets
	// []string{"at+jwt"}. The session-cache type is never accepted.
	Types  []string
	Leeway time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}
```
<!-- /ds:block hash=e8f464 -->

<!-- ds:block id=fetchjwks-b7gr2ztn -->
**fetchJWKS** · [`examples/api-keys-and-jwt/main.go:310-321`](../../examples/api-keys-and-jwt/main.go#L310-L321)

```go
func fetchJWKS(c *http.Client, u string) (jwt.JWKS, error) {
	var set jwt.JWKS
	res, err := c.Get(u)
	if err != nil {
		return set, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return set, fmt.Errorf("%w: %d", errJWKSStatus, res.StatusCode)
	}
	return set, json.NewDecoder(res.Body).Decode(&set)
}
```
<!-- /ds:block hash=65205b -->

<!-- ds:block id=newreportservice-pvejk47d -->
**newReportService** · [`examples/api-keys-and-jwt/main.go:283-300`](../../examples/api-keys-and-jwt/main.go#L283-L300)

```go
func newReportService(v jwt.Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /report", func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		c, err := v.Verify(tok)
		if !ok || err != nil {
			log.Printf("report: refused: %v", err)
			writeJSON(w, http.StatusUnauthorized, reportError{Error: "invalid token"})
			return
		}
		var name string
		if raw, found := c.Extra[claimName]; found {
			_ = json.Unmarshal(raw, &name) // a malformed app claim leaves the name empty
		}
		writeJSON(w, http.StatusOK, reportResult{Subject: c.Subject, Name: name, ExpiresAt: c.ExpiresAt.UTC()})
	})
	return mux
}
```
<!-- /ds:block hash=19c0ee -->

<!-- ds:block id=verifier-verify-rj97wyhj lines=1-12 -->
**Verifier.Verify** · [`plugin/jwt/verify.go:158-249`](../../plugin/jwt/verify.go#L158-L249)

```go
func (v Verifier) Verify(token string) (Verified, error) {
	parts := strings.Split(token, segmentSeparator)
	if len(parts) != segmentCount {
		return Verified{}, fmt.Errorf("%w: not three parts", ErrInvalid)
	}
	// Strict: a segment has one spelling. The lenient decoder ignores the
	// unused bits of the last character, so one signature would have many
	// valid texts and a token could be re-encoded without the key.
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return Verified{}, fmt.Errorf("%w: header", ErrInvalid)
```
<!-- /ds:block hash=2dafc2 -->

What it checks, in order: three segments; the header decodes, its `typ` is `JWT` and its `alg` is one of `jwt.AlgValues` (`EdDSA`, the RSA and the ECDSA algorithms, never `none` or HMAC); the `kid` is in `Keys` and the token's `alg` is the algorithm of that key; the `kid` is in `Keys`; the signature verifies; the payload decodes; `sub` and `exp` are present; not expired and not before `nbf`, both with the leeway; `iss` and `aud` match when the verifier sets them. Anything else is `jwt.ErrInvalid`:

<!-- ds:block id=errinvalid-nnxsc8aq -->
**ErrInvalid** · [`plugin/jwt/verify.go:20`](../../plugin/jwt/verify.go#L20-L20)

```go
var ErrInvalid = errors.New("jwt: token is not valid")
```
<!-- /ds:block hash=184d4d -->

The example's report service in action, with a good token, a tampered one, and none:

```sh
curl -s localhost:8082/report -H "Authorization: Bearer $JWT"
curl -s localhost:8082/report -H "Authorization: Bearer ${JWT%??}AA"
curl -s localhost:8082/report
```

```json
{"subject":"usr_ggbadjf7fyqsz52xzmgxsovd","name":"Alice","expiresAt":"2026-10-01T05:21:21Z"}
{"error":"invalid token"}
{"error":"invalid token"}
```

```text
2026/10/01 10:46:21 report: refused: jwt: token is not valid: signature
2026/10/01 10:46:21 report: refused: jwt: token is not valid: not three parts
```

<!-- ds:block id=verified-ja44f9nz -->
**Verified** · [`plugin/jwt/verify.go:54-62`](../../plugin/jwt/verify.go#L54-L62)

```go
type Verified struct {
	Subject   string
	SessionID string
	// Actor is the admin behind an impersonation, or "".
	Actor     string
	ExpiresAt time.Time
	// Extra holds every claim the app added with Claims, raw.
	Extra map[string]json.RawMessage
}
```
<!-- /ds:block hash=937f77 -->

Check: `Verified.Subject` is the user id and `Verified.Extra["name"]` is the app's claim as raw JSON.

A verifier that loads the set once stops verifying at the app's next rotation. [`examples/jwt-keys`](../../examples/jwt-keys/) builds its report service on `jwt.RemoteKeys` instead, which fetches on first use and again when a token names a key it does not know ([JWT, Step 8](../plugins/jwt.md#step-8--let-the-other-service-follow-rotations-by-itself)):

<!-- ds:block id=jwtkeys-newverifier-m3k8vq2t -->
**newVerifier** · [`examples/jwt-keys/main.go:213-217`](../../examples/jwt-keys/main.go#L213-L217)

```go
func newVerifier(jwksURL, issuer string, hc *http.Client, now func() time.Time) (jwt.Verifier, *jwt.RemoteKeys) {
	remote := jwt.NewRemoteKeys(jwksURL, hc)
	remote.Now = now
	return jwt.Verifier{Lookup: remote.Lookup, Issuer: issuer, Audience: audience, Now: now}, remote
}
```
<!-- /ds:block hash=67a43d -->

Check: `TestRotation_TheReportServiceFollowsANewKey` in that example.

## Step 3 — Verify in another language

Any JWT library that supports the app's algorithm and JWKS works (an app that signs `RS256` reaches the widest set, including AWS API Gateway's JWT authorizer). Configure it with the same four facts: the key set URL, the app's algorithm as the only accepted one (`EdDSA` below), your service's audience and the app's issuer. Python with PyJWT and its `cryptography` extra, run against the example app:

```python
import json, os, urllib.request
import jwt  # PyJWT with the cryptography extra

jwks = json.load(urllib.request.urlopen("http://localhost:8081/auth/jwt/jwks"))
keys = {k["kid"]: jwt.PyJWK(k).key for k in jwks["keys"] if k["kty"] == "OKP" and k["crv"] == "Ed25519"}
token = os.environ["JWT"]
kid = jwt.get_unverified_header(token)["kid"]
claims = jwt.decode(token, keys[kid], algorithms=["EdDSA"], audience="reports", issuer="http://localhost:8081", leeway=30)
print(json.dumps({"sub": claims["sub"], "sid": claims["sid"], "name": claims.get("name"), "exp": claims["exp"]}))
```

```sh
pip install 'pyjwt[crypto]'
JWT=$JWT python3 verify.py
```

```json
{"sub": "usr_ggbadjf7fyqsz52xzmgxsovd", "sid": "ses_eu2rvsts3t2bu2kj4l7nsrhf", "name": "Alice", "exp": 1790832081}
```

Whatever the library, make sure of these, because a lenient default is how JWT verification fails in practice:

- Accept only the app's algorithm (`EdDSA` unless the app signs with RSA or P-256), or pin the algorithm per key as `jwt.Verifier` does. Never let the token's header choose the algorithm, and never accept `none` or an HMAC algorithm, which would let a client sign tokens with the public key.
- Look the key up by `kid`; refuse a token whose `kid` is unknown after one refetch.
- Require `exp` and `sub`; check `exp` and `nbf` with a small leeway (the Go verifier uses [30 seconds](ds:block?id=defaultleeway-sq3t3z4e)).
- Check `aud` is your service and `iss` is the app.
- Treat `act` as "an admin is acting as this user" and decide whether your service allows that.

Check: the same token verifies in Go and in the other language, and a token with its signature altered is refused by both.

## Step 4 — Decide what the token is not

- It is not revocable. A revoked session's tokens work until `exp`, at most the issuing app's TTL ([5 minutes](ds:block?id=defaultttl-kqd34f84) by default, [1 hour](ds:block?id=maxttl-n53tvy7p) at most). If a minute matters, call the app.
- It is not single use. `jti` is unique per token, but the verifier does not track it; replay within the lifetime is possible, so put the token in the `Authorization` header over TLS only.
- It is not the session. The browser keeps the session cookie for the app; the second service sees the token and nothing else.

## Step 5 — Or make the auth server its own process

Everything above also works when authentication is not embedded in the product's app but is a service of its own: one process that owns the users and sessions and serves nothing but the ready-made pages, the JSON routes and the JWT plugin, while every other service verifies its tokens exactly as in steps 2 and 3. [`examples/auth-server`](../../examples/auth-server/) is that shape; its whole handler is:

<!-- ds:block id=newhandler-authserver-4nx8rv5c -->
**newHandler** · [`examples/auth-server/main.go:196-203`](../../examples/auth-server/main.go#L196-L203)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.Health(),
		authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: appName, Version: "1", Servers: []string{baseURL}})))
	mux.Handle("GET "+homePath+"{$}", authhttp.Middleware(a)(http.HandlerFunc(home)))
	mux.Handle("/", authui.Handler(a, authui.AppName(appName), authui.AfterSignIn(homePath)))
	return mux
}
```
<!-- /ds:block hash=e6c721 -->

The plugin list is email, password and jwt, nothing else:

<!-- ds:block id=newauth-authserver-7pk3mq2w -->
**newAuth** · [`examples/auth-server/main.go:172-182`](../../examples/auth-server/main.go#L172-L182)

```go
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			jwt.New(jwt.WithSigningKey(key), jwt.Audience(jwtAudience), jwt.Claims(nameClaim)),
		),
	)
}
```
<!-- /ds:block hash=bbd22a -->

A browser signs in on the pages and holds a session cookie for the auth server's origin; a client of the product then mints a JWT with `POST /auth/jwt/token` and sends it to the other services, which hold no session store, no auth tables and make no call to the auth server per request. The example's API service is the verifier of step 2 behind one route:

<!-- ds:block id=newapiservice-authserver-9wq6tz3h -->
**newAPIService** · [`examples/auth-server/main.go:254-271`](../../examples/auth-server/main.go#L254-L271)

```go
func newAPIService(v jwt.Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/profile", func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		c, err := v.Verify(tok)
		if !ok || err != nil {
			log.Printf("api: refused: %v", err)
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "invalid token"})
			return
		}
		var name string
		if raw, found := c.Extra[claimName]; found {
			_ = json.Unmarshal(raw, &name) // a malformed app claim leaves the name empty
		}
		writeJSON(w, http.StatusOK, profileResult{Subject: c.Subject, Name: name, ExpiresAt: c.ExpiresAt.UTC()})
	})
	return mux
}
```
<!-- /ds:block hash=a20a31 -->

What changes against the embedded shape: cookies belong to the auth server's host, so a product page on another origin reaches the routes cross-origin ([SPA frontends](spa-frontends.md)) or through the pages; `authhttp.OpenAPI` and `authhttp.Health` are worth switching on because the server has clients that are not its own code; and the trade-off in step 4 stands, a revoked session's tokens live until `exp`.

## What can go wrong

- `jwt: token is not valid: unknown key "…"` — the app rotated its key; refetch the key set.
- `jwt: token is not valid: expired` — the token was minted more than its TTL ago (or the session it came from expired sooner). The frontend fetches a new one.
- `jwt: token is not valid: audience "…"` or `issuer "…"` — the verifier's `Audience`/`Issuer` do not match what the app set with `jwt.Audience` and `auth.WithBaseURL` or `jwt.Issuer`.
- `jwt: token is not valid: algorithm "…"` — the token is not from this app.
- PyJWT raises `InvalidAlgorithmError` — install the `cryptography` extra (`pip install "pyjwt[crypto]"`); EdDSA needs it.
- The key set is served over plain HTTP in development; in production fetch it over HTTPS, or a network attacker could hand your service their own keys.

## Next

- [JWT](../plugins/jwt.md): options on the issuing side.
- [Mobile apps](mobile-apps.md) and [SPA frontends](spa-frontends.md): how the frontend holds the session that mints these tokens.

# JWT: hand another service a signed "who is calling"

You will have a route where a signed-in browser gets a short-lived JSON Web Token, a public key set the other service fetches once, and that service verifying tokens with no access to your auth database. The session stays an opaque, revocable cookie; the JWT is a copy of "who" for a few minutes.

## Before you start

- [First app](../start/first-app.md): an app with a sign-in method, because a token is minted from a session.
- The plugin is `github.com/ubgo/auth/plugin/jwt`, in the core module; it signs with Ed25519 (`EdDSA`, the default), RSA (`RS256`) or ECDSA P-256 (`ES256`) from the standard library and nothing else. Its README is the [reference](../../plugin/jwt/README.md).
- The runnable program is [`examples/api-keys-and-jwt`](../../examples/api-keys-and-jwt/): the app on `:8081` and a second program, a report service, on `:8082` that trusts only the published keys. The transcript below was captured from it.
- Steps 6, 8, 9 and 10 are one more program, [`examples/jwt-keys`](../../examples/jwt-keys/): keys that rotate every day, a report service that follows them through `RemoteKeys`, and an RS256 token for a job with no session.
- When to use it: your frontend calls a second backend, and that backend must know the user without asking your app on every request or sharing its database. When not to: as the session itself (a signed token cannot be revoked), or to call your own app's API from a script (that is an [API key](apikey.md)).

## Step 1 — Make a signing key

The plugin signs with a private key you provide, and the key decides the algorithm: Ed25519 signs `EdDSA` (the default, and what this guide uses), RSA `RS256`, ECDSA P-256 `ES256` (Step 10). Generate one once, keep its 32-byte seed in your secret store, and build the key from it at start, so every instance signs with the same key and tokens survive a restart:

<!-- ds:block id=signingkey-jmtjdh92 -->
**signingKey** · [`examples/api-keys-and-jwt/main.go:155-169`](../../examples/api-keys-and-jwt/main.go#L155-L169)

```go
func signingKey(getenv func(string) string) (ed25519.PrivateKey, error) {
	if s := getenv(envSigningKey); s != "" {
		seed, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s must be %d bytes, base64url without padding", envSigningKey, ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	log.Printf("%s is not set: signing with a new key; tokens stop verifying when the process restarts", envSigningKey)
	return key, nil
}
```
<!-- /ds:block hash=2a7275 -->

Check: with `JWT_SIGNING_KEY` unset the example generates a key and logs `JWT_SIGNING_KEY is not set: signing with a new key; tokens stop verifying when the process restarts`.

## Step 2 — Wire the plugin

Name the audience (the service the tokens are for) and, if the other service needs more than the user id, add claims:

<!-- ds:block id=withsigningkey-5f28debd -->
**WithSigningKey** · [`plugin/jwt/jwt.go:142-158`](../../plugin/jwt/jwt.go#L142-L158)

```go
func WithSigningKey(k crypto.Signer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.WithSigningKey", k) {
			return
		}
		switch key := k.(type) {
		case ed25519.PrivateKey:
			// Public() would panic on a short Ed25519 key, so it is
			// checked here rather than in Validate.
			if len(key) == ed25519.PrivateKeySize {
				p.signer = keySigner{key: key}
			}
		default:
			p.signer = keySigner{key: k}
		}
	}
}
```
<!-- /ds:block hash=241516 -->

<!-- ds:block id=audience-rxjspxrf -->
**Audience** · [`plugin/jwt/jwt.go:185-187`](../../plugin/jwt/jwt.go#L185-L187)

```go
func Audience(aud ...string) Option {
	return func(p *Plugin) { p.audience = append(p.audience, aud...) }
}
```
<!-- /ds:block hash=52f0b0 -->

<!-- ds:block id=claims-w22bs5en -->
**Claims** · [`plugin/jwt/jwt.go:222-229`](../../plugin/jwt/jwt.go#L222-L229)

```go
func Claims(fn func(ctx context.Context, u auth.User) map[string]any) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.Claims", fn) {
			return
		}
		p.claims = fn
	}
}
```
<!-- /ds:block hash=874871 -->

<!-- ds:block id=newauth-eczkzgwy -->
**newAuth** · [`examples/api-keys-and-jwt/main.go:176-187`](../../examples/api-keys-and-jwt/main.go#L176-L187)

```go
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			apikey.New(apikey.Scopes(scopeOrdersRead, scopeOrdersWrite)),
			jwt.New(jwt.WithSigningKey(key), jwt.Audience(jwtAudience), jwt.Claims(nameClaim)),
		),
	)
}
```
<!-- /ds:block hash=791822 -->

<!-- ds:block id=nameclaim-a6ksmavc -->
**nameClaim** · [`examples/api-keys-and-jwt/main.go:193-195`](../../examples/api-keys-and-jwt/main.go#L193-L195)

```go
func nameClaim(_ context.Context, u auth.User) map[string]any {
	return map[string]any{claimName: u.Name}
}
```
<!-- /ds:block hash=fb2dff -->

The issuer (`iss`) defaults to the origin of `auth.WithBaseURL`; `jwt.Issuer` overrides it. A claim named like one the plugin writes (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid`, `act`) fails the call instead of overwriting it.

Check: `auth.New` returns no error. It refuses a missing key ("jwt: pass jwt.WithSigningKey with an Ed25519, RSA or P-256 private key, or jwt.WithSigner"), a key of no supported algorithm (`jwt.ErrUnsupportedKey`) and a missing issuer ("jwt: needs auth.WithBaseURL or jwt.Issuer").

## Step 3 — Mint a token from the session

`POST /auth/jwt/token` with the session cookie. The token lives [5 minutes](ds:block?id=defaultttl-kqd34f84) by default and never longer than the session it came from.

```sh
curl -s -b ck.txt -X POST localhost:8081/auth/jwt/token -H 'Origin: http://localhost:8081'
```

```json
{"token":"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IkVjQnhTSGhIRDdIOXlPV2gifQ.eyJhdWQiOiJyZXBvcnRzIiwiZXhwIjoxNzkwODMyMDgxLCJpYXQiOjE3OTA4MzE3ODEsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSIsImp0aSI6IktDRkZNTzNMWUE0TEhFWDcySlRYSzUzMlBCIiwibmFtZSI6IkFsaWNlIiwibmJmIjoxNzkwODMxNzgxLCJzaWQiOiJzZXNfZXUycnZzdHMzdDJidTJrajRsN25zcmhmIiwic3ViIjoidXNyX2dnYmFkamY3Znlxc3o1Mnh6bWd4c292ZCJ9.5H02kbttJqIQbGPlKboWDikMIhOFbYX-VwyxLOWU7pNcDvrCEQC1ANszS0fD8Ck0w3z5wylhmMQ01xF0v-2FAw","expiresAt":"2026-10-01T05:21:21.747096Z"}
```

<!-- ds:block id=tokenresult-bjwxk5ww -->
**TokenResult** · [`plugin/jwt/jwt.go:359-362`](../../plugin/jwt/jwt.go#L359-L362)

```go
type TokenResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}
```
<!-- /ds:block hash=7fa07f -->

The payload, decoded: the app is the issuer, the report service the audience, `sub` is the user id, `sid` the session id, and `name` the app's own claim.

```sh
echo "$JWT" | cut -d. -f1 | tr '_-' '/+' | base64 -d   # the header (pad with = as needed)
echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | base64 -d | jq -c .
```

```json
{"alg":"EdDSA","typ":"JWT","kid":"EcBxSHhHD7H9yOWh"}
{"aud":"reports","exp":1790832081,"iat":1790831781,"iss":"http://localhost:8081","jti":"KCFFMO3LYA4LHEX72JTXK532PB","name":"Alice","nbf":1790831781,"sid":"ses_eu2rvsts3t2bu2kj4l7nsrhf","sub":"usr_ggbadjf7fyqsz52xzmgxsovd"}
```

From Go, for the signed-in user of the request in `ctx`:

<!-- ds:block id=plugin-token-zbw68s25 -->
**Plugin.Token** · [`plugin/jwt/jwt.go:393-395`](../../plugin/jwt/jwt.go#L393-L395)

```go
func (p *Plugin) Token(ctx context.Context) (TokenResult, error) {
	return p.token.Call(ctx, struct{}{})
}
```
<!-- /ds:block hash=717dfd -->

A caller without a session, or with an API key, gets none (`$KEY` is a key from `POST /auth/apikey/create`):

```sh
curl -s -X POST localhost:8081/auth/jwt/token -H 'Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/jwt/token -H "Authorization: Bearer $KEY"
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"error":{"code":"auth.api_key_refused","message":"This cannot be done with an API key."}}
```

Check: the header is `{"alg":"EdDSA","typ":"JWT","kid":"…"}`: the algorithm is the signing key's, never a choice the token makes.

## Step 4 — Publish the keys

`GET /auth/jwt/jwks` is public and answers the key set: the current key first, then any `AlgorithmKeys`, then any `PreviousKeys`. In-process, `PublicKeys()` returns the same.

```sh
curl -s localhost:8081/auth/jwt/jwks
```

```json
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"diSpY9DKkrGLiMhlb2k0IiBOpktf0t_ruBoHWYqv9qQ","kid":"EcBxSHhHD7H9yOWh","use":"sig","alg":"EdDSA"}]}
```

<!-- ds:block id=jwk-abe7xa5t -->
**JWK** · [`plugin/jwt/jwt.go:371-381`](../../plugin/jwt/jwt.go#L371-L381)

```go
type JWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv,omitempty"`
	X       string `json:"x,omitempty"`
	Y       string `json:"y,omitempty"`
	N       string `json:"n,omitempty"`
	E       string `json:"e,omitempty"`
	KeyID   string `json:"kid"`
	Use     string `json:"use"`
	Alg     string `json:"alg"`
}
```
<!-- /ds:block hash=c9b36b -->

<!-- ds:block id=plugin-publickeys-47hkqn9t -->
**Plugin.PublicKeys** · [`plugin/jwt/jwt.go:402-414`](../../plugin/jwt/jwt.go#L402-L414)

```go
func (p *Plugin) PublicKeys() JWKS {
	keys := p.publishedKeys()
	out := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		// auth.New refused an unsupported key, but a custom Signer's list
		// may change later; a key with no JWK form is left out rather than
		// published broken.
		if j, ok := jwkOf(k); ok {
			out.Keys = append(out.Keys, j)
		}
	}
	return out
}
```
<!-- /ds:block hash=2caa72 -->

<!-- ds:block id=keysfromjwks-xkm5vbya -->
**KeysFromJWKS** · [`plugin/jwt/verify.go:69-77`](../../plugin/jwt/verify.go#L69-L77)

```go
func KeysFromJWKS(set JWKS) map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if pub, ok := keyOfJWK(k); ok {
			out[k.KeyID] = pub
		}
	}
	return out
}
```
<!-- /ds:block hash=e33482 -->

Check: `kid` in the key set equals `kid` in the token's header.

## Step 5 — Verify in the other service

The receiving Go service needs the key set, the issuer and itself as audience, and no JWT library:

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

Every refusal is `jwt.ErrInvalid`, wrapped with the reason for the log; the client is told only that the token is not valid. [Other services](../integrations/other-services.md) covers services in other languages.

Check: a token with one byte of its signature changed is refused, and the log says `jwt: token is not valid: signature`.

## Step 6 — Rotate the key

Two ways. By hand: generate a new key, put the old public key in `PreviousKeys`, deploy. Tokens signed before the rotation verify until they expire (at most the TTL), and a service that caches the key set refetches when it meets a `kid` it does not know.

Automatically: `jwt.Rotating(seed, interval, grace)` is a signer that derives a fresh Ed25519 key for every `interval` from one 32-byte seed with HKDF, so every instance of your app derives the same key for the same period with no shared storage and no coordination. The key set publishes the current key first, then the keys of the periods that ended within `grace`, which must be at least the TTL; a service that refetches on an unknown `kid` never misses one. The seed is the one secret: it stands in for the stored private key, so rotating the seed is how a leak is handled.

<!-- ds:block id=rotating-q3nx8wtd -->
**Rotating** · [`plugin/jwt/signer.go:118-120`](../../plugin/jwt/signer.go#L118-L120)

```go
func Rotating(seed []byte, interval, grace time.Duration) Signer {
	return &rotatingSigner{seed: seed, interval: interval, grace: grace, now: time.Now}
}
```
<!-- /ds:block hash=e19da3 -->

<!-- ds:block id=jwtkeys-newjwt-p6c2xr8v -->
**newJWT** · [`examples/jwt-keys/main.go:169-175`](../../examples/jwt-keys/main.go#L169-L175)

```go
func newJWT(seed []byte, rsaKey crypto.Signer) *jwt.Plugin {
	return jwt.New(
		jwt.WithSigner(jwt.Rotating(seed, rotationInterval, rotationGrace)),
		jwt.AlgorithmKeys(rsaKey),
		jwt.Audience(audience),
	)
}
```
<!-- /ds:block hash=75a7a6 -->

The interval is at least [an hour](ds:block?id=minrotationinterval-h7zt2vcp), so the key set does not churn faster than verifiers refetch it.

<!-- ds:block id=previouskeys-rek5vjkg -->
**PreviousKeys** · [`plugin/jwt/jwt.go:166-173`](../../plugin/jwt/jwt.go#L166-L173)

```go
func PreviousKeys(keys ...crypto.PublicKey) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "jwt.PreviousKeys", keys) {
			return
		}
		p.previous = append(p.previous, keys...)
	}
}
```
<!-- /ds:block hash=5f5548 -->

Check: `TestRotation_PreviousKeysStillVerify` and `TestRotating_DerivesTheSameKeysEverywhereAndPublishesWithinGrace` in the plugin pin both ways; in the example, `TestRotation_TheReportServiceFollowsANewKey` signs one token two minutes before midnight and one after, and `TestRotation_EveryInstanceDerivesTheSameKey` checks two instances built from one seed.

## Step 7 — Keep the private key in a KMS

When the signing key must never be in the process, the simplest way is a KMS client that implements `crypto.Signer`, passed to `jwt.WithSigningKey` as if it were a key: the plugin hashes and converts the signature itself (an ECDSA signature arrives in ASN.1 and is turned into the `r||s` form JWS wants). Otherwise implement `jwt.Signer`: `PublicKeys` lists the keys the JWKS should publish (the signing key first) and `Sign` asks the service for the JWS signature of the input with the key the header named. The algorithm follows the first key (Ed25519, RSA of at least 2048 bits, or P-256), and every signature is checked against the published key before a token is minted, so a KMS that answers with the wrong key or encoding fails the call with `jwt.ErrSignature` instead of handing out a token no verifier accepts.

<!-- ds:block id=signer-v8kd3qxw -->
**Signer** · [`plugin/jwt/signer.go:26-42`](../../plugin/jwt/signer.go#L26-L42)

```go
type Signer interface {
	// PublicKeys returns every key a token in flight may carry, the key
	// that signs now first: its KeyID becomes the token's kid header, and
	// the JWKS publishes the list in this order. An empty list means the
	// signer cannot sign, and Token fails with ErrSignerKey.
	PublicKeys() []crypto.PublicKey
	// Sign returns the JWS signature of the signing input (header dot
	// payload) with the private half of key, the first key PublicKeys
	// returned when the token's header was built: for EdDSA the Ed25519
	// signature of the input, for RS256 the PKCS #1 v1.5 signature of its
	// SHA-256, for ES256 the 64-byte r||s of its SHA-256 (RFC 7518 section
	// 3.4, not the ASN.1 form crypto.Signer returns). The key is passed
	// back, rather than assumed current, so a signer whose key changes
	// between the two calls, at the instant of a rotation, still signs with
	// the key the header names.
	Sign(ctx context.Context, key crypto.PublicKey, signingInput []byte) ([]byte, error)
}
```
<!-- /ds:block hash=33c33f -->

<!-- ds:block id=withsigner-k2mz7nrt -->
**WithSigner** · [`plugin/jwt/signer.go:53-60`](../../plugin/jwt/signer.go#L53-L60)

```go
func WithSigner(s Signer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("jwt.WithSigner", s) {
			return
		}
		p.signer = s
	}
}
```
<!-- /ds:block hash=691891 -->

A signer that publishes no key fails the token call with `jwt.ErrSignerKey` rather than minting a token nobody could verify.

## Step 8 — Let the other service follow rotations by itself

A verifying service that loaded the key set once stops verifying after a rotation. `jwt.NewRemoteKeys(url, client)` fetches the key set over HTTP and caches it, refetching when a token names a `kid` it does not know, at most once a [minute](ds:block?id=remoteminrefresh-c6vw2kzp) so forged tokens cannot make it hammer your app, and at least once a [day](ds:block?id=remotemaxage-t9hr4nxb) so a retired key disappears. Hand its `Lookup` to the verifier:

<!-- ds:block id=remotekeys-m5bz7qwn -->
**RemoteKeys** · [`plugin/jwt/remote.go:47-57`](../../plugin/jwt/remote.go#L47-L57)

```go
type RemoteKeys struct {
	url string
	hc  *http.Client
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
	lastErr error
}
```
<!-- /ds:block hash=6aaad6 -->

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

The example's app publishes the rotating key first and the RSA key after it:

```sh
curl -s localhost:8081/auth/jwt/jwks | python3 -c 'import json,sys; [print(k["kty"],k["alg"],k["kid"]) for k in json.load(sys.stdin)["keys"]]'
curl -s localhost:8082/report -H "Authorization: Bearer $JWT"
```

```text
OKP EdDSA sRqgJwq9xyckYw_l
RSA RS256 156nz-RRj9TnJlXG
{"subject":"usr_epa5gyhu4kmqbchbpnwnuhsn","sessionId":"ses_fecqp7ib3s5mydazgvljdaq3"}
```

A fetch that fails keeps the keys already held, so a brief outage of the app does not sign every caller out; `remote.LastError()` reports it for a health check.

Check: `TestRemoteKeys_FetchesCachesAndBoundsRefresh` in the plugin pins the refresh bounds.

## Step 9 — Mint a token without a session

Some tokens name no session: a service token for a nightly job, a token for a user the app looked up itself, a token a webhook receiver should verify. `jw.Sign(ctx, jwt.SignRequest{Subject: "job-7", Audience: []string{"reports"}, TTL: 10 * time.Minute, Claims: map[string]any{"role": "worker"}})` mints one under the plugin's key and issuer:

<!-- ds:block id=signrequest-b7kx3nqm -->
**SignRequest** · [`plugin/jwt/jwt.go:502-530`](../../plugin/jwt/jwt.go#L502-L530)

```go
type SignRequest struct {
	// Subject is the sub claim; required.
	Subject string
	// Audience is the aud claim; nil takes the plugin's Audience.
	Audience []string
	// TTL is the token's lifetime; 0 takes the plugin's, and more than MaxTTL
	// becomes MaxTTL, like WithTTL.
	TTL time.Duration
	// Claims are app claims; a registered claim here is ErrReservedClaim.
	Claims map[string]any
	// Type is the JWS "typ" header; "" is "JWT". An OAuth provider's access
	// token uses "at+jwt" (RFC 9068). It is a media-type name: letters,
	// digits and "+-." only (ErrBadType otherwise), and never
	// SessionCacheType, so no Sign call can mint a session-cache snapshot.
	Type string
	// SessionID is the sid claim, for an ID token that a logout request can
	// later bind to the browser's session; "" leaves it out.
	SessionID string
	// Alg picks the signing algorithm, better-auth's signingAlgorithm: ""
	// or the signing key's algorithm signs with it, another one with the
	// AlgorithmKeys key of that algorithm, and an algorithm with no key is
	// ErrNoAlgorithmKey.
	Alg Alg
	// KeyID picks the signing key by its key id among the signing key and
	// the AlgorithmKeys keys, better-auth's signingKeyId; a key id the
	// plugin does not sign with, or one of another algorithm than Alg, is
	// ErrNoSigningKey.
	KeyID string
}
```
<!-- /ds:block hash=294a78 -->

The token carries `sub`, `iss`, `aud`, `iat`, `nbf`, `exp` and `jti` but no `sid`, so a receiver's `Verified.SessionID` is empty; the plugin's `Subject` and `Claims` options do not apply, since the caller names both; an empty `TTL` takes the plugin's and a long one is capped at `MaxTTL`. `Sign` is Go only and for trusted code: whatever it mints is as good as a session token to the receiving service, which is why no route offers it.

The example's nightly job, in RS256 for a consumer that accepts RSA only:

<!-- ds:block id=jwtkeys-mintjobtoken-z9w4hd3k -->
**mintJobToken** · [`examples/jwt-keys/main.go:196-203`](../../examples/jwt-keys/main.go#L196-L203)

```go
func mintJobToken(ctx context.Context, jw *jwt.Plugin) (jwt.TokenResult, error) {
	return jw.Sign(ctx, jwt.SignRequest{
		Subject: jobSubject,
		TTL:     jobTTL,
		Alg:     jwt.RS256,
		Claims:  map[string]any{claimRole: roleWorker},
	})
}
```
<!-- /ds:block hash=fdd321 -->

```sh
curl -s localhost:8082/report -H "Authorization: Bearer $JOB_TOKEN"
```

```json
{"subject":"job:nightly-export","sessionId":"","role":"worker"}
```

Check: `TestSign_MintsATokenWithoutASession`, and `TestJobToken_RS256WithoutASession` in the example.

Two more fields: `SessionID` puts a `sid` claim in the token (the OAuth provider sets it on ID tokens, so a logout request can name the session), and `Type` sets the header's `typ`, `JWT` by default. A receiver accepts another type only when its `jwt.Verifier` lists it in `Types`, so an `at+jwt` access token is never taken for an ID token and the reverse. The session-cache snapshot's type cannot be signed this way (`jwt.ErrBadType`).

## Step 10 — Sign with RSA or ECDSA

Some consumers accept only RSA or ECDSA: AWS API Gateway's JWT authorizer, older JWT libraries, a KMS without Ed25519. Pass an RSA key (at least [2048 bits](ds:block?id=minrsabits-q8w2nd5k)) or an ECDSA key instead: an RSA key signs `RS256`, and an ECDSA key the algorithm of its curve (P-256 `ES256`, P-384 `ES384`, P-521 `ES512`). For the other RSA algorithms (`RS384`, `RS512`, `PS256`, `PS384`, `PS512`), bind the key with `jwt.RSAKey(key, jwt.PS256)`; it wraps any RSA `crypto.Signer`, a KMS key included. `jwt.GenerateKey` makes a key for any of the ten algorithms (RSA at 2048 bits; pass a larger key yourself for a bigger modulus), which you store like the Ed25519 seed (PKCS #8 through `x509.MarshalPKCS8PrivateKey` is the usual form):

<!-- ds:block id=generatekey-m4ps8tvx -->
**GenerateKey** · [`plugin/jwt/alg.go:290-303`](../../plugin/jwt/alg.go#L290-L303)

```go
func GenerateKey(alg Alg) (crypto.Signer, error) {
	switch {
	case alg == EdDSA || alg == "":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case slices.Contains(rsaAlgs, alg):
		k, err := rsa.GenerateKey(rand.Reader, MinRSABits)
		return bindRSA(k, err, alg)
	}
	if c, ok := curveOf(func(c ecCurve) bool { return c.alg == alg }); ok {
		return ecdsa.GenerateKey(c.curve, rand.Reader)
	}
	return nil, fmt.Errorf("%w: algorithm %q", ErrUnsupportedKey, alg)
}
```
<!-- /ds:block hash=3b8905 -->

```go
key, err := jwt.GenerateKey(jwt.RS256) // once; then load it from your secret store
jw := jwt.New(jwt.WithSigningKey(key), jwt.Audience("reports"))
```

The key set then publishes `kty RSA` with `n` and `e` (or `kty EC`, the curve, `x` and `y`), `alg` naming the algorithm, and a `kid` hashed from the key; one modulus bound to two algorithms is two keys with two ids. A verifier never lets the token choose: `jwt.Verifier` looks the key up by `kid` and accepts the token only when its `alg` is that key's algorithm, so `alg: none`, an HMAC algorithm, or an `EdDSA` header on an RSA key is `ErrInvalid` before any signature is checked. Moving from one algorithm to another is a rotation by hand: the new key signs and the old public key stays in `PreviousKeys` until the tokens it signed expire. `Rotating` derives Ed25519 keys only.

Check: `TestAlgorithms_EachSignsPublishesAndVerifies` and `TestVerify_PinsTheAlgorithmToTheKey`.

Several algorithms at once, better-auth's `keyPairConfigs`: keep the signing key for session tokens and add keys of other algorithms with `jwt.AlgorithmKeys(rsaKey, p256Key)`. Each is published in the key set (after the signing key, before `PreviousKeys`), and `jw.Sign(ctx, jwt.SignRequest{Subject: "job-7", Alg: jwt.RS256})` signs with the one of that algorithm, for a consumer that accepts RSA only. An algorithm with no key is `jwt.ErrNoAlgorithmKey`, naming it. Several keys may share an algorithm (the first, the signing key before the others, answers `Alg`), and `jwt.SignRequest{KeyID: kid}` picks one by key id, better-auth's per-resource `signingKeyId` (`jwt.ErrNoSigningKey` for a key id it does not sign with); one key given twice fails `auth.New` with `jwt.ErrAlgorithmKeys`. better-auth creates such a key the first time it is asked for and stores it; this plugin stores no keys, so the app makes them once with `jwt.GenerateKey` and loads them from its secret store.

<!-- ds:block id=algorithmkeys-h7tn2xqc -->
**AlgorithmKeys** · [`plugin/jwt/algkeys.go:43-56`](../../plugin/jwt/algkeys.go#L43-L56)

```go
func AlgorithmKeys(keys ...crypto.Signer) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "jwt.AlgorithmKeys", keys) {
			return
		}
		for _, k := range keys {
			if ek, ok := k.(ed25519.PrivateKey); ok && len(ek) != ed25519.PrivateKeySize {
				p.algKeysErr = fmt.Errorf("%w: a short Ed25519 key", ErrAlgorithmKeys)
				continue
			}
			p.algKeys = append(p.algKeys, keySigner{key: k})
		}
	}
}
```
<!-- /ds:block hash=9a7f2d -->

Check: `TestAlgorithmKeys` and `TestAlgorithmKeys_Validate`; the example's `newJWT` (Step 6) publishes an RSA key beside the rotating Ed25519 one.

## Step 11 — Move or hand off the key set

`jwt.JWKSPath("/.well-known/jwks.json")` serves the key set at `GET /auth/jwt/.well-known/jwks.json`; the old path answers 404. The path starts with `/`, holds letters, digits and `-._~/` only, has no `..` or `//`, and is not `/token` or `/template`.

<!-- ds:block id=jwkspath-c7n4wq8z -->
**JWKSPath** · [`plugin/jwt/routes.go:64`](../../plugin/jwt/routes.go#L64-L64)

```go
func JWKSPath(path string) Option { return func(p *Plugin) { p.jwksPath = path } }
```
<!-- /ds:block hash=2360bf -->

`jwt.RemoteJWKS(url)` says the key set lives elsewhere, typically at your KMS's own JWKS endpoint: the plugin stops serving its route (404) and `jw.JWKSURL()` returns the URL for you to configure in each verifier (`jwt.NewRemoteKeys(url, nil)`, jose's `createRemoteJWKSet`, an API gateway's issuer settings). No token names the URL: a `jku` header would let a forged token point the verifier at the forger's keys. The URL must be `https` (plain `http` only for a loopback host).

<!-- ds:block id=remotejwks-r2k8vm5d -->
**RemoteJWKS** · [`plugin/jwt/routes.go:79`](../../plugin/jwt/routes.go#L79-L79)

```go
func RemoteJWKS(rawURL string) Option { return func(p *Plugin) { p.remoteJWKS = rawURL } }
```
<!-- /ds:block hash=a382cf -->

Check: `TestJWKSPath_MovesTheRoute` and `TestRemoteJWKS_TurnsTheRouteOffAndPublishesTheURL`.

## Step 12 — A token with every session read

`jwt.IssueOnSession()` makes `GET /auth/session` (and `Auth.Session`, on every transport) hand out a fresh token in the `Set-Auth-JWT` response header, listed in `Access-Control-Expose-Headers` so a frontend on another origin can read it. It is the token `POST /auth/jwt/token` would return at that moment; a signed-out read answers 401 and carries none. From Go, read it with `jwt.SessionJWT(ctx)` after `a.Session(ctx)`. It is off by default because it hands a bearer token to every page that reads the session.

<!-- ds:block id=issueonsession-h5q9wz3b -->
**IssueOnSession** · [`plugin/jwt/routes.go:94`](../../plugin/jwt/routes.go#L94-L94)

```go
func IssueOnSession() Option { return func(p *Plugin) { p.issueOnSession = true } }
```
<!-- /ds:block hash=3658dd -->

```js
const res = await fetch("https://app.example.com/auth/session", { credentials: "include" });
const jwt = res.headers.get("Set-Auth-JWT"); // null when signed out
```

[`examples/jwt-session`](../../examples/jwt-session) turns it on:

<!-- ds:block id=jwtsession-newjwt-4hq8mz2c -->
**newJWT** · [`examples/jwt-session/main.go:127-133`](../../examples/jwt-session/main.go#L127-L133)

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

Try it: `go run ./jwt-session`, sign up with curl, then `curl -si -b c.txt localhost:8081/auth/session`. The answer carries `Access-Control-Expose-Headers: Set-Auth-JWT` and the token (curl prints the name as Go canonicalizes it, `Set-Auth-Jwt`); `curl -s localhost:8081/reports -H "Authorization: Bearer $TOKEN"` answers the user and session id from it. Signed out, the read is a 401 with no token.

Check: `TestSessionReadHandsOutAToken` in the example; `TestJWT_IssueOnSessionHeader` in the integration suite, on SQLite, Postgres and MySQL.

## Step 13 — A session cache that is a signed JWT

The core's session cache keeps a sealed (encrypted) copy of the session in a cookie, so most requests skip the session lookup. `jwt.NewSessionCache(jw)` is the same cache with a signed JWT as the copy, better-auth's `sessionCookieCache`: header `typ` [`ubgo-auth.session-cache+jwt`](ds:block?id=sessioncachetype-w8d3kq6n) and `kid`, claims `iss`, `aud` ([`ubgo-auth:session-cache`](ds:block?id=sessioncacheaudience-v4m7zt2h)), `sub`, `sid`, `iat`, `exp`, the session, the user, and a binding to the session token.

<!-- ds:block id=newsessioncache-k9r3vx7m -->
**NewSessionCache** · [`plugin/jwt/cache.go:73`](../../plugin/jwt/cache.go#L73-L73)

```go
func NewSessionCache(p *Plugin) auth.SessionCache { return &sessionCache{p: p} }
```
<!-- /ds:block hash=9b4c2a -->

The same plugin signs the tokens and the cache, in [`examples/jwt-session`](../../examples/jwt-session):

<!-- ds:block id=jwtsession-newauth-v7kx3pw9 -->
**newAuth** · [`examples/jwt-session/main.go:139-150`](../../examples/jwt-session/main.go#L139-L150)

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

Every rule of the sealed cache holds: a copy is used only with the session token it was made for, only until its expiry (never past 15 minutes), the core never renews one without reading the store, and sign-out clears it. The copy is verified with the plugin's own published key by `kid`, under that key's algorithm, and anything that does not verify is a miss that falls back to the store. Its `typ` keeps it apart from access tokens: `jwt.Verifier` refuses a snapshot, and the cache refuses an access token.

The difference to weigh: the claims are signed, not encrypted. Whoever holds the cookie (or the `Set-Auth-Session-Cache` header in bearer mode) can read the session's IP address, user agent and app data, and the user's name and image. Keep the sealed `auth.NewSnapshotCache` when that matters.

Try it: in the same example, read the session once, then `sqlite3 jwt-session.db 'delete from auth_session'`: `/me` still answers from the signed copy until it expires (one minute there), sign-out clears it, and the copy sent to `/reports` as a bearer token is refused with `jwt: token is not valid: type "ubgo-auth.session-cache+jwt"` in the log.

Check: `TestSessionCacheIsASignedJWT` in the example; `TestSessionCache_PassesTheCacheContract` runs `sessiontest.RunCache` (the contract every cache passes, the core's and Redis's included) with each algorithm, and `TestJWT_SessionCacheEndToEnd` runs it over HTTP on all three engines.

## Step 14 — Tokens shaped for another service, by name

A third party (Supabase, Hasura, Convex, Firebase) wants a token in its own shape: its audience, its role claim, sometimes its own key. Register each shape on the server as a named template, and the signed-in client asks for one by name with `POST /auth/jwt/template`, Clerk's `getToken({ template })`. The client sends nothing but the name, so it can never shape a claim; a name the app did not register answers `404 jwt.unknown_template`.

<!-- ds:block id=withtemplate-c3vz9kxm -->
**WithTemplate** · [`plugin/jwt/template.go:162-173`](../../plugin/jwt/template.go#L162-L173)

```go
func WithTemplate(name string, t Template) Option {
	return func(p *Plugin) {
		if p.templates == nil {
			p.templates = map[string]Template{}
		}
		if _, dup := p.templates[name]; dup {
			p.templateErr = fmt.Errorf("jwt.WithTemplate(%q): %w: given twice", name, ErrTemplateName)
			return
		}
		p.templates[name] = t
	}
}
```
<!-- /ds:block hash=222a6d -->

A [`Template`](ds:block?id=template-n4xk7wqp) sets `Claims` (a `ClaimsFunc` from the user and the session; an error fails the call), `Subject`, `Issuer`, `Audience`, `TTL` (capped at [an hour](ds:block?id=maxttl-n53tvy7p) and at the session's expiry), `Key`, `Algs` and `Type`. The registered claims (`iss`, `sub`, `iat`, `nbf`, `exp`, `jti`, `sid`, `aud`, `act`) stay the plugin's: a template's `Claims` returning one fails the call, so a template renames nothing a receiver trusts. The key is one of three:

| Key | Signs | Published in the JWKS | For |
|---|---|---|---|
| nil, or `jwt.PublishedKey(alg, kid)` | the signing key, or an `AlgorithmKeys` key picked by algorithm or key id | yes (it already is) | a receiver that fetches your key set: Convex's `customJwt`, Hasura's `jwk_url` |
| `jwt.HMACKey(secret)` | [`HS256`](ds:block?id=hs256-t5mq8wzk) with a secret of at least [32 bytes](ds:block?id=minhmacsecret-r8kw2vnd) | never | a receiver that verifies with a shared secret: Supabase's legacy JWT secret, Hasura's `HS256` key |
| `jwt.PrivateKey(signer, kid)` | a key the receiver issued | never | Firebase custom tokens, signed with the service account key |

Prefer a published key wherever the receiver can fetch a key set: whoever holds a shared secret can mint tokens, the receiver included. An `HS256` token never passes a `jwt.Verifier`, which holds public keys only; `jwt.VerifyHS256(token, secret)` checks one for the app's own use.

The presets in `github.com/ubgo/auth/plugin/jwt/jwtpreset` are example conventions read from each vendor's documentation (the link is in each function's comment), opt-in and never a default. [`examples/jwt-templates`](../../examples/jwt-templates) registers three of them and one of its own:

<!-- ds:block id=jwttemplates-newjwt-r5mk8wqz -->
**newJWT** · [`examples/jwt-templates/main.go:159-181`](../../examples/jwt-templates/main.go#L159-L181)

```go
func newJWT(k keys, org *organization.Plugin, meta *metadata.Plugin) (*jwt.Plugin, error) {
	supabase, err := jwtpreset.Supabase(jwtpreset.SupabaseConfig{Key: jwt.HMACKey(k.supabase)})
	if err != nil {
		return nil, err
	}
	convex, err := jwtpreset.Convex(jwtpreset.ConvexConfig{ApplicationID: convexApplicationID, Alg: jwt.ES256})
	if err != nil {
		return nil, err
	}
	orgClaims, err := orgjwt.Claims(org)
	if err != nil {
		return nil, err
	}
	return jwt.New(
		jwt.WithSigningKey(k.main),
		jwt.AlgorithmKeys(k.es256),
		jwt.WithTemplate(TemplateSupabase, supabase),
		jwt.WithTemplate(TemplateHasura, jwtpreset.Hasura(jwtpreset.HasuraConfig{Audience: []string{hasuraAudience}})),
		jwt.WithTemplate(TemplateConvex, convex),
		jwt.WithTemplate(TemplateOrg, jwt.Template{Audience: []string{orgAudience}, Claims: orgClaims}),
		jwt.WithTemplate(TemplateProfile, jwt.Template{Audience: []string{profileAudience}, Claims: jwt.UserClaim(publicMetadataClaim, meta.PublicOf)}),
	), nil
}
```
<!-- /ds:block hash=06eab0 -->

| Preset | What the token carries | Key |
|---|---|---|
| `jwtpreset.Supabase(SupabaseConfig{Key, Issuer, Role, Claims})` | `aud` and `role` `authenticated` (or `Role`), `session_id`, `is_anonymous: false`; `aal`, `email` and `phone` are the app's to add through `Claims` | `HMACKey` with the project's JWT secret, or a `PrivateKey` imported into the project |
| `jwtpreset.Hasura(HasuraConfig{Key, Audience, Namespace, Roles, Claims})` | the `https://hasura.io/jwt/claims` namespace with `x-hasura-default-role`, `x-hasura-allowed-roles` (the default role is always in it) and `x-hasura-user-id` | nil (the key set, through `jwk_url`) or `HMACKey` |
| `jwtpreset.Convex(ConvexConfig{ApplicationID, Alg, Claims})` | `aud` the application id; `auth.New` fails unless the key is `RS256` or `ES256`, the only two Convex verifies | a published key; configure Convex with your issuer and `/auth/jwt/jwks` |
| `jwtpreset.Firebase(FirebaseConfig{ServiceAccountEmail, Key, KeyID, Claims})` | `iss` and `sub` the service account, `aud` the Identity Toolkit URL, `uid`, and `claims`; `RS256` only. Not exchanged against a live Firebase project here, so try one sign-in in a test project first | `PrivateKey` with the service account's RSA key |

Try it: `go run ./jwt-templates`, sign up with curl as in Step 3, then

```sh
curl -s -b c.txt -X POST localhost:8081/auth/jwt/template -H 'Origin: http://localhost:8081' -d '{"template":"supabase"}'
```

The answer is `{"token": "...", "expiresAt": "..."}`; its header is `{"alg":"HS256","typ":"JWT"}` and its payload carries `"aud":"authenticated"` and `"role":"authenticated"`. `{"template":"admin"}` answers `404` with code `jwt.unknown_template`, and signed out the route answers `401`.

Check: `TestTemplates_EachReceiverVerifies` and `TestTemplates_Refusals` in the example verify each token the way its receiver does over HTTP; `TestTemplate_KeysMatrix`, `TestTemplate_UnknownAndReservedRefused`, `TestVerifyHS256_AlgConfusion` and `TestTemplate_ValidateRefusesBadConfiguration` in the plugin; one test per preset in `jwtpreset`.

## Step 15 — The active organization in the token

With the [organization plugin](organization.md), `orgjwt.Claims(org)` from `github.com/ubgo/auth/plugin/organization/orgjwt` (it returns the claims func and an error, so a bad option stops the app at start) adds the session's active organization: `{"org": {"id", "slug", "role", "permissions"}}`, the permissions as sorted `resource:action` strings (Clerk's `o` claim; `orgjwt.ClaimName("o")` renames it, `orgjwt.WithoutPermissions()` drops the list). With no active organization, or one the caller has left, there is no claim. Put it in one template, as the example's `org` template does, or in every session token with `jwt.ClaimSource(claims)` with `claims, err := orgjwt.Claims(org)`. A failing database read fails the token call rather than minting a token without the claim. Like every claim, it is a copy for the token's lifetime: a member removed from the organization keeps it in tokens already minted until they expire.

The default permissions are the organization plugin's own roles (`organization.PermissionsOf`). An app that decides permissions elsewhere, through `organization.WithAuthorizer` backed by Casbin, OPA, Cedar or a relationship store, must not use them, since the roles say nothing about what its authorizer allows: pass its answer with `orgjwt.Permissions(func(ctx, orgID, userID, role) ([]string, error))`, or turn the list off with `orgjwt.WithoutPermissions()`. `orgjwt.Permissions(nil)` is refused: `orgjwt.Claims` returns `auth.ErrNilOption` naming it, never a func that quietly uses the role-derived list.

The user's public metadata ([plugin/metadata](metadata.md)) rides the same way: `jwt.UserClaim("public_metadata", meta.PublicOf)` as a `ClaimSource` or a template's `Claims`, as the example's `profile` template does. Only the public document belongs in a token: a JWT is signed, not encrypted.

Check: `TestTemplates_OrganizationClaim` and `TestTemplates_PublicMetadataClaim` in the example (no organization claim before an organization exists, the owner's role and permissions after; `{}` for a user with no public metadata); `TestClaims_NoOrganizationNoClaim`, `TestClaims_ReadFailuresFailTheToken` and `TestClaims_PermissionsFromTheAppsAuthorizer` in `orgjwt`; `TestUserClaim` in the plugin.

## Options you may want

| Option | Use it when |
|---|---|
| `jwt.WithTTL(d)` | Tokens should live less than 5 minutes, or up to [an hour](ds:block?id=maxttl-n53tvy7p) (the cap; a longer value becomes the cap) |
| `jwt.Issuer(iss)` | The `iss` claim should not be the base URL's origin |
| `jwt.Audience(aud...)` | Always, in practice: the receiving service refuses tokens meant for another. Several values make `aud` an array; `jwt.Verifier` accepts a token whose array contains its `Audience` |
| `jwt.Subject(fn)` | The receiving service keys users by something other than the user id, such as an external id on the user; `fn(ctx, user, session)` returns it, and an empty result fails the call |
| `jwt.Claims(fn)` | The receiver needs a role, a tenant, a display name |
| `jwt.Payload(fn)` | A claim comes from the session too (its organization, its device): `fn(ctx, user, session)`, better-auth's `definePayload`. The default payload is the user id only, never the whole user |
| `jwt.PreviousKeys(pub…)` | During a rotation by hand |
| `jwt.WithSigner(jwt.Rotating(seed, 24*time.Hour, time.Hour))` | Keys should rotate on their own, with no key storage; the grace period is at least the TTL |
| `jwt.WithSigner(yourKMS)` | The private key lives in a key management service |
| `jwt.WithSigningKey(rsaKey)` or `(ecdsaKey)` | A consumer accepts only RSA or ECDSA, such as AWS API Gateway's JWT authorizer; `jwt.RSAKey(key, jwt.PS256)` for an RSA algorithm other than `RS256` (Step 10) |
| `jwt.JWKSPath("/.well-known/jwks.json")` | The key set should be served at another path (Step 11) |
| `jwt.RemoteJWKS(url)` | The key set is published elsewhere, such as by your KMS (Step 11) |
| `jwt.IssueOnSession()` | The frontend should get a fresh token with every session read instead of calling the token route (Step 12) |
| `auth.WithSessionCache(jwt.NewSessionCache(jw), ttl)` | The session cookie cache should be a signed JWT, better-auth's `sessionCookieCache` (Step 13) |
| `jwt.NewRemoteKeys(url, nil)` as `Verifier.Lookup` | The receiving service should pick up rotated keys without a deploy |
| `Verifier.Leeway` | The services' clocks drift more than [30 seconds](ds:block?id=defaultleeway-sq3t3z4e) |
| `jw.Sign(ctx, jwt.SignRequest{…})` | A token for a job, a service or a receiver that is tied to no session (Step 9) |
| `jwt.WithTemplate(name, t)` | A client needs a token shaped for a third party, asked for by name (Step 14) |
| `jwt.ClaimSource(fn)` | A claim comes from a lookup that can fail, such as `orgjwt.Claims(org)` (Step 15) |

<!-- ds:block id=withttl-ddzbqhwd -->
**WithTTL** · [`plugin/jwt/jwt.go:214`](../../plugin/jwt/jwt.go#L214-L214)

```go
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }
```
<!-- /ds:block hash=1a31a6 -->

<!-- ds:block id=issuer-mcvvmqgb -->
**Issuer** · [`plugin/jwt/jwt.go:178`](../../plugin/jwt/jwt.go#L178-L178)

```go
func Issuer(iss string) Option { return func(p *Plugin) { p.issuer = iss } }
```
<!-- /ds:block hash=07f38f -->

## Combining with other plugins

- [Admin](admin.md): a token minted in an impersonation session carries `act: {"sub": "<admin id>"}`, so the receiving service can tell and refuse. `Verified.Actor` is the admin's id.
- [API keys](apikey.md): a key cannot mint a token; the token route is an `/auth` operation.
- [Two-factor](twofactor.md): a session pending its second factor is signed out as far as the token route is concerned.

## From TypeScript

Use this when a browser or app calls another service of yours that checks a JWT instead of the session. The [typed client](../client/README.md) has the two routes as `client.jwt.token` and `client.jwt.jwks`; list `jwt()` in `plugins`. The page asks for a token with its session, keeps it until shortly before `expiresAt`, and sends it to the other service as `Authorization: Bearer`:

<!-- ds:block id=tsp-jwt-token-4xq9mw3k -->
**cached** · [`clients/ts/examples/plugin-account.ts:88`](../../clients/ts/examples/plugin-account.ts#L88-L88)

```typescript
null
```
<!-- /ds:block hash=74234e -->

`jwt.jwks` answers the public keys, for a service written in TypeScript that verifies the token itself; it is public and needs no session (Step 4).

The code a frontend handles: `auth.signed_out` from `token` when there is no session (sign in first). More in [What can go wrong](#what-can-go-wrong).

There is no runnable TypeScript example for the JWT plugin; the block is type-checked by `task ts:check`, and Steps 3 and 4 show the same calls with curl.

Pitfalls:

- **A token outlives a sign-out until it expires.** That is why it is short-lived (five minutes by default); never cache it longer than `expiresAt`, and fetch a new one after the user signs in as someone else.
- **Do not send the JWT to the auth routes.** They use the session cookie or bearer session token; the JWT is for the other service only.

Every method with its route and types: [TypeScript client reference › jwt](../reference/ts-client.md#jwt).

## What can go wrong

- `401 auth.signed_out` on `/auth/jwt/token` — no session, or one pending a second factor.
- `403 auth.api_key_refused` — an API key asked for a token.
- `500` with code `auth.internal` and `jwt: Subject returned an empty subject` in the log — `jwt.Subject`'s function returned ""; an app bug. The same error from `Sign` means the `SignRequest` had no `Subject`.
- `500` with code `auth.internal` — `Claims` returned a reserved claim (`jwt: Claims may not set a registered claim`) or a value with no JSON form; both are app bugs and are logged.
- `jwt: token is not valid: …` in the receiving service — `expired`, `not yet valid`, `signature`, `unknown key "…"` (rotate the cached key set), `algorithm "…"` (not `EdDSA`, `RS256` or `ES256`, or not the algorithm of the key the `kid` names), `type "…"` (not a `JWT`: a session-cache snapshot, Step 13), `issuer "…"` or `audience "…"` (the verifier's settings do not match the issuing app).
- A token still works after the session was revoked — expected, for at most the TTL. Keep the TTL short; that is the revocation.
- `auth.New` fails with "jwt: pass jwt.WithSigningKey with an Ed25519, RSA or P-256 private key, or jwt.WithSigner" — the key is missing or an Ed25519 key is not 64 bytes (`ed25519.PrivateKey`), for example a seed passed as is: build it with `ed25519.NewKeyFromSeed`.
- `auth.New` fails with `jwt.ErrUnsupportedKey` — an RSA key under 2048 bits, an ECDSA key on another curve than P-256, or such a key in `PreviousKeys` or a `Signer`'s list.
- `auth.New` fails with `jwt.ErrJWKSPath` or `jwt.ErrRemoteJWKS` — see Step 11.
- `404 jwt.unknown_template` from `/auth/jwt/template` — the name is not one the app registered with `jwt.WithTemplate`; names are case-sensitive.
- `auth.New` fails with `jwt.ErrTemplateName`, `jwt.ErrHMACSecret` or `jwt.ErrTemplateKey` — a template name outside `a-z0-9-_` or given twice, an HMAC secret under 32 bytes, or a key that cannot sign for the template (no such published key, or an algorithm its receiver does not accept, such as `EdDSA` for Convex); see Step 14.
- `500` with `jwt: the Signer's signature does not verify with its published key` — a KMS `Signer` signed with another key or returned the wrong encoding.
- `auth.New` fails with "jwt: Rotating needs a 32-byte seed", "…interval is at least an hour" or "…grace period is at least the token TTL" — the rotation parameters.
- `500` with `jwt: Signer has no published key to sign with` in the log — a custom `Signer` returned no public keys.
- `jwt: remote key set could not be read` from `RemoteKeys.LastError` — the key-set URL is wrong, unreachable, or not JSON; the keys already fetched stay in use.

## Next

- [Other services](../integrations/other-services.md): verifying in Go, Python and anything else.
- [API keys](apikey.md): when the caller is a script, not a service.
- Reference: [plugin/jwt/README.md](../../plugin/jwt/README.md), [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/jwt).

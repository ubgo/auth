# github.com/ubgo/auth/plugin/jwt

Issues short-lived JSON Web Tokens from a signed-in session, so another service can tell who is calling by checking a signature against the app's published public keys, without access to the auth database.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module `github.com/ubgo/auth` and adds no dependency: signing is Ed25519 (`EdDSA`, the default), RSA (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`) or ECDSA (`ES256`, `ES384`, `ES512`) from the standard library, key rotation derives keys with `crypto/hkdf`, and the verifier needs no JWT library.

## Wire it

From [examples/api-keys-and-jwt](../../examples/api-keys-and-jwt/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		jwt.New(jwt.WithSigningKey(key), jwt.Audience("reports"), jwt.Claims(nameClaim)),
	),
)
```

`key` is an `ed25519.PrivateKey`; in production load it from your secret store (the example reads a 32-byte seed from `JWT_SIGNING_KEY` and calls `ed25519.NewKeyFromSeed`). The key chooses the algorithm: an `*rsa.PrivateKey` of at least [`MinRSABits`](ds:block?id=minrsabits-q8w2nd5k) (2048) signs `RS256` (or, bound by `RSAKey(key, alg)`, `RS384`, `RS512`, `PS256`, `PS384` or `PS512`), an `*ecdsa.PrivateKey` the algorithm of its curve (P-256 `ES256`, P-384 `ES384`, P-521 `ES512`), and any `crypto.Signer` of those types works, a KMS client included; [`GenerateKey(alg)`](ds:block?id=generatekey-m4ps8tvx) makes one. The plugin needs a sign-in method (any plugin such as `password`) because a token is minted from a session.

`auth.New` fails when:

| Condition | Error |
|---|---|
| No key, or an Ed25519 key that is not `ed25519.PrivateKeySize` bytes, and no `WithSigner` | `ErrNoKey`: "jwt: pass jwt.WithSigningKey with an Ed25519, RSA or P-256 private key, or jwt.WithSigner" |
| A signing key, a `PreviousKeys` key or a `Signer` key that is not Ed25519, RSA of at least 2048 bits, or ECDSA on P-256 (a P-256 point off the curve included) | `ErrUnsupportedKey` |
| A `JWKSPath` that does not start with `/`, is `/` alone, holds `..`, `//` or a character outside `A-Za-z0-9-._~/`, or is `/token` or `/template` | `ErrJWKSPath` |
| A `WithTemplate` name that is empty, over 64 characters, holds a character outside `a-z0-9-_`, or is given twice | `ErrTemplateName` |
| A template `HMACKey` secret under [`MinHMACSecret`](ds:block?id=minhmacsecret-r8kw2vnd) (32) bytes | `ErrHMACSecret` |
| A template key that cannot sign for it: a `PublishedKey` naming no key (`ErrNoAlgorithmKey`, `ErrNoSigningKey`), a nil or unsupported `PrivateKey` or one with a key id outside `A-Za-z0-9-_.`, or a key whose algorithm is not in the template's `Algs` | `ErrTemplateKey` |
| A `RemoteJWKS` URL that is not absolute `https` (`http` only for a loopback host), or has a fragment or user information | `ErrRemoteJWKS` |
| `Rotating` with a seed that is not [`RotationSeedSize`](ds:block?id=rotationseedsize-f4wq9bkm) (32) bytes, an interval below [`MinRotationInterval`](ds:block?id=minrotationinterval-h7zt2vcp) (an hour), or a grace period below the TTL | `ErrRotationSeed`, `ErrRotationInterval`, `ErrRotationGrace` |
| Neither `auth.WithBaseURL` nor `jwt.Issuer` is set | `ErrNoIssuer`: "jwt: needs auth.WithBaseURL or jwt.Issuer" |

On the receiving side:

```go
v := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: "reports"}
claims, err := v.Verify(token) // every failure is jwt.ErrInvalid
```

A `Verifier` accepts the `typ` `JWT` only; `Types: []string{"at+jwt"}` accepts the OAuth provider's access tokens instead (an entry outside letters, digits and `+-.`, or the session-cache type, is `ErrBadType`).

## Options

| Option | What it does | Default |
|---|---|---|
| `WithSigningKey(k crypto.Signer)` | The key that signs new tokens, and so the algorithm: `ed25519.PrivateKey` (`EdDSA`), `*rsa.PrivateKey` (`RS256`), an `RSAKey` (its algorithm), `*ecdsa.PrivateKey` on P-256, P-384 or P-521 (`ES256`, `ES384`, `ES512`), or a KMS `crypto.Signer` of one of those | none (one of the two is required) |
| `Payload(fn PayloadFunc)` | App claims from the user and the session, better-auth's `definePayload`; added after `Claims`', and a registered claim fails the call like there | none |
| `WithSigner(s Signer)` | A signer in place of the key: `Rotating`, or your own for a KMS or HSM; `PublicKeys` lists the keys to publish (the signing key first) and `Sign` signs with the key the header named | none |
| `Rotating(seed []byte, interval, grace time.Duration)` | A `Signer` whose Ed25519 key changes every `interval`, derived from the seed with HKDF-SHA256 per period, so every instance derives the same key with no storage; the key set publishes the keys of the periods that ended within `grace` | none |
| [`AlgorithmKeys(keys ...crypto.Signer)`](ds:block?id=algorithmkeys-h7tn2xqc) | Signing keys of other algorithms beside the signing key (better-auth's `keyPairConfigs`): `Sign` with `SignRequest.Alg` set to one of them signs with the first key of it, `SignRequest.KeyID` picks one by key id (`ErrNoSigningKey` otherwise), and each is published in the key set; several may share an algorithm, but one key given twice is `ErrAlgorithmKeys`. The session token route keeps the signing key | none |
| `PreviousKeys(keys ...crypto.PublicKey)` | Keeps publishing old public keys after a rotation, so tokens signed just before it verify until they expire; a key may be of another algorithm than the signing key, which is how a deployment moves from `EdDSA` to `RS256` | none |
| `Issuer(iss string)` | The `iss` claim | the origin of `auth.WithBaseURL` |
| `Audience(aud ...string)` | The `aud` claim: the service, or services, the tokens are for; one value is a string, several an array (RFC 7519 4.1.3), and `Verifier` accepts either | no `aud` claim |
| `Subject(fn SubjectFunc)` | Replaces the `sub` claim (the user id) with what `fn(ctx, user, session)` returns; an empty result fails the call with `ErrEmptySubject` | `sub` is the user id |
| `WithTTL(d time.Duration)` | Token lifetime; a value that is not positive or exceeds [`MaxTTL`](ds:block?id=maxttl-n53tvy7p) (1 hour) becomes [`MaxTTL`](ds:block?id=maxttl-n53tvy7p) | [`DefaultTTL`](ds:block?id=defaultttl-kqd34f84) (5 minutes) |
| `Claims(fn func(ctx context.Context, u auth.User) map[string]any)` | Adds app claims such as a role or tenant | none |
| [`ClaimSource(fn ClaimsFunc)`](ds:block?id=claimsource-p9wd3mxk) | App claims whose lookup can fail (a database read, such as `orgjwt.Claims`): added after `Payload`'s, and an error or a registered claim fails the token call rather than minting a token without the claim | none |
| [`UserClaim(name, read)`](ds:block?id=userclaim-x6vq3nzr) | A `ClaimsFunc` writing one claim from a per-user JSON document, such as plugin/metadata's public document: `ClaimSource(UserClaim("public_metadata", meta.PublicOf))`. A failing read or invalid JSON fails the call. Never pass private metadata: a JWT is signed, not encrypted | none |
| [`WithTemplate(name string, t Template)`](ds:block?id=withtemplate-c3vz9kxm) | Registers a named token template a signed-in client asks for with `POST /jwt/template` (Clerk's `getToken({ template })`); see Templates below | none |
| [`JWKSPath(path string)`](ds:block?id=jwkspath-c7n4wq8z) | Serves the key set at `/jwt<path>` under the mount prefix instead of [`DefaultJWKSPath`](ds:block?id=defaultjwkspath-t3vk9q2w); the old path answers 404 (better-auth's `jwks.jwksPath`) | `/jwks` |
| [`RemoteJWKS(url string)`](ds:block?id=remotejwks-r2k8vm5d) | The key set is published at `url` (a KMS's JWKS endpoint, a CDN): the local key-set route is not served (404), and `JWKSURL()` returns `url` for the app to configure in its verifiers. No token carries the URL (no `jku`), because a verifier that followed a URL named by the token would let the token choose its keys (better-auth's `jwks.remoteUrl`, which it advertises only in OpenID discovery) | the plugin serves its keys |
| [`IssueOnSession()`](ds:block?id=issueonsession-h5q9wz3b) | The session read (`GET /session`, `Auth.Session`) also mints a token and sends it in the [`Set-Auth-JWT`](ds:block?id=setjwtheader-p6xr2m4c) header, listed in `Access-Control-Expose-Headers` (better-auth's `set-auth-jwt`); the token is the one `POST /jwt/token` returns at that instant, none when signed out, and a minting failure fails the read. A Go caller reads it with `SessionJWT(ctx)` | off |

`Verifier` fields: `Keys` (key id to `crypto.PublicKey`; the token's `alg` must be the algorithm of the key its `kid` names, so the header never chooses), `Lookup` (a function tried for a `kid` that `Keys` lacks; `RemoteKeys.Lookup` fetches the issuer's JWKS), `Issuer` and `Audience` (checked when not empty), `Leeway` (default [`DefaultLeeway`](ds:block?id=defaultleeway-sq3t3z4e), 30 seconds), `Now` (default `time.Now`). `Verified` carries `Subject`, `SessionID`, `Actor`, `ExpiresAt` (always UTC) and `Extra` (every app claim, raw JSON). [`NewRemoteKeys(url, hc)`](ds:block?id=newremotekeys-y8pk2vrc) (a nil client gets one with [`DefaultRemoteTimeout`](ds:block?id=defaultremotetimeout-w3jq8mdf), 10 seconds) fetches and caches a key set, refetching for an unknown `kid` at most once per [`RemoteMinRefresh`](ds:block?id=remoteminrefresh-c6vw2kzp) (a minute) and whenever the set is older than [`RemoteMaxAge`](ds:block?id=remotemaxage-t9hr4nxb) (a day); a failed fetch keeps the keys already held and is reported by `LastError`.

## Routes and Go API

Paths are under the mount prefix (`/auth` in the example). A Query is served as GET, a Mutation as POST.

| Route | Go API | Requirement | Rate limit |
|---|---|---|---|
| `POST /jwt/token` | `(*Plugin).Token(ctx) (TokenResult, error)` | SignedIn (an API key is refused with `auth.ErrAPIKeyRefused`) | none |
| `POST /jwt/template` `{"template": "<name>"}` | [`(*Plugin).TemplateToken(ctx, name)`](ds:block?id=plugin-templatetoken-g6rn4wvz) `(TokenResult, error)`; `(*Plugin).TemplateNames()` lists the names | SignedIn (an API key is refused like the token route); an unregistered name is `ErrUnknownTemplate` | none |
| `GET /jwt/jwks` (`/jwt` + the `JWKSPath`; not served under `RemoteJWKS`) | `(*Plugin).PublicKeys() JWKS` | Public | none |
| Go only | [`(*Plugin).Sign(ctx, SignRequest)`](ds:block?id=plugin-sign-x4wq9tkn): a token for a subject the app names, with its own audience, TTL (capped at `MaxTTL`) and claims, under the plugin's key and issuer; `SessionID` sets `sid` and `Type` the `typ` header (default `JWT`; an OAuth access token uses `at+jwt`, and the session-cache type is refused, `ErrBadType`), `Alg` and `KeyID` pick the signing key, and the `Subject` and `Claims` options do not apply. For trusted code only: a service token, a webhook receiver, a user the app looked up itself | none (app code) | none |
| Go only | `jwt.Verifier.Verify(token)`, `jwt.KeysFromJWKS(set)`, `jwt.KeyID(pub)`, `jwt.AlgOf(pub)`, `jwt.HashOf(alg)`, `jwt.GenerateKey(alg)`, `jwt.RSAKey(key, alg)`, `jwt.PublicKeyForAlg(jwk, alg)`, `jwt.NewRemoteKeys(url, hc).Lookup` | none | none |
| Go only | `(*Plugin).JWKSURL()` (the `RemoteJWKS` URL or ""), `(*Plugin).JWKSRoute()` (the key-set route under the mount, "" under `RemoteJWKS`), `jwt.SessionJWT(ctx)` (the `IssueOnSession` token of the request) | none | none |
| Go only | [`jwt.NewSessionCache(p)`](ds:block?id=newsessioncache-k9r3vx7m): an `auth.SessionCache` for `auth.WithSessionCache` whose client copy is a JWT signed with the plugin's key (below) | none | none |

`TokenResult` is `{"token", "expiresAt"}`. Claims written: `iss`, `sub` (user id), `iat`, `nbf`, `exp`, `jti` (random, 128 bits), `sid` (session id), `aud` when set, and `act: {"sub": <admin id>}` when the session is an impersonation. The header is `{"alg":"EdDSA","typ":"JWT","kid":...}` (the key's algorithm for an RSA or ECDSA key; [`DefaultAlgorithm`](ds:block?id=algorithm-j38g35tv) is `EdDSA`), where `kid` is `KeyID(pub)`: the first 16 base64url characters of the SHA-256 of the raw Ed25519 key, or of an RSA or ECDSA key's PKIX encoding (followed by the algorithm for an `RSAKey`, so one modulus under two algorithms has two ids). The key set uses `use` [`KeyUseSignature`](ds:block?id=keyusesignature-azygjgrb), `alg` the key's algorithm, and per key type: `kty` [`KeyTypeOKP`](ds:block?id=keytypeokp-cx2p5h5q) with `crv` [`CurveEd25519`](ds:block?id=curveed25519-w6kd4wru) and `x`; `kty RSA` with `n` and `e`; `kty EC` with `crv` (`P-256`, `P-384`, `P-521`), `x` and `y`. An ECDSA signature is the fixed `r||s` JWS requires (64, 96 or 132 bytes), converted from the ASN.1 a `crypto.Signer` returns.

### Templates

[`Template`](ds:block?id=template-n4xk7wqp) is a token shape the app registers by name, for a third party that wants its own claims (Clerk's JWT templates). The client sends only the name; the claims, audience, issuer, subject, lifetime and key are server configuration, so a client can never shape a claim. Fields: `Claims` (a `ClaimsFunc`; an error fails the call), `Subject` (else the plugin's `Subject`, else the user id), `Issuer` (else the plugin's), `Audience` (nil writes none), `TTL` (0 is the plugin's, capped at `MaxTTL` and at the session's expiry), `Key`, `Algs` (the algorithms the receiver accepts; `auth.New` fails with `ErrTemplateKey` when `Key` signs another) and `Type` (the `typ` header). The registered claims stay the plugin's: `iss`, `sub`, `iat`, `nbf`, `exp`, `jti`, `sid`, `aud` and `act` are always written by the plugin, and a template's `Claims` returning one fails the call with `ErrReservedClaim`. The plugin's `Claims`, `Payload` and `ClaimSource` options do not apply to a template.

`Key` is one of three, a closed set: nil or `PublishedKey(alg, kid)` signs with the signing key or an `AlgorithmKeys` key (chosen like `SignRequest`), already in the key set, for a receiver that fetches the JWKS (Convex's `customJwt`, Hasura's `jwk_url`); `HMACKey(secret)` signs [`HS256`](ds:block?id=hs256-t5mq8wzk) with a secret shared with one receiver (Supabase's legacy JWT secret, Hasura's `HS256` key), at least 32 bytes, never published, and refused by every `Verifier` (`VerifyHS256(token, secret)` checks one for the app's own use, pinning `alg` to `HS256` and comparing in constant time); `PrivateKey(signer, kid)` signs with a key the receiver issued (a Firebase service account key), never published, `kid` written as given or left out when "".

Presets live in `github.com/ubgo/auth/plugin/jwt/jwtpreset`, each an example convention, opt-in, never a default, with the vendor's documentation cited in its comment: `Supabase(SupabaseConfig)` (aud and `role` `authenticated`, `session_id`, `is_anonymous`), `Hasura(HasuraConfig)` (the `https://hasura.io/jwt/claims` namespace with `x-hasura-default-role`, `x-hasura-allowed-roles`, `x-hasura-user-id`), `Convex(ConvexConfig)` (aud the application id, `Algs` RS256 and ES256) and `Firebase(FirebaseConfig)` (a custom token: RS256 with the service account key, `iss` and `sub` the service account, aud the Identity Toolkit URL, `uid`, `claims`; not exchanged against a live Firebase project here). `github.com/ubgo/auth/plugin/organization/orgjwt` adds the active organization (`id`, `slug`, `role`, `permissions`) as a `ClaimsFunc`; the permissions come from the organization plugin's roles unless `orgjwt.Permissions(fn)` supplies them (an app whose `organization.WithAuthorizer` is Casbin, OPA or similar must, or drop them with `orgjwt.WithoutPermissions()`).

### JWT session cache

`auth.WithSessionCache(jwt.NewSessionCache(jw), ttl)` with `jw` in `auth.WithPlugins` is better-auth's `sessionCookieCache`: the cache copy the client holds (the cache cookie, or `Set-Auth-Session-Cache` in bearer mode) is a JWT signed with the plugin's key. Header: `typ` [`SessionCacheType`](ds:block?id=sessioncachetype-w8d3kq6n) (`ubgo-auth.session-cache+jwt`), `alg`, `kid`. Claims: `iss` (the plugin's issuer), `aud` [`SessionCacheAudience`](ds:block?id=sessioncacheaudience-v4m7zt2h) (`ubgo-auth:session-cache`), `sub` (user id), `sid` (session id, not the token as better-auth writes), `iat`, `exp` (the entry's expiry, whole seconds rounded down), `tbh` (a SHA-256 of the session token's hash under a fixed label), `session` and `user`. It keeps every rule of the sealed `auth.NewSnapshotCache`, which stays the default: used only with its token (constant-time compare of `tbh`), only before `exp`, never past `auth.MaxSessionCacheTTL`, never renewed without the store, cleared at sign-out. `Get` verifies with the plugin's own published key named by `kid`, under that key's algorithm, refuses another `typ`, issuer or audience and a `sub`/`sid` that disagree with the user and session carried; every failure is a miss. **The claims are signed, not encrypted**: whoever holds the value reads the session's IP, user agent and app data and the user's name and image. A cache whose plugin is not in `auth.WithPlugins` fails every `Put` with `ErrCacheNotWired`. It passes `sessiontest.RunCache`, as the core caches and contrib/redis do.

## Tables and columns

None. The plugin is stateless: tokens are never stored, and the keys come from options; `Rotating` derives its keys from the seed on every call rather than storing them.

## Errors

| Variable | Code | HTTP | When |
|---|---|---|---|
| `ErrReservedClaim` | none; answered over HTTP as `auth.internal` | 500 | `Claims` returned a claim the plugin owns (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid`, `act`); an app bug |
| `ErrInvalid` | none | none | Returned by `Verifier.Verify` for every untrusted token, wrapped with the reason for the log |
| `ErrEmptySubject` | none; answered over HTTP as `auth.internal` | 500 | `Subject` returned an empty string, or `Sign` was given none; an app bug |
| `ErrSignerKey` | none; answered over HTTP as `auth.internal` | 500 | A `Signer` published no key, or `Rotating` was asked to sign with a key outside its grace |
| `ErrRemoteKeys` | none | none | `RemoteKeys.LastError`: the key set could not be fetched or was not a key set |
| `ErrSignature` | none; answered over HTTP as `auth.internal` | 500 | A `Signer`'s signature did not verify with the key it published (a KMS that used another key or returned ASN.1 for ECDSA); no token is minted |
| `ErrCacheNotWired` | none | 500 through the core's `auth: session cache:` | `NewSessionCache`'s plugin is not in `auth.WithPlugins` |
| `ErrUnsupportedKey`, `ErrJWKSPath`, `ErrRemoteJWKS` | none | none | Configuration, returned by `auth.New` (`ErrUnsupportedKey` also by `GenerateKey` for an unknown algorithm) |
| `ErrNoAlgorithmKey` | none | none | `Sign` with a `SignRequest.Alg` that neither the signing key nor an `AlgorithmKeys` key signs; the message names the algorithm |
| `ErrNoKey`, `ErrNoIssuer`, `ErrRotationSeed`, `ErrRotationInterval`, `ErrRotationGrace`, `ErrAlgorithmKeys` | none | none | Configuration, returned by `auth.New` |
| `ErrUnknownTemplate` | `jwt.unknown_template` | 404 | `POST /jwt/template` named a template the app did not register |
| `ErrTemplateName`, `ErrHMACSecret`, `ErrTemplateKey` | none | none | Template configuration, returned by `auth.New` |

A claim with no JSON form (NaN, a channel, a func) also fails `Token` with "jwt: encode claims: ...". A caller without a session gets the core's `auth.ErrSignedOut`.

## Security notes

| Property | Pinned by |
|---|---|
| `alg: none`, a tampered body, a wrong key, issuer or audience, and an expired token are all `ErrInvalid` | `TestSignVerifyAndRejections` |
| Each of the ten algorithms signs, publishes the right `kty`/`crv`/`alg` and fields, and verifies from the JSON key set; ECDSA signatures are `r||s` of the curve's size | `TestAlgorithms_EachSignsPublishesAndVerifies` |
| `RSAKey` binds a modulus to one algorithm with its own key id; `PublicKeyForAlg` reads an alg-less foreign JWK within its family only | `TestRSAKey_BindsOneModulusToOneAlgorithm`, `TestPublicKeyForAlg` |
| `Payload` sees the session, follows `Claims`, and cannot set a registered claim | `TestPayload_ClaimsFromUserAndSession` |
| The token's `alg` must be the algorithm of the key its `kid` names: `none`, `HS256`, `PS256`, `ES384` and every cross-algorithm header are refused even with a valid signature | `TestVerify_PinsTheAlgorithmToTheKey` |
| `typ` must be `JWT`, so a session-cache snapshot is never an access token, and the cache refuses an access token | `TestVerify_RequiresTheJWTType`, `TestSessionCache_SnapshotsAndAccessTokensNeverStandInForEachOther` |
| RSA under 2048 bits and curves other than P-256, P-384 and P-521 are refused at `auth.New`, in key sets and in verification; an off-curve EC point in a key set is dropped | `TestAlgOf_RefusesUnsupportedKeys`, `TestValidate_RefusesUnsupportedKeys`, `TestKeysFromJWKS_RSAAndECKeys` |
| A KMS signature that does not verify with its published key mints nothing | `TestSignWithKey_RefusesWhatASignerGetsWrong` |
| An Ed25519 `kid` is unchanged by the multi-algorithm work, so tokens in flight keep verifying | `TestKeyID_Ed25519IsUnchangedAndOthersHashTheirPKIX` |
| A template is an allowlist: an unknown name is refused, a template's claims cannot set a registered claim, a failing `ClaimsFunc` mints nothing, the subject and lifetime rules hold, and an impersonation carries `act` | `TestTemplate_UnknownAndReservedRefused`, `TestClaimsFunc_ErrorsFailTheCall`, `TestTemplate_SubjectTTLAndSession` |
| Each template key signs a token its receiver verifies; an HMAC secret or a `PrivateKey` is never in the key set, and their tokens never verify through it | `TestTemplate_KeysMatrix`, `TestTemplates_EachReceiverVerifies` (example) |
| An `HS256` token never passes a `Verifier` (not with a published `kid`, not MACed with the public key's bytes), an asymmetric token never passes `VerifyHS256`, and a short secret verifies nothing | `TestVerifyHS256_AlgConfusion` |
| A misconfigured template (name, short secret, unknown key, an algorithm the receiver refuses) fails `auth.New` | `TestTemplate_ValidateRefusesBadConfiguration`, `TestConvex_AlgorithmAndAudience`, `TestFirebase_ClaimShape` |
| `JWKSPath` moves the route and refuses `..`, `//`, `/token`, `/template` and escapes; `RemoteJWKS` turns the route off (404), needs https, and no token carries `jku` | `TestJWKSPath_MovesTheRoute`, `TestJWKSPath_RefusesWhatIsNotARoute`, `TestRemoteJWKS_TurnsTheRouteOffAndPublishesTheURL`, `TestRemoteJWKS_NeedsAnHTTPSURL` |
| `IssueOnSession` puts the token route's token in `Set-Auth-JWT`, exposed through CORS; none when signed out or off; on all three engines | `TestIssueOnSession_HookMintsTheTokenRouteToken`, `TestJWT_IssueOnSessionHeader` (integration) |
| The JWT session cache passes the cache contract with every algorithm and `Rotating`, refuses a snapshot that disagrees with its issuer, audience, user or session, one under a key no longer published, and never outlives `MaxSessionCacheTTL` | `TestSessionCache_PassesTheCacheContract`, `TestSessionCache_RefusesASignedSnapshotThatDisagrees`, `TestSessionCache_OnlyThePluginsPublishedKeysVerify`, `TestSessionCache_NeverPastMaxSessionCacheTTL`, `TestJWT_SessionCacheEndToEnd` (integration) |
| Malformed segments, a non-object payload, a claim of the wrong type, a missing `sub` or `exp`, and a future `nbf` beyond the leeway are refused | `TestVerify_RefusesMalformedTokens` |
| `KeysFromJWKS` keeps only Ed25519 keys of the right length, and RSA and ECDSA keys whose `alg` matches | `TestKeysFromJWKS_KeepsOnlySupportedSigningKeys`, `TestKeysFromJWKS_RSAAndECKeys` |
| A token signed before a rotation still verifies through `PreviousKeys` | `TestRotation_PreviousKeysStillVerify` |
| `Sign` picks the `AlgorithmKeys` key of the asked algorithm, every one is published and verifies by `kid`, and an algorithm with no key is refused | `TestAlgorithmKeys`, `TestAlgorithmKeys_Validate` |
| `SignRequest.KeyID` picks one of several keys of an algorithm, and refuses an unknown key id or one of another algorithm | `TestSign_KeyIDPicksAmongKeysOfOneAlgorithm` |
| A token never outlives the session it came from; app claims cannot overwrite registered ones | `TestTokensJWT_ClaimsLifetimeAndKeySet` |
| An impersonation token names the admin in `act` | `TestJWT_IssueFromSessionAndVerifyElsewhere` |
| The TTL is capped at [`MaxTTL`](ds:block?id=maxttl-n53tvy7p) | `TestNew_OptionsAndTTLClamp` |
| A `Sign` token verifies with the plugin's key set, carries no `sid`, takes its own audience over the plugin's, is capped at `MaxTTL`, and refuses a reserved claim or an empty subject | `TestSign_MintsATokenWithoutASession` |
| `Verified.ExpiresAt` is UTC whatever the verifying machine's time zone | `TestVerify_ExpiresAtIsUTC` |
| A custom signer's token carries the published key's id and verifies against the key set; a signer with no key fails the call | `TestSigner_CustomSignerSignsAndIsChecked` |
| Two instances derive the same rotating key; the previous key is published within grace and dropped after; a token from a retired key is refused | `TestRotating_DerivesTheSameKeysEverywhereAndPublishesWithinGrace` |
| A remote key set is refetched for an unknown `kid` at most once a minute, and a failed fetch keeps the old keys | `TestRemoteKeys_FetchesCachesAndBoundsRefresh` |

Limits, honestly: a signed token cannot be revoked; its short life is its revocation, so a revoked session stays usable through its JWTs until they expire (at most the TTL). `Verify` does not track `jti`, so it does not stop replay within a token's lifetime. `Issuer` and `Audience` are checked only when set on the `Verifier`. A verifying service must refetch the key set when it meets an unknown `kid` after a rotation, which `RemoteKeys` does. `Rotating` protects against nothing a leaked seed allows: whoever holds the seed derives every key, past and future, as with a stored private key; it buys a bounded lifetime per key and a schedule nobody has to run. `Rotating` derives Ed25519 keys only; RSA and ECDSA keys rotate by hand (`WithSigningKey` with the new key, `PreviousKeys` with the old). No key set and no `Verifier` has an HMAC (`HS*`) algorithm: a key set is public, and a shared secret in one is a forgery waiting to happen; `HS256` exists only for a template's `HMACKey`, whose secret is shared with that one receiver, who can therefore mint tokens too. With `RemoteJWKS`, keeping the remote key set in step with the `Signer` is the app's job; the plugin cannot check it. `IssueOnSession` hands a bearer token to every page that reads the session, which is why it is off by default. The JWT session cache's claims are readable by whoever holds the cookie.

## Example

- [examples/api-keys-and-jwt](../../examples/api-keys-and-jwt/): mints a JWT from a session and verifies it in a second service that fetches `/auth/jwt/jwks`.
- [examples/jwt-templates](../../examples/jwt-templates/): Supabase, Hasura, Convex and organization templates, each verified the way its receiver verifies it.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/jwt

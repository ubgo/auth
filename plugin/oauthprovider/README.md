# github.com/ubgo/auth/plugin/oauthprovider

Makes the app an OAuth 2.1 authorization server and OpenID Connect provider. Other applications send their users here to sign in, and they get back an authorization code, then access and refresh tokens and an ID token. It is opt-in, and it is its own module.

## Install

```sh
go get github.com/ubgo/auth/plugin/oauthprovider
```

It depends on the core module and sqlb only. ID tokens are signed by the core module's `plugin/jwt`, whose keys are published at `<issuer>/oauth2/jwks`.

## Wire it

```go
jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer("https://auth.example.com"))
op := oauthprovider.New(jw,
	oauthprovider.Issuer("https://auth.example.com"),
	oauthprovider.LoginPage("/login"),
	oauthprovider.ConsentPage("/consent"),
)
a, err := auth.New(auth.WithDB(db, sqlb.PostgresDialect{}), auth.WithBaseURL("https://auth.example.com"),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), jw, op))

mux.Handle("/auth/", authhttp.Handler(a, authhttp.Prefix("/auth"))) // consent, client registry, consents
mux.Handle("/.well-known/", op.Handler())                           // discovery
mux.Handle("/oauth2/", op.Handler())                                // authorize, token, userinfo, ...
```

List `jw` before `op`. The jwt plugin's `Issuer` must be the provider's `Issuer`; `auth.New` signs a probe token and refuses a mismatch (`ErrIssuerMatch`).

`New` takes a `Signer`: `Sign(ctx, jwt.SignRequest) (jwt.TokenResult, error)` and `PublicKeys() jwt.JWKS`. `*jwt.Plugin` satisfies it and is the default; a KMS, an HSM or a key service the app already runs can stand in. A signer that is a plugin is required by name (`Requires`) and must be listed before the provider; one that is not a plugin needs no registration, so the jwt plugin's token route is not mounted. The issuer probe runs for every signer. A custom signer keeps the jwt plugin's contract: `iss` is the issuer, the claims are `sub`, `aud`, `iat`, `exp` plus the request's, `typ` is the request's `Type` (`JWT` when empty), the header's `kid` names a key `PublicKeys` lists, and the first listed key's `alg` is the ID tokens' (it decides the `at_hash` hash). Register clients from Go with `op.CreateClient`, or let users register their own (see below).

## Endpoints

`Handler` serves the protocol endpoints at their paths under the issuer, in the wire format the RFCs fix. Each one is a self-served operation (`auth.OpInfo.SelfServed`), so it runs the full pipeline, with rate limits, hooks and tracing. No other transport mounts it.

| Path | Method | What |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery; 404 when `openid` is not a supported scope |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 metadata |
| `/oauth2/authorize` | GET, POST | Authorization endpoint: `response_type=code` only, PKCE S256 |
| `/oauth2/token` | POST (form) | `authorization_code`, `refresh_token`, `client_credentials` |
| `/oauth2/userinfo` | GET, POST | OIDC UserInfo; token in `Authorization: Bearer` or the form, never both |
| `/oauth2/introspect` | POST (form) | RFC 7662; a confidential client sees its own tokens, a client made with `IntrospectAny` sees every client's |
| `/oauth2/revoke` | POST (form) | RFC 7009; a refresh token revokes its whole family |
| `/oauth2/end-session` | GET, POST | OpenID Connect RP-initiated logout: a valid `id_token_hint` for the browser's user ends the session at once; otherwise a browser gets a confirmation page (a signed state cookie, 5 minutes) and anything else `invalid_request`. The client needs `EnableEndSession`, which needs `auth.WithSecret` (`ErrNoSecret` from `auth.New` for a trusted client, from `CreateClient` and `UpdateClient` otherwise; without a secret discovery does not advertise the endpoint). A `post_logout_redirect_uri` is followed only when registered exactly; otherwise the success page says it was not registered |
| `/oauth2/end-session/confirm` | POST (form) | The confirmation page's form (`action=confirm`); the signed state is the only context it accepts, and it ends only the session the state was made for |
| `/oauth2/register` | POST (JSON) | RFC 7591 dynamic registration, closed unless `AllowDynamicRegistration`. Only `redirect_uris` is required; the answer always carries `client_name`, `grant_types`, `response_types`, `token_endpoint_auth_method` and `scope` as registered (the input is `ClientMetadata`, the answer's `Client` embeds `RegisteredMetadata`, the same fields with those always present) |
| `/oauth2/jwks` | GET | The jwt plugin's public keys |

These operations are served by every transport under `/oauthprovider`:

| Route | Requires | What |
|---|---|---|
| `POST /oauthprovider/consent` | signed in | The consent page's answer: `{oauth_query, accept, scope}` returns `{redirect_to}` |
| `GET /oauthprovider/public-client?client_id=` | signed in | What a consent page shows: name, URIs, contacts |
| `POST /oauthprovider/create-client` | fresh sign-in | A client the user owns; its secret is shown once |
| `GET /oauthprovider/clients`, `GET /oauthprovider/client?client_id=` | signed in | The user's clients; another user's client is `client_not_found` |
| `POST /oauthprovider/update-client` | fresh sign-in | Replace metadata; the authentication method cannot change |
| `POST /oauthprovider/rotate-secret` | fresh sign-in | New secret; the old one stops at once |
| `POST /oauthprovider/delete-client` | signed in | Deletes the client with its codes, tokens and consents |
| `GET /oauthprovider/get-consent?id=`, `POST /oauthprovider/update-consent` | signed in | One consent; replace its scopes (only scopes the client may request) |
| `GET /oauthprovider/consents`, `POST /oauthprovider/revoke-consent` | signed in | The user's consents; withdrawing one revokes that client's tokens for the user |

Go callers use `Authorize`, `Consent`, `Token`, `UserInfo`, `Introspect`, `Revoke`, `Register`, `CreateOwnedClient`, `Clients`, `OwnedClient`, `UpdateOwnedClient`, `RotateSecret`, `DeleteOwnedClient`, `PublicClientInfo`, `Consents`, `ConsentByID`, `UpdateConsent`, `RevokeConsent` and `EndSession`. Trusted code also has `CreateClient(ClientSpec)` and `UpdateClient`, which can set `SkipConsent`, `OptionalPKCE`, `IntrospectAny`, `EnableEndSession` and `OwnerID`, plus `SetClientDisabled`, `DeleteClient`, `Client`, `VerifyAccessToken` and `Metadata`.

## The browser flow

1. A signed-out browser at `/oauth2/authorize` goes to `LoginPage`, with the authorize parameters appended. After sign-in, the page sends it to `op.ResumeURL(query)`.
2. A signed-in user who has not consented to this client and these scopes goes to `ConsentPage`, also with the parameters. The page shows `PublicClientInfo` and posts `{oauth_query: <its query string>, accept: true|false}` to the consent operation. The query is validated again in full, so nothing the page sends is trusted. Without a `ConsentPage` the answer is `consent_required`. A client made with `SkipConsent` never asks.
3. The browser then goes to the client's redirect URI with `code`, `state` and `iss` (RFC 9207), or with `error` and `state`.

`prompt=none` never shows a page: it answers `login_required` or `consent_required`. `prompt=login` and `prompt=select_account` send even a signed-in user to the login page. The prompt is dropped from those parameters, so the page cannot loop. `prompt=consent` forces the consent page. `max_age` sends a user whose session is older to the login page, and `login_hint` is passed to it. `prompt=create` goes to `SignupPage`. A fetch caller (`Sec-Fetch-Mode: cors` or `Accept: application/json`) gets redirects as `{"redirect": true, "url": ...}`. `request` and `request_uri` are refused (`request_not_supported`, `request_uri_not_supported`). ID tokens carry `at_hash`: SHA-512 for EdDSA keys, SHA-256 otherwise.

## Security rules

Each rule has a test in `integration/r33_test.go` that was broken once to prove it fails:

- A redirect URI matches a registered one as an exact string. An unknown client or unregistered URI is answered to the user, never redirected (`invalid_redirect_target`), so the endpoint is not an open redirector. Registration takes only https, loopback http and reverse-domain private-use schemes, with no fragment and no credentials.
- PKCE with S256 is mandatory for public clients and the default for confidential ones; `plain` is refused. A code issued without a challenge refuses a verifier.
- A code is single use, expires after 10 minutes, and is bound to its client, its redirect URI and its verifier. Reusing it revokes every token issued from it.
- A refresh token rotates on every use. Presenting a spent one revokes its whole family.
- A client secret is compared in constant time against its SHA-256, and a client must authenticate with its registered method. `client_credentials` is refused to public clients and never grants `openid`, `profile`, `email` or `offline_access`.
- Client secrets, codes, and access and refresh tokens are stored only as SHA-256 hashes. Their prefixes (`ubos_`, `uboc_`, `uboa_`, `ubor_`) let secret scanners recognize a leak.
- The token, revocation, introspection and userinfo endpoints ignore the browser's cookie, so they are open to CORS without carrying a session.

## Options

| Option | Default | What |
|---|---|---|
| `Issuer(url)` | required | The `iss` and the base of every URL; https, or http on loopback |
| `LoginPage(url)` | required | Same-site path or a URL on a trusted origin |
| `ConsentPage(url)` | none | Without it, clients that need consent get `consent_required` |
| `BasePath(path)` | [`/oauth2`](ds:block?id=oauthprovider-defaultbasepath-p2v6mz9c) | Where the protocol endpoints live under the issuer |
| `Scopes(...)` | [`openid profile email offline_access`](ds:block?id=oauthprovider-defaultscopes-k3n8vq2m) | Supported scopes; without `openid` it is a plain OAuth 2.1 server |
| `GrantTypes(...)` | [all three](ds:block?id=oauthprovider-defaultgranttypes-w7p2xk4n) | `refresh_token` needs `authorization_code` |
| `CodeTTL`, `AccessTokenTTL`, `RefreshTokenTTL`, `IDTokenTTL` | [10m](ds:block?id=oauthprovider-defaultcodettl-r5m2qw8x), [1h](ds:block?id=oauthprovider-defaultaccessttl-h4k9zt3p), [30d](ds:block?id=oauthprovider-defaultrefreshttl-b8x3nq6v), 10h | Lifetimes |
| `M2MAccessTokenTTL(d)` | the access TTL | Lifetime of `client_credentials` access tokens |
| `ScopeExpirations(map)` | none | Shorter access-token lifetimes per scope; a token gets the earliest |
| `CacheResources(ttl)`, `CacheResourcesIn(kv, ttl)` | off | Keeps resource policies for `ttl` ([1m](ds:block?id=oauthprovider-resourcecache-ttl-5vq8mz2k) for 0, at most 15m), in this process or in any `auth.SecondaryStorage`; see Resources below |
| `SignupPage(url)` | none | Where `prompt=create` goes; the login page without it |
| `ValidateRedirectURI(fn)` | exact match | Replaces the redirect decision (gets the URI, the registered ones and the exact-match result); relaxes RFC 9700, so accept only hosts you control |
| `AccessTokenClaims(fn)` | none | Extra claims in JWT access tokens; provider claims cannot be replaced |
| `AdvertisedScopes(...)`, `AdvertisedClaims(...)` | every scope, the built-in claims | What discovery lists |
| `GenerateClientID(fn)`, `GenerateClientSecret(fn)` | random | At least 22 characters; a client id may never be an https URL |
| `PairwiseSecret(s)` | none | Pairwise subjects for clients registered with `subject_type: pairwise` (at least 32 characters) |
| `Claims(fn)` | none | Extra ID token and userinfo claims; it cannot override `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time` or `azp` |
| `AllowDynamicRegistration()` | off | RFC 7591 registration for signed-in users |
| `AllowUnauthenticatedRegistration()` | off | Registration with no session, as MCP clients expect; such a client has no owner |
| `RefreshReuseInterval(d)` | 0 | A just-rotated refresh token works again within `d` (a new pair each time), for clients that refresh from two tabs; after `d`, reuse revokes the family |
| `AssertionMaxLifetime(d)` | 5m | The longest a `private_key_jwt` assertion may live |
| `RateLimit(endpoint, n, window)`, `NoDefaultRateLimits()` | [per endpoint](ds:block?id=oauthprovider-defaultratelimits-q7v3mx2k) | Per-IP limits per endpoint; `n` 0 removes one |
| `ClientIDMetadataDocuments(...)` | off | CIMD: https client ids are fetched metadata documents |
| `ProtectedResource(url, scopes...)` | none | A resource server (an MCP server) whose RFC 9728 metadata `Handler` serves at `/.well-known/oauth-protected-resource{path}` |
| `MCP()` | off | `AllowUnauthenticatedRegistration` and a 30-second `RefreshReuseInterval` (`MCPRefreshReuseInterval`); later options override either |
| `RegistrationDefaultScopes(...)`, `RegistrationAllowedScopes(...)` | every scope | A registration naming no scope gets the defaults; one naming a scope outside defaults and allowed is `invalid_scope` |
| `RegistrationSecretExpiresAt(t)` | never | A fixed end for dynamically registered secrets; with `RegistrationSecretExpiration` the earlier wins. An instant not after now on the app's clock (`auth.WithClock`) fails `auth.New` with `ErrBadTTL` |
| `ClientJWKSFetch(fn)` | public addresses only | Replaces the `jwks_uri` fetcher (tests, an egress proxy) |
| `DPoPSigningAlgorithms(...)` | `EdDSA ES256 ES512 PS256 RS256` | The DPoP proof algorithms accepted and advertised |
| `HashStoredSecrets(fn)` | SHA-256 | The stored form of client secrets, codes, access and refresh tokens (`SecretKind` says which): deterministic, 32 bytes, refused at `auth.New` otherwise |
| `GenerateAccessToken(fn)`, `GenerateRefreshToken(fn)` | 256 random bits | The random part of opaque access and refresh tokens; at least 22 characters |
| `UserInfoInsufficientScope()` | off | Userinfo for a token without `openid` answers RFC 6750's 403 `insufficient_scope` instead of 400 `invalid_scope` |
| `SelectAccountFallsBackToLogin()` | off | `prompt=select_account` with no `SelectAccount` page goes to the login page instead of answering `unsupported_prompt_select_account` |
| `RevokeAccessTokenOnly()` | off, warns at start | Revoking an access token leaves its refresh token working. Risk: a leaked grant survives revoking its access token |
| `RefuseJWTRevocation()` | off, warns at start | A live JWT access token's revocation answers `unsupported_token_type`. Risk: the token stays usable everywhere until it expires |
| `EncryptClientSecrets(enc)` | off, warns at start | Encrypted client secrets: a recoverable copy beside the hash, read with `RevealClientSecret`. Risk: the key plus the database yields every secret |
| `RefreshReplay(enc)` | off, warns at start | Replays the first response to a refresh token reused inside `RefreshReuseInterval` (required). Risk: issued tokens are stored recoverable for the window |

## Resource servers and MCP

`RequireToken(RequireOptions{Resource, Scopes, JSONRPC, ChallengeScopes})` guards a resource server's routes. It verifies the bearer access token and every required scope, and puts the token in the context (`TokenFrom`). A missing or bad token gets 401, and a missing scope gets 403 `insufficient_scope` naming the missing scopes. Each refusal carries the `WWW-Authenticate: Bearer` challenge with `resource_metadata`, which is how an MCP client finds the authorization server. `JSONRPC` answers in the JSON-RPC 2.0 error envelope (`code -32000`, `id null`). `ChallengeScopes` names other scopes in a 401 challenge than the ones checked. An MCP setup is `ProtectedResource` plus `MCP()` plus `RequireToken` on the MCP endpoint.

## Resource indicators and JWT access tokens

A client asks for a token for one API by sending `resource` (RFC 8707), at authorize or in a `client_credentials` request. The resource must be declared with `ProtectedResource`, or the answer is `invalid_target`. Its scopes must be user scopes or the resource's own, or the answer is `invalid_scope`. The access token for a resource is a JWT signed with the jwt plugin's key: `sub` (the user, or the client for `client_credentials`), `aud` (the resource), `client_id`, `scope`, `iat`, `exp`, `jti` and `token_id`. A service in another process verifies it offline with `jwt.Verifier{Keys: jwt.KeysFromJWKS(...), Issuer: issuer, Audience: resource, Types: []string{oauthprovider.AccessTokenType}}` against `/oauth2/jwks`. It is stored hashed like an opaque token, so revocation and introspection (which answers `aud`) still apply in-process, and `RequireToken` with `Resource` accepts only tokens for that resource. A refresh keeps the resource; a different one at the exchange or refresh is `invalid_target`. Without `resource` the access token stays opaque. The header `typ` is `at+jwt` (RFC 9068), so it is never taken for an ID token (`JWT`). ID tokens carry `sid`, the session they were issued in, which RP-initiated logout matches against the browser's session.

## Client authentication with private_key_jwt

A client registered with `AuthMethod: AuthMethodPrivateKeyJWT` and an inline `JWKS` or a `JWKSURI` (one or the other; public Ed25519, RSA of at least 2048 bits, or P-256, P-384 or P-521 keys with a `kid`; a private or symmetric member is refused) has no secret. It authenticates at the token, introspection and revocation endpoints with `client_assertion` and `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` (RFC 7523). The assertion is signed by one of its keys, has `iss` and `sub` equal to the client_id, an `aud` of the endpoint URL or the issuer, an `exp` at most `AssertionMaxLifetime` ahead, and a `jti` that works once: spent ids are kept in `auth_oauth_assertion` until they expire. A secret together with an assertion is `invalid_request`. When the form has no `client_id`, the assertion's `sub` names the client, and the signature decides. Every `jwt.AlgValues` algorithm is accepted (listed as `token_endpoint_auth_signing_alg_values_supported`); a key with no `alg` verifies under the header's algorithm within its family (any RSA algorithm for an RSA key, the curve's for an EC key), and the header needs no `typ`.

A `jwks_uri` must be https on an origin the app trusts (the client_id's own origin for a CIMD client), with no credentials or fragment. The set is fetched on first use by a fetcher that reaches public addresses only, follows no redirect, times out after 5 seconds and reads at most 64 KiB of an exactly-200 JSON or `application/jwk-set+json` answer. It is cached 5 minutes (500 sets at most), served stale up to 10 minutes while the host fails, and fetched again when an assertion fails to verify, at most every 30 seconds. `ConsumeClientAssertion(ctx, clientID, assertion, audience)` runs the same check, jti spent, for an endpoint of the app's own.

## Client ID metadata documents (CIMD)

With `ClientIDMetadataDocuments()`, a `client_id` that is an https URL names a JSON document the client publishes. The first authorize or token request fetches it and stores it as a client row. It is fetched again once older than `CIMDRevalidate` (1 hour), and a failed refetch refuses the request. The default fetcher only reaches public addresses (RFC 6890 ranges refused), dials the address it checked, follows no redirect, times out after 5 seconds, and reads at most 5 KB of an exactly-200 `application/json` or `application/*+json` answer. At most 16 fetches run at once.

A document is refused (`invalid_client`, or the authorize error page) when:

- its `client_id` differs from the URL;
- it sets a member only the server decides, such as `client_secret`, `skip_consent` or `require_pkce`, in snake or camel case (`skipConsent`);
- it uses a shared-secret method (only `none` or `private_key_jwt` is allowed);
- a URL of an origin-bound field is on another origin: `client_uri` and the post-logout URIs by default (`DefaultCIMDOriginBoundFields`), `CIMDOriginBoundFields(...)` to choose (loopback and private-use schemes allowed in the redirect fields), and the `jwks_uri` always;
- none of its grants is one the provider serves (unknown ones are dropped; one is enough). Without `redirect_uris` it keeps only grants that need none, such as `client_credentials`.

`IsCIMDClientID`, `ValidCIMDClientID` and `ValidateCIMDDocument` expose the same checks to Go.

The client_id URL needs an https host and a path that is not `/`, with no dot segments, fragment or credentials. `CIMDAllow` gates URLs before any fetch, `CIMDProfileMCP` requires `client_name` and `redirect_uris`, and `CIMDFetch` replaces the fetcher (tests, an egress proxy). Registered clients have generated ids, so a document can never take one over. Discovery advertises `client_id_metadata_document_supported`.

A fetched document stays fresh for its HTTP lifetime, capped by `CIMDRevalidate`. These rules apply:

- `s-maxage` takes precedence over `max-age`, which takes precedence over `Expires`, less `Age`;
- `no-store`, `private`, `no-cache` and `Vary: *` give a lifetime of zero, and so does a repeated or invalid directive.

A stale document is revalidated with `If-None-Match` and `If-Modified-Since`. A `304` keeps it, but only when validators were stored. Concurrent requests for one URL share one fetch. The governor (`CIMDPolicy`) caps fetches: 16 in flight, 4 per origin, 120 a minute and 30 per origin a minute, with retries of a failed URL paced to one a second. Fresh hits and joined fetches spend nothing, and a fetch over budget is refused (`429 temporarily_unavailable`), never queued. `CIMDOnClientCreated` and `CIMDOnClientRefreshed` are best-effort hooks, and `CIMDTransport` replaces the fetcher with one that sees the conditional headers.

## The resource registry

Resources are rows of their own: `CreateResource`, `Resource`, `Resources`, `UpdateResource` and `DeleteResource` from Go, with `LinkClient` and `UnlinkClient` for the client links (a second link answers `alreadyLinked`). A resource sets `AllowedScopes`, which narrows a token's scopes by intersection (`invalid_scope` when none are left), shorter `AccessTTL` and `RefreshTTL`, `CustomClaims` for its JWT access tokens and introspection (protected claims ignored), `DPoPRequired`, `Disabled` and `Metadata`. A resource declared with `ProtectedResource` and no row has the provider's defaults; a row overrides it. Several resources in one request (the parameter repeated over HTTP, space-separated in Go) combine their policies: the shortest lifetimes, DPoP when any requires it, every custom claim, and one signing algorithm and key at most (conflicting pins are `invalid_request`); the JWT's `aud` names each, introspection answers `aud` as an array, a token or refresh request may narrow to some of them, and `AccessToken.HasResource` answers for one. `Resource.SigningKeyID` pins the signing key by key id (`jwt.AlgorithmKeys` may hold several keys of one algorithm), checked by a probe signature at write; `PolicyVersion` counts writes. A consent records its resources, so a new resource asks again. `LinkClientWithMetadata` and `ClientResourceLinks` read and write a link's metadata. `PatchResource(ctx, id, ResourcePatch{...})` changes only the fields it names, and `SeedResources(ctx, mode, seeds...)` writes configured resources after migrations: `SeedInsertOnly` (the default) leaves existing rows, `SeedMerge` sets the named fields, `SeedOverwrite` replaces the policy.

`CacheResources(ttl)` is opt-in: the resource policies an issuance, a refresh and an introspection read are kept in this process for `ttl`, and `CacheResourcesIn(kv, ttl)` keeps them in any `auth.SecondaryStorage` instead (contrib/redis's `NewStorage`, or the store already given to `auth.WithSecondaryStorage`; only `Get`, `Set` and `Delete` are used, entries carry their own expiry judged by the core's clock, and a failing store is logged and the database read instead), so every instance shares one cache (0 is `DefaultResourceCacheTTL`, one minute; above `MaxResourceCacheTTL`, 15 minutes, or negative is `ErrBadResourceCacheTTL` at `auth.New`). `CreateResource`, `UpdateResource`, `PatchResource`, `SeedResources` and `DeleteResource` drop the entry once they have written, so this instance's writes are seen at once, and with a shared store every instance's; with the in-process cache, a change on another instance, or by SQL, is seen when the entry expires. `Resource` and `Resources` always read the database, and an identifier with no row is remembered only when it is a `ProtectedResource` declared in code, so requests for random identifiers cannot grow the cache.

Every issuance resolves the resource again:

- an unknown or disabled resource is `invalid_target`;
- a client not linked to the resource is `invalid_target` (`EnforcePerClientResources(false)` turns this off);
- a token whose resource was deleted becomes inactive, while a disabled resource's issued tokens keep working until they expire.

A token for a resource carries the userinfo URL as a second audience when `openid` is granted. A client linked to a token's resource may introspect it. `RegistrationDefaultResources` are linked to every new client, `RegistrationAllowedResources` are the extra ones a registration's `resources` member may name, and `IdentifierValidator` replaces the RFC 8707 identifier check.

## Client policy

These rules hold for every client:

- `client_credentials` needs a server-owned ceiling (`ClientSpec.ClientCredentialsScopes`): without one the grant is `unauthorized_client`, a scope outside it or a user scope is `invalid_scope`, and an omitted scope takes the whole ceiling.
- `application_type` is `web` (the default: https on non-loopback hosts) or `native` (https on non-loopback hosts, http only on exactly `localhost`, `127.0.0.1` or `[::1]`, or a reverse-domain private-use scheme). A CIMD document without one is held to the native rules.
- `ClientSpec.SecretExpiresAt` ends a secret, and an expired one authenticates nothing. `RegistrationSecretExpiration` gives dynamically registered confidential clients one, and `RegistrationRequirePKCE(false)` lets them omit PKCE.
- `ReferenceID` and `Metadata` are stored as given.
- An owner may set the `client_credentials` ceiling through the operations (`client_credentials_scopes` at creation, `ClientCredentialsScopes` in an update) only when `ClientPrivileges` exists and grants `ActionConfigureCCScopes`; an anonymous registration and a metadata document may never set it.

## Resource servers in other processes

`ResourceGuard{Issuer, Audience, Keys, IntrospectURL, ClientID, ClientSecret, AllowMissingAudience, Scopes, ChallengeScopes, ScopeSatisfied, ResourceMetadataURL, JSONRPC}.Middleware` protects a resource server that runs apart from the provider. It verifies `at+jwt` access tokens offline with the provider's keys (`jwt.NewRemoteKeys(...).Lookup`), and opaque ones by introspection: the introspected audience must name this resource, and one that names none is refused unless `AllowMissingAudience` is set. It then checks scopes and answers the same challenges as `RequireToken`; the verified token is in `GuardedTokenFrom(ctx)`. DPoP-bound tokens are refused there, because the guard checks no proofs. `RequireOptions.ScopeSatisfied` replaces the exact scope match, `WriteInsufficientScope` answers a 403 from inside a handler, and `ProtectedResourceMetadata` builds an RFC 9728 document for a resource served elsewhere.

## Signed query, pre-login, and registration options

With `auth.WithSecret`, the parameters the provider hands a login or consent page are signed: `exp` (the code lifetime), `ba_iat`, the sorted `ba_param` names, and `sig`, an HMAC over the canonical query. The consent operation verifies the `oauth_query` it receives (`invalid_signature` for a changed, unsigned or expired one), and `VerifyOAuthQuery` does the same from Go. `AllowPublicClientPrelogin` serves `POST /oauthprovider/public-client-prelogin` (`PublicClientPrelogin`), which shows a client's public fields to a page holding a valid signed query for that client, before sign-in; it and `PostLogin` need `auth.WithSecret`, and `auth.New` refuses them without one (`ErrNoSecret`).

`TokenResponseFields(fn)` adds members to the token response (never replacing a standard one), before any token is stored. `ValidateInitialAccessToken(fn)` accepts an RFC 7591 initial access token as `Authorization: Bearer` on `/oauth2/register`: a valid one admits the registration even when open registration is off and sets the client's `ReferenceID`, and a presented token is refused (`invalid_token`) when no validator is configured. `software_id`, `software_version` and `software_statement` are stored as given. A resource's `SigningAlgorithm` pins its JWT access tokens to one of the jwt plugin's algorithms. `ClientReference(fn)` makes clients belong to a reference (an organization) instead of the user, and `ClientPrivileges(fn)` gates each owner action (`create`, `read`, `update`, `delete`, `list`, `rotate`; `forbidden` when refused).

## Pairwise subjects

With `PairwiseSecret`, a client registered with `subject_type: "pairwise"` sees each user as `base64(HMAC-SHA256(secret, "<host of its first redirect URI>.<user id>"))`, so two clients cannot join their users by `sub`. It applies in ID tokens, userinfo, introspection and JWT access tokens. Such a client's redirect URIs must all be on one host (the sector), and without the secret the registration is refused. Discovery then lists `subject_types_supported: ["public", "pairwise"]`.

## The claims parameter

An authorize request with `openid` may send the OpenID Connect `claims` parameter (Core section 5.5). It must be a JSON object whose `userinfo` and `id_token` members map claim names to `null` or a request object; anything else is `invalid_request`, as is the parameter without `openid`. An essential `acr` that does not allow `"0"` (the only level this provider asserts) is `access_denied`. The `userinfo` names the provider supports are recorded on the consent, so a request for a name not yet consented asks again. Userinfo then releases those claims even without their scope. The standard claims are `name`, `picture`, `given_name` and `family_name` (split from the display name), `email` and `email_verified`. Discovery lists `claims_parameter_supported` and `acr_values_supported: ["0"]`.

## Pushed authorization requests

With `RequestURIResolver(fn)`, an authorize request with `request_uri` takes every parameter from what `fn` returns, except `client_id`, which comes from the URL (RFC 9126 section 4); a nil answer is `invalid_request_uri`. Without a resolver `request_uri` is `request_uri_not_supported`, and `request` together with `request_uri` is `invalid_request`. The pushed-request endpoint itself is the app's to serve.

## Back-channel logout

A client registered with `backchannel_logout_uri` (https, or http on loopback) is told when a session it holds tokens for ends: sign-out, a revoked session, a password reset or a ban. After the commit, the provider POSTs `logout_token`, a `logout+jwt` signed with the ID-token key, carrying `iss`, `aud`, `sub` (pairwise when the client is), `sid`, `iat`, `exp` (two minutes), `jti` and the back-channel event, and never a `nonce`. Each client gets one attempt with a 5-second timeout and no redirects, as OpenID Connect Back-Channel Logout 1.0 section 2.5 asks. The session's access tokens stop at once; its refresh tokens stop too unless `offline_access` was granted (section 2.7). `BackchannelHTTPClient` replaces the HTTP client. Discovery lists `backchannel_logout_supported` and `backchannel_logout_session_supported`.

## DPoP

A client registered with `dpop_bound_access_tokens: true`, an authorize request with `dpop_jkt`, or a bound refresh token makes the token endpoint require a `DPoP` proof (RFC 9449). Any token request may send one. The proof must:

- be a `dpop+jwt`, signed with one of `DPoPSigningAlgorithms` (default EdDSA, ES256, ES512, PS256, RS256), by the public JWK in its header (a private or symmetric member is refused; a key with no `alg` is read for the header's algorithm within its family);
- name `htm` and `htu` (origin and path) of the request;
- have an `iat` at most 5 seconds ahead and `DPoPProofMaxAge` (300 seconds) old;
- carry a `jti` used once for that key and request.

A bound token answers `token_type: "DPoP"`, carries `cnf.jkt` (in the JWT access token and in introspection), and is accepted at userinfo and `RequireToken` only with `Authorization: DPoP <token>` and a fresh proof of the same key whose `ath` is the token's hash. The DPoP scheme with an unbound token is `invalid_token`. Failures are `invalid_dpop_proof` with a `WWW-Authenticate: DPoP` challenge. `VerifyPresentedToken` applies the same rules from Go.

## Extension grants

`WithGrant(ExtensionGrant{Type, Handle, ErrorNamespace})` serves an extra `grant_type`, an absolute URI, at the token endpoint. The device authorization grant module uses it. The provider authenticates the client and checks that it registered the grant type before calling `Handle`. `Handle` returns a `GrantDecision` (user, scopes, resource, auth time), and the provider checks the scopes and issues tokens through the same path as every other grant. Errors whose code starts with `ErrorNamespace.` keep the rest as their wire code (`authorization_pending`). Extension grants are listed in `grant_types_supported`; `DeviceAuthorizationEndpoint(url)` adds `device_authorization_endpoint`. `AuthenticateClient` and `CheckScopes` are exported for a module that serves an endpoint of its own, with `IssueTokens(ctx, IssueRequest{GrantType, ClientID, UserID, Scopes, Resource, Confirmation, ...})` (a raw minting primitive: the caller has decided the grant), `HashToken(token, kind)` and `ConsumeClientAssertion`.

## Revocation, userinfo and error names

Where a laxer answer is offered, it is an opt-in that warns at every start. By default revoking an access token ends its refresh token too, and a JWT access token is revoked like an opaque one; `RevokeAccessTokenOnly` and `RefuseJWTRevocation` give the laxer answers. Userinfo without `openid` is 400 `invalid_scope`, and a token whose session has ended is 401 `invalid_token` there. The wire codes are `invalid_redirect` (an unregistered redirect URI), `invalid_user` (a grant whose user was deleted), `unsupported_prompt_select_account`, `not_found` (a missing client or consent), `unsupported_token_type`. `invalid_software_statement`, `unapproved_software_statement` and `invalid_request_object` are never answered: software statements are stored as given and request objects are `request_not_supported`.

## Authorization requests

An unknown `client_id` is `invalid_client` and a disabled client `client_disabled`; neither is sent to the redirect URI, and a browser (an `Accept: text/html` navigation) gets an HTML error page with `no-store`, a CSP and `nosniff` (errors.Is also sees `ErrBadRedirectTarget`). A refresh token needs PKCE: `offline_access` without a challenge is `invalid_request` unless a confidential client sends `openid` and a `nonce`. `display` and `ui_locales` are passed to the login, consent and other pages. An `id_token_hint` must be an ID token this provider signed for the client (expired is fine, `invalid_request` otherwise); when it names another user than the signed-in one, the browser goes to the login page, or `prompt=none` answers `login_required`. Logout errors are the same HTML page for a browser. The consent operation's `claims` (a claims-request object) grants fewer of the requested userinfo claims. Userinfo without any credential answers 401 with a bare `WWW-Authenticate: Bearer`. Introspection reports an access token inactive once its session has ended, by sign-out or by expiry; a refresh token outlives its session.

## Tables

[`auth_oauth_client`](ds:block?id=oauthprovider-tableclient-n4x8kq2v), [`auth_oauth_code`](ds:block?id=oauthprovider-tablecode-t6m3wp9z), [`auth_oauth_token`](ds:block?id=oauthprovider-tabletoken-c2h7vb5r), [`auth_oauth_consent`](ds:block?id=oauthprovider-tableconsent-y9q4kd3s) and [`auth_oauth_assertion`](ds:block?id=oauthprovider-tableassertion-v5k2np8w), with no foreign keys; migration `0013` adds the client's `jwks_uri`. `DeleteUser` removes a user's rows, and `Sweep` deletes expired codes and fully expired tokens.

## Not yet

These are not built yet:

- request objects (`request`, refused) and a pushed-request endpoint (the resolver is the app's)
- DPoP nonces
- extension client-authentication strategies
- the device grant via the provider, which plugin/deviceauth wires through `WithGrant`
- the Agent Auth protocol, which is [plugin/agentauth](../agentauth/README.md)

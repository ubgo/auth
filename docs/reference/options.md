# Limits and options

Every limit, lifetime and behaviour of the two OIDC clients and the OAuth provider on one page: the option that sets it, its default, what 0, an empty value or `NoLimit` means, and, for what has no option, why. The clients are [`oidcclient`](../../oidcclient/doc.go) (Go) and [`@ubgo/auth-client/oidc`](../../clients/ts/README.md#ubgoauth-clientoidc-server-side-sign-in-through-an-openid-connect-server) (TypeScript), twins with the same model; the provider is [`plugin/oauthprovider`](../../plugin/oauthprovider/README.md). The guides explain each option with a worked example: [OIDC client › Every option](../integrations/oidc-client.md#every-option) and [OAuth provider › Every lifetime, limit and hook](../plugins/oauthprovider.md#every-lifetime-limit-and-hook).

The rules every row follows:

- The default is the value the library used before the option existed, so leaving an option out changes nothing.
- For a limit, 0 or an empty value means off or no limit, except where 0 would remove a security protection: there it is refused when the client or `auth.New` starts, with an error naming the option, so an unset setting read as 0 never starts a server without the protection. [Where 0 is refused](#where-0-is-refused) lists those.
- An option that existed before keeps the meaning its 0 had (for example a zero `oidcclient.Lifetimes` field is the default); a new "no limit" then has its own name, `NoLimit` in Go and `NO_LIMIT` in TypeScript.
- What is deliberately fixed is listed with its reason: [clients](#fixed-in-the-clients), [provider](#fixed-in-the-provider).
- Changes are backward compatible and ship as patch releases.

## OIDC clients: oidcclient and @ubgo/auth-client/oidc

Go durations are `time.Duration`; every TypeScript time is in milliseconds. `NoLimit` is the largest `time.Duration`, `NO_LIMIT` is `Infinity`, and each is accepted only where the table says so.

### Lifetimes and timing

| Go | TypeScript | Default | 0 / empty | `NoLimit` / `NO_LIMIT` | What it decides |
|---|---|---|---|---|---|
| `WithLifetimes(Lifetimes{Idle, Absolute})` | `lifetimes: { idleMs, absoluteMs }` | [7 days](ds:block?id=defaultidlelifetime-mjhkz59a) idle, [30 days](ds:block?id=defaultabsolutelifetime-957evyy7) absolute | Go: the default. TypeScript: refused, because an empty environment variable reads as 0 | no such bound | How long a session lives without the login server's pages: idle since the last use, absolute since sign-in. With no idle bound `ExpiresAt` is the last use plus [400 days](ds:block?id=maxcookielifetime-uej2685q) (`MaxCookieLifetime`, `MAX_COOKIE_LIFETIME_MS`) so a store keeps a real TTL |
| `WithRecheckInterval(d)` | `recheckIntervalMs` | [1 minute](ds:block?id=defaultrecheckinterval-vekfr6zh) | `RecheckEveryRequest` / `RECHECK_EVERY_REQUEST`: ask on every request | never ask again | How long the login server's last "yes" stands: the longest a removed person keeps access |
| `WithOutageGrace(d)` | `outageGraceMs` | [5 minutes](ds:block?id=defaultoutagegrace-asgxt3qs) | `NoOutageGrace` / `NO_OUTAGE_GRACE`: refuse at once | the whole outage | How long the last "yes" stands while the login server cannot be reached; never past the lifetimes |
| `WithSlideInterval(d)` | `slideIntervalMs` | [1 minute](ds:block?id=defaultslideinterval-73hnwk85) | slide on every request | never slide (only with no idle bound) | How often a request moves the idle window and rewrites the cookie or store row; shorter than a limited idle bound |
| `WithClockSkew(d)` | `clockSkewMs` | [30 seconds](ds:block?id=defaultclockskew-vc9erhjq) | trust both clocks exactly | not accepted; at most `MaxClockSkew` / `MAX_CLOCK_SKEW_MS` (5 minutes) | The clock difference allowed on ID and logout tokens' `iat`, `nbf`, `exp` and on a sign-in's start |
| `WithFlowLifetime(d)` | `flowLifetimeMs` | [10 minutes](ds:block?id=defaultflowlifetime-fb3km7wf) | refused | not accepted | How long one sign-in may take, login route to callback |
| `WithHTTPClient(c)` | `fetch`, `httpTimeoutMs` | 10 seconds, no redirects followed | Go: your client's `Timeout` decides (0 is none). TypeScript: `httpTimeoutMs` 0 is refused | | One request to the login server; proxies, mTLS and retries of idempotent requests belong in your client or `fetch` |

`New` and `createOidcClient` refuse the one configuration where nothing could ever end a session: no idle and no absolute bound, never re-checked, and a store that cannot revoke (no `SessionRevoker` / `revokeSessions`).

### Cookie, sign-out and return

| Go | TypeScript | Default | 0 / empty | What it decides |
|---|---|---|---|---|
| `WithCookie(CookieOptions{Name, Domain, SameSite, BrowserSession})` | `cookie: { name, domain, sameSite, browserSession }` | `__Host-oidc_session`, host-only, `Lax`, kept until `ExpiresAt` | `BrowserSession` false: the cookie survives a browser restart; true writes no expiry | The session cookie's name, sharing with subdomains (a `__Secure-` name with `Domain`), `Strict`, and whether closing the browser forgets it |
| `WithLogoutPolicy(p)` | `logoutPolicy` | `LogoutAlways(LogoutAtServer)` / `logoutAlways(LogoutMode.atServer)` | an unknown mode signs out at the server | Per sign-out: at the server (end-session redirect) or the app only |
| `WithPostLogoutPath(path)` | `postLogoutPath` | `/` | | Where the browser lands after sign-out |
| `WithReturnPolicy(p)` | `returnPolicy` | `ReturnToRequested()` / `returnToRequested()` | | Where sign-in lands; held to the same-site floor |
| `WithPaths(p)` | `paths` | `PathsUnder("/auth")` / `pathsUnder("/auth")` | | Where the login, callback, logout and back-channel routes live |
| `WithScopes(...)`, `WithAuthParams(map)` | `scopes`, `authParams` | `openid email profile offline_access`, none | `openid` is always added | Requested scopes and extra authorization parameters (`prompt`, `login_hint`, `acr_values`) |

### Seams and hooks

| Go | TypeScript | Default | What it replaces or hears |
|---|---|---|---|
| `WithSessionStore(store)` | `store` | the sealed cookie | Where sessions live: memory, Redis, SQL, your own; a revoker enables back-channel logout |
| `WithSealer(s)`, `Config.PreviousSessionSecrets` | `sealer`, `previousSessionSecrets` | AES-256-GCM from the session secret | A KMS-held key, or rotating the secret |
| `WithUserMapper(fn)` | `mapUser` | `DefaultUser` / `defaultUser` | The app's user from the ID token |
| `WithAuthorizer(fn)` | `authorize` | none | The app's own rule on every request; fails closed |
| `WithRechecker(r)` | `rechecker` | by refresh | How the login server is asked again: refresh, introspection, userinfo, back-channel only, or your own |
| `WithResponder(r)` | `responder` | built-in pages and JSON | Refusal pages and API bodies |
| `WithClientAuth(a)` | `clientSecret` or `clientAuth` | `client_secret_basic` | `client_secret_post`, a public client, or your own |
| `WithDiscovery(m)`, `WithLogger(l)`, `WithClock(now)` | `discovery`, `logger`, `now` | discovery on first use, the default logger, the system clock | A server without discovery, your logger, a test clock |
| `WithObserver(o)` | `observe` | none | Metrics and audit, without session data |
| `WithOnSessionStart(fn)` | `onSessionStart` | none | Every sign-in before the session is saved; an error refuses the sign-in |
| `WithOnSessionEnd(fn)` | `onSessionEnd` | none | Every session the package ends, with its reason (logout, idle, absolute, refused re-check, replaced, back-channel) |
| `WithOnRefreshFailed(fn)` | `onRefreshFailed` | none | Each re-check that did not keep the session, once per flight, with whether the server was unreachable |

### Fixed in the clients

| Behaviour | Why it has no option |
|---|---|
| PKCE (S256), state, nonce, the ID token's signature algorithms and its `iss`, `aud`, `azp`, `sub` and `at_hash` checks | Each has one correct value; an option to weaken it would be the first thing a hurried integration turns off |
| `Secure`, `HttpOnly`, `Path=/`, the `__Host-` / `__Secure-` prefixes, `SameSite=None` refused | A session cookie readable by script, sent over http or cross-site is one anyone can take |
| The flow cookie is always `SameSite=Lax` | The login server's redirect back is a cross-site navigation that `Strict` would strip it from |
| Sign-out is a `POST` from the app's own origin, and it revokes the refresh token | Otherwise any site could sign people out with a link, and a saved cookie copy could keep refreshing |
| The same-site return path | A policy can only narrow it; anything else is an open redirect |
| Three cookies of about 3.8 KB per session, up to three sign-ins in flight per browser | Browser and proxy header limits; a bigger session belongs in a server-side store |
| One refresh per session at a time in a process, its answer reused for 10 seconds | Closes the two-tab refresh race |
| Key set re-read daily or on an unknown key id (at most once a minute); a failed discovery retried after a minute | Shared with `plugin/oauth`; a rotated key is picked up on its first use |
| Back-channel logout tokens at most 2 minutes old, each accepted once | The specification and the provider's token lifetime |
| Responses from the login server at most 1 MiB | A safety bound on what a remote server can make the app read |
| No built-in retries | A GET can retry in your own transport; a refresh must not, because a rotated refresh token whose answer was lost cannot be presented again |

## OAuth provider: plugin/oauthprovider

Options go to `oauthprovider.New`; the CIMD options go to `ClientIDMetadataDocuments(...)`. "Refused" means `auth.New` fails with `ErrBadTTL` or `ErrBadLimit` and the option's name.

### Lifetimes and clocks

| Option | Default | 0 means | What it bounds |
|---|---|---|---|
| `CodeTTL(d)` | [10 minutes](ds:block?id=oauthprovider-defaultcodettl-r5m2qw8x) | refused | How long a code waits to be exchanged |
| `AccessTokenTTL(d)` | [1 hour](ds:block?id=oauthprovider-defaultaccessttl-h4k9zt3p) | refused | An access token's lifetime |
| `M2MAccessTokenTTL(d)` | `AccessTokenTTL` | `AccessTokenTTL` | A `client_credentials` access token's lifetime |
| `ScopeExpirations(map)` | none | a scope's 0 is refused | Shorter access-token lifetimes per scope; a token with several gets the earliest |
| `RefreshTokenTTL(d)` | [30 days](ds:block?id=oauthprovider-defaultrefreshttl-b8x3nq6v) | refused | The idle limit: each rotation starts a new one |
| `MaxAuthAge(d)` | 0 | no cap | The absolute limit: no refresh token outlives the sign-in by more than `d` |
| `IDTokenTTL(d)` | 10 hours | refused | An ID token's lifetime |
| `RefreshReuseInterval(d)` | [0](ds:block?id=oauthprovider-refreshreuseinterval-y84nezrp) | strict rotation | How long a just-rotated refresh token may be presented again (`MCP()` sets 30 seconds) |
| [`ConsentTTL(d)`](ds:block?id=oauthprovider-consentttl-2dhamaaw) | 0 | never expires | How long a stored consent holds before the user is asked again |
| `EndSessionConfirmTTL(d)` | [5 minutes](ds:block?id=oauthprovider-defaultendsessionconfirmttl-337cbwz6) | refused (at least 1 second) | How long the logout confirmation page stays valid |
| [`EndSessionHintGrace(d)`](ds:block?id=oauthprovider-endsessionhintgrace-9ut43fa7) | 0 | no expired hint accepted | How long past its `exp` an `id_token_hint` still ends a session |
| `BackchannelLogoutTokenTTL(d)` | [2 minutes](ds:block?id=oauthprovider-defaultbackchannellogouttokenttl-wyrq8uee) | refused (at least 1 second) | A logout token's lifetime |
| `BackchannelTimeout(d)` | [5 seconds](ds:block?id=oauthprovider-defaultbackchanneltimeout-na9cwfke) | no bound of the plugin's own; the core's `auth.DeliveryTimeout` still ends the background work | One logout delivery, with a custom `BackchannelHTTPClient` too |
| `ClockSkew(d)` | [30 seconds](ds:block?id=oauthprovider-defaultclockskew-hujzr276) | no skew | Clock difference on a `private_key_jwt` assertion and an end-session hint |
| `AssertionMaxLifetime(d)` | 5 minutes | refused | How far ahead a client assertion's `exp` may be |
| `DPoPClockSkew(d)` | [5 seconds](ds:block?id=oauthprovider-defaultdpopclockskew-rattkq5w) | no skew | How far ahead a DPoP proof's `iat` may be |
| `DPoPProofMaxAge(d)` | 300 seconds | refused | How old a DPoP proof may be |
| `RegistrationSecretExpiration(d)`, `RegistrationSecretExpiresAt(t)` | never | never expires | When secrets of dynamically registered clients end; a time already past is refused |
| `ResourceGuard{Leeway}` | 30 seconds | 30 seconds (the `jwt.Verifier` convention; the smallest positive value allows practically none) | Clock skew on a JWT's `exp` and `nbf` in the remote resource guard |

### Sizes, fetches, caches and rate limits

| Option | Default | 0 / empty means | What it bounds |
|---|---|---|---|
| `MaxRequestBytes(n)` | [64 KiB](ds:block?id=oauthprovider-defaultmaxrequestbytes-zew63u39) | refused | A protocol form or registration body |
| `ClientJWKSCacheTTL(d)` | [5 minutes](ds:block?id=oauthprovider-defaultclientjwkscachettl-pygnhbvn) | refused (at least 1 second) | How long a client's `jwks_uri` keys are used before a refetch |
| `ClientJWKSFetchLimits(timeout, n)` | [5 seconds](ds:block?id=oauthprovider-defaultclientjwksfetchtimeout-qrmbwraj), [64 KiB](ds:block?id=oauthprovider-defaultclientjwksmaxbytes-d2q4yrh4) | refused | The default `jwks_uri` fetcher |
| `CIMDFetchLimits(timeout, n)` | [5 seconds](ds:block?id=oauthprovider-defaultcimdfetchtimeout-nbbp2ekj), [5 KB](ds:block?id=oauthprovider-defaultcimdmaxdocumentbytes-yhuej2dr) | refused | A client metadata document's fetch time (default fetcher) and size (every fetcher) |
| `CIMDRevalidate(d)` | [1 hour](ds:block?id=oauthprovider-defaultcimdrevalidate-h3w8kq5n) | refused | How long a document without HTTP freshness is used |
| `CIMDMaxCacheEntries(n)` | 1000 | the default | Document clients remembered per instance |
| `CIMDPolicy(CIMDFetchPolicy{...})` | 1 second between retries of a failed URL, 16 fetches in flight (4 per origin), 120 a minute (30 per origin) | a zero field is that field's default | The fetch governor for URLs callers choose |
| `CIMDOriginBoundFields(...)` | post-logout URIs and client URI | none bound (the `jwks_uri` always is) | Which document URLs must be on the client id's origin |
| `CacheResources(ttl)`, `CacheResourcesIn(kv, ttl)` | off: every issuance reads the resource row | ttl 0 is 1 minute; at most 15 minutes | How long resource policies are kept in memory or in a shared store |
| `RateLimit(endpoint, n, window)`, `NoDefaultRateLimits()` | [per endpoint](ds:block?id=oauthprovider-defaultratelimits-q7v3mx2k) | `n` 0 removes that endpoint's limit | Calls per client IP |

### Hooks and seams

| Option | Default | What it decides or hears |
|---|---|---|
| `ClientAccess(fn)`, `NoAccessPage(url)` | everyone; a 403 | Who may use each client, asked before every code and every token (refresh included), and where a refused user lands |
| `TokenResponseFields(fn)` | none | Extra members in the token response; an error fails the issuance |
| `Claims(fn)`, `AccessTokenClaims(fn)` | none | The app's claims in ID tokens, userinfo and JWT access tokens |
| [`ScopeClaims(map)`](ds:block?id=oauthprovider-scopeclaims-ukr5yn84) | OpenID Connect Core 5.4 | Which scope releases which built-in claim; nil is the default, an empty map releases none by scope |
| `ValidateRedirectURI(fn)`, `ValidatePostLogoutRedirectURI(fn)` | exact match | Widen or narrow the redirect match at authorize and end-session; an accepted URI must still be absolute with no fragment or credentials |
| [`OnTokenEvent(fn)`](ds:block?id=oauthprovider-ontokenevent-kzgnhsu3) | none | Every issuance after its commit and every revocation with its reason; never sees a token |
| [`BackchannelDelivery(fn)`](ds:block?id=oauthprovider-backchanneldelivery-cxz4bac5), `BackchannelHTTPClient(c)` | one POST, no redirects, no retry | How signed logout tokens are delivered (queue, retry, outbox) |
| [`RenderPage(fn)`](ds:block?id=oauthprovider-renderpage-rmzvn2hv) | built-in English pages | The error, logout confirmation and logged-out pages |
| `SelectAccount(g)`, `PostLogin(g)`, `SignupRedirect(fn)` | none | Gates between sign-in and consent |
| `RequestURIResolver(fn)` | `request_uri` not supported | Pushed or stored authorization requests |
| `ClientPrivileges(fn)`, `ClientReference(fn)` | the owning user | Who manages a client, and whether clients belong to an organization |
| `ValidateInitialAccessToken(fn)` | a presented token is refused | Registration with an initial access token |
| `IdentifierValidator(fn)` | RFC 8707 check | What counts as a resource identifier |
| `CIMDFetch(f)`, `CIMDTransport(fn)`, `CIMDAllow(fn)`, `CIMDOnClientCreated(fn)`, `CIMDOnClientRefreshed(fn)`, `ClientJWKSFetch(f)` | public-address fetchers, every URL allowed | How client documents and key sets are fetched, and which are allowed |
| `WithGrant(g)`, `Extend(...)`, `DeviceAuthorizationEndpoint(url)` | none | Extension grants, extensions, the device flow's endpoint |
| `HashStoredSecrets(fn)`, `FormatRefreshToken(f)`, `GenerateAccessToken(fn)`, `GenerateRefreshToken(fn)`, `GenerateClientID(fn)`, `GenerateClientSecret(fn)` | SHA-256, built-in formats and generators | The stored form of secrets and the shape of tokens and ids |
| [`WithStore(s)`](ds:block?id=oauthprovider-withstore-3nd8kv5q) | the plugin's tables on `auth.WithDB` | Where clients, codes, tokens and consents live (Redis, another database, your own); `storetest.Run` checks a store's contract, races included, and the SQL store passes it on every engine. See [a custom store](../plugins/oauthprovider.md#a-custom-store) |
| `Signer` passed to `New` | the jwt plugin | Signing keys, in a KMS or HSM |
| an `auth.OperationHook` on `EndpointToken`, `EndpointRevoke`, `EndpointEndSession` | none | Refuse any provider operation before it runs, from every transport |

A rotated refresh token or a spent code presented again also reaches the core's security stream as `auth.SecurityTokenReplay` when the app registered a sink.

### Endpoints, scopes, clients and registration

| Option | Default | Empty means | What it decides |
|---|---|---|---|
| `Issuer(url)`, `LoginPage(url)` | required | refused | The provider's identifier and where a browser signs in |
| `BasePath(path)` | [`/oauth2`](ds:block?id=oauthprovider-defaultbasepath-p2v6mz9c) | | Where the protocol endpoints live |
| `ConsentPage(url)`, `SignupPage(url)` | none: `consent_required`; `prompt=create` goes to the login page | | The consent and sign-up pages |
| `Scopes(...)`, `AdvertisedScopes(...)`, `AdvertisedClaims(...)` | [`openid profile email offline_access`](ds:block?id=oauthprovider-defaultscopes-k3n8vq2m); every scope served; the claims the provider releases | | Supported and advertised scopes and claims; without `openid` it is a plain OAuth 2.1 server |
| `GrantTypes(...)` | [`authorization_code`, `client_credentials`, `refresh_token`](ds:block?id=oauthprovider-defaultgranttypes-w7p2xk4n) | | Which grants are served |
| `ProtectedResource(url, scopes...)`, `EnforcePerClientResources(on)`, `RegistrationDefaultResources(...)`, `RegistrationAllowedResources(...)` | none; on; none; none | | Resource servers and which client may ask for which |
| `AllowDynamicRegistration()`, `AllowUnauthenticatedRegistration()`, `MCP()` | off | | RFC 7591 registration, for signed-in users or anyone; `MCP()` also sets a 30-second reuse window |
| `RegistrationRequirePKCE(on)`, `RegistrationDefaultScopes(...)`, `RegistrationAllowedScopes(...)` | PKCE required; every scope | nil: every scope | What a registered client gets |
| `TrustedClients(...)`, `ClientIDMetadataDocuments(...)`, `PairwiseSecret(s)` | none, off, off | | Clients in code, URL client ids, pairwise subjects |
| `AllowPublicClientPrelogin()` | off | | A login page that reads the client before sign-in |

### Opt-ins that relax a default

Each is off by default; `auth.New` logs a warning while the first four are on.

| Option | What it relaxes |
|---|---|
| `RevokeAccessTokenOnly()` | Revoking an access token keeps its refresh token |
| `RefuseJWTRevocation()` | A still-valid JWT access token is not revoked (it stays usable by offline verifiers) |
| `EncryptClientSecrets(e)` | Client secrets are also stored encrypted, so they can be read back |
| `RefreshReplay(e)` | A reuse inside `RefreshReuseInterval` answers the first response again, stored encrypted until the window ends |
| `UserInfoInsufficientScope()`, `SelectAccountFallsBackToLogin()` | Interoperability answers: 403 instead of 400 at userinfo, the login page for `prompt=select_account` |

### Fixed in the provider

| Rule | Why it is not an option |
|---|---|
| PKCE uses S256 only, and is required for public clients and for a refresh token unless a confidential client sends `openid` with a nonce | `plain` sends the verifier through the browser; nothing else proves the token request comes from whoever started the flow (OAuth 2.1) |
| A code works once, and its reuse revokes what it issued | RFC 6749 section 4.1.2; a second use means a stolen code |
| A refresh token always rotates, and reuse outside `RefreshReuseInterval` revokes the family | OAuth 2.1 section 4.3.1; the interval is the supported relaxation |
| No "never expires" for codes, access tokens, ID tokens or refresh tokens | Each needs an `exp`; `MaxAuthAge` 0 and a long `RefreshTokenTTL` cover long-lived access. A refresh token that never expired would keep every rotated row forever, since reuse detection needs them |
| A redirect URI matches exactly (any port on a loopback IP) | RFC 9700 section 4.1.3; `ValidateRedirectURI` is the escape hatch |
| `client_credentials` never carries `openid`, `profile`, `email` or `offline_access` | There is no user behind the token |
| `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `azp`, `at_hash` and the other protected claims are the provider's | They make an ID token valid for this issuer and request |
| `state` at most 1024 bytes, `nonce` 512 | Both are echoed into URLs or signed into tokens |
| Plugin cookie attributes (`HttpOnly`, `Secure`, `SameSite`) | The core owns them for every plugin; the name prefix and domain are core options |
| Token prefixes `uboa_`, `ubor_`, `uboc_`, `ubos_` | Secret scanners key on them; the generators and `FormatRefreshToken` change the rest |
| A store's single use, rotation and family revoke are one atomic method each (`RedeemCode`, `RotateRefresh`, `RevokeTokens`) | The provider never builds them from a read and a write, so no store can break them by accident; `storetest.Run` pins each with racing callers. Where the state lives is `WithStore` (see Hooks and seams) |
| The resource registry and the `private_key_jwt` and DPoP replay caches stay on `auth.WithDB` | Operator configuration and short-lived replay records; the provider needs the app's database for users anyway |

## Where 0 is refused

These limits refuse 0 (and anything below their minimum) at start-up instead of treating it as "off", because "off" would remove a protection, not a convenience:

| Option | Why 0 is not "off" |
|---|---|
| `EndSessionConfirmTTL` | A confirmation that never expires would let a page posted long ago end a later session; 0 would delete the cookie at once |
| `BackchannelLogoutTokenTTL` | Back-Channel Logout requires an `exp`; an unbounded one widens the window for a replayed token |
| `MaxRequestBytes` | An unbounded body lets one request hold the server's memory |
| `ClientJWKSCacheTTL`, `ClientJWKSFetchLimits`, `CIMDFetchLimits`, `CIMDRevalidate` | The provider fetches URLs that callers choose; no cache, no timeout or no size cap lets any caller hold or hammer it |
| `CodeTTL`, `AccessTokenTTL`, `RefreshTokenTTL`, `IDTokenTTL`, `AssertionMaxLifetime`, `DPoPProofMaxAge` | Each is a token's or proof's expiry; "never" is not offered (see [fixed](#fixed-in-the-provider)) |
| Clients: `WithFlowLifetime` / `flowLifetimeMs` | A sign-in that never expires is a flow cookie that never goes away |
| Clients: `WithClockSkew` / `clockSkewMs` above 5 minutes | An expired ID token would be accepted that much longer |
| TypeScript client: `httpTimeoutMs` of 0 | A request to the login server with no bound would hold the app's request as long as the server hangs; in Go the `http.Client` you pass decides |
| TypeScript client: `lifetimes` of 0 | `Number("")` is 0, so an empty environment variable would silently remove the cap; `NO_LIMIT` says it on purpose |

A few options that existed before this rule keep 0 as "the default" rather than "off": a zero `oidcclient.Lifetimes` field, `M2MAccessTokenTTL`, `CacheResources`, `CIMDMaxCacheEntries`, the `CIMDPolicy` fields and `ResourceGuard.Leeway`. Changing them would change what existing configurations do.

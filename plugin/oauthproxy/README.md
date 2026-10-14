# oauthproxy

Sign in with a provider on preview and development deployments through the one callback URL registered at the provider, better-auth's `oauth-proxy` plugin. A provider console takes a fixed list of redirect URLs; a preview deployment gets a new URL on every push. With this plugin the console lists only production's callback, and every deployment signs in.

The module also holds [`oauthpopup`](oauthpopup), the popup sign-in for apps embedded on another site.

```go
proxy := oauthproxy.New(
	oauthproxy.ProductionURL("https://app.example.com"),
	oauthproxy.WithSecret(sharedSecret), // the same on every deployment
)
a, err := auth.New(auth.WithBaseURL(os.Getenv("BASE_URL")), auth.WithSecret(appSecret),
	auth.WithTrustedOrigins("https://*.preview.example.com"), // production relays only to trusted origins
	auth.WithPlugins(oauth.New(oauth.WithProviders(proxy.Wrap(oauth.Google(id, secret)))), proxy))
```

Deploy the same code, the same provider credentials and the same proxy secret everywhere; only `BASE_URL` differs. Register `https://app.example.com/auth/oauth/google/callback` at the provider and nothing else.

## How it works

1. On a preview, the wrapped provider's authorization URL carries production's callback as `redirect_uri` and, as `state`, a sealed package naming the preview's own state and callback.
2. Production's oauth callback sees the package (a Before hook on `oauth.CallbackEndpoint(provider)`), checks that the preview's callback is on a trusted origin and that the package is fresh, and redirects the browser to the preview's callback with the preview's state and the authorization code sealed for it. Production exchanges nothing and writes nothing; a callback whose state is not a package is production's own sign-in and runs as usual.
3. The preview's own oauth callback runs unchanged: flow cookie, state, `ValidateProfile`, linking, sign-up rules, `StoreTokens`. The wrapped provider opens the sealed code and exchanges it with the provider itself, using production's `redirect_uri` and the PKCE verifier that never left the preview. The user and session are created in the preview's database.

By default what travels between deployments is an authorization code, never a profile (`PassProfile` below is the opt-in exception). It is sealed with AES-256-GCM under a key derived from the shared secret, bound to the provider and the preview's callback, accepted for `MaxAge` (60 seconds, with 10 seconds of clock skew), and useless without the PKCE verifier only the preview holds. A holder of the proxy secret can therefore relay codes but cannot make a deployment accept an identity the provider did not assert, which better-auth's encrypted-profile design allows.

## Options

| Option | Default | better-auth |
|---|---|---|
| `ProductionURL(u)` | required | `productionURL` |
| `WithSecret(current, previous...)` | the app's `auth.WithSecret` | `secret` |
| `MaxAge(d)` | 60 seconds | `maxAge` |
| `ProductionCallback(fn)` | the preview callback's path on the production origin | the shared `basePath` assumption |
| `PassProfile()` | off: production relays the sealed code | the encrypted-profile passthrough (see below) |
| `HTTPClient(hc)` | 10-second timeout, no redirect followed | production's exchange client under `PassProfile` |

A sealed state lives `StateMaxAge` (10 minutes, the person signs in at the provider meanwhile). Keys are derived per purpose (`oauthproxy-state`, `oauthproxy-code`), so a state never opens as a code. Previous secrets still open values sealed under them, for rotation.

## Opt-in: profile passthrough

`PassProfile()` is better-auth's design, for deployments where only production can exchange a code. The preview seals a fresh PKCE verifier into the state and sends the provider its challenge; production exchanges the code with it and its own callback, and relays the profile (claims and the provider's tokens included) sealed under the `oauthproxy-profile` key, prefixed `oxp1p.`, bound to the provider and the preview callback, valid `MaxAge`. The preview's own callback checks the flow cookie and state, then opens the profile instead of exchanging; a start with `X-Skip-OAuth-Proxy` still exchanges its own code. A refused exchange is relayed as `error=invalid_code` (`RelayErrorInvalidCode`); a relay with no profile is `ErrMissingProfile` (better-auth's `missing_profile`), logged and answered `oauth.provider_failed`. Turn it on on every deployment: a production without it refuses a state that asks for an exchange, a preview without it never opens a profile.

Risk: whoever holds the proxy secret can then make a preview accept any identity. `Init` logs `WarnPassProfile` at every start.

## Errors

| Code | Where | When |
|---|---|---|
| `oauthproxy.invalid_state` | production callback | the package does not open, is too old, names another provider, or names an untrusted or relative callback |
| `oauthproxy.invalid_code` | preview exchange | the relayed code does not open, is too old, or is bound to another provider or callback; the oauth callback answers `oauth.provider_failed` |

## Limits

- A wrapped provider forwards discovery, the issuer check (production relays `iss`), request parameters, form posts (Apple), refresh, revoke, profile reads and logout. ID-token sign-in and provider-initiated flows are not proxied, so a wrapped provider does not offer them.
- The proxy decides by comparing the callback URL with `ProductionURL`; a start request carrying `X-Skip-OAuth-Proxy` (`oauthproxy.SkipHeader`, any value) is not proxied, through the oauth plugin's `RequestAuthURLer` hook, and its code, arriving unsealed, is exchanged with the deployment's own callback.
- `DeploymentURL(os.Getenv, fallback)` infers a preview's base URL from its host (`VERCEL_URL`, `NETLIFY_URL`, `RENDER_URL`, and the function-name variables better-auth reads), for `auth.WithBaseURL`.
- Every participating deployment must run a compatible version: the sealed formats are versioned (`oxp1.`), and an in-flight sign-in across an upgrade starts again.

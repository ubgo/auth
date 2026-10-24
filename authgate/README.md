# github.com/ubgo/auth/authgate

A login gate, not user accounts: sign in with any OAuth 2.0 or OpenID Connect provider and keep the person's profile in a sealed cookie. No database, no user table, no `auth.New`.

For an internal tool behind company login, a prototype, a tool acting on the person's GitHub or Google account, or a serverless function with nowhere to keep rows. The guide with a full walkthrough is [docs/integrations/login-gate.md](../docs/integrations/login-gate.md); the runnable example is [examples/login-gate](../examples/login-gate).

## What it does not do

No per-device sign-out, no passwords or second factors of its own, no bans, no admin, no user list, no account linking. Revocation is all or nothing: raise `SessionVersion` (or drop a secret) and everyone signs in again; each cookie also expires at an absolute time. When you need any of that, use `auth.New` with `plugin/oauth`; the same provider values work there.

## Install

```sh
go get github.com/ubgo/auth
```

It is in the core module and uses only the standard library, `plugin/oauth`'s providers and `authhttp`'s error writer.

## Wire it

<!-- ds:block id=logingate-newgate-5wn8qk3t -->
**newGate** · [`examples/login-gate/main.go:84-118`](../examples/login-gate/main.go#L84-L118)

```go
func newGate(getenv func(string) string) (*authgate.Gate, error) {
	var providers []oauth.Provider
	if id, secret := getenv(envGoogleID), getenv(envGoogleSecret); id != "" && secret != "" {
		providers = append(providers, oauth.Google(id, secret))
	}
	if iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret); iss != "" && id != "" && secret != "" {
		providers = append(providers, oauth.OIDC(oidcProviderName, iss, id, secret))
	}
	if len(providers) == 0 {
		return nil, errNoProvider
	}
	domain := getenv(envAllowedDomain)
	if domain == "" {
		return nil, errNoDomain
	}
	version := uint64(0)
	if v := getenv(envSessionVersion); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envSessionVersion, err)
		}
		version = n
	}
	g, err := authgate.New(
		authgate.WithProviders(providers...),
		authgate.WithSecret([]byte(getenv(envSecret))),
		authgate.WithBaseURL(baseURL),
		authgate.AllowEmailDomain(domain),
		authgate.SessionVersion(version),
	)
	if errors.Is(err, auth.ErrSecretTooShort) {
		return nil, fmt.Errorf("set %s to at least %d bytes, such as the output of openssl rand -base64 32: %w", envSecret, auth.MinSecretSize, err)
	}
	return g, err
}
```
<!-- /ds:block hash=89e8d8 -->

<!-- ds:block id=logingate-newhandler-8tq2vm6r -->
**newHandler** · [`examples/login-gate/main.go:124-129`](../examples/login-gate/main.go#L124-L129)

```go
func newHandler(g *authgate.Gate) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", g.Handler())
	mux.Handle("/{$}", g.RequireUser(http.HandlerFunc(dashboard)))
	return mux
}
```
<!-- /ds:block hash=35e6c7 -->

## Options

| Option | Default | What it does |
|---|---|---|
| `WithProviders(ps ...oauth.Provider)` | required | the providers: `oauth.Google`, `oauth.GitHub`, a preset, `oauth.OIDC`, or your own `oauth.Provider`; each passes `oauth.ValidateProvider` |
| `WithSecret(current, previous...)` | required | at least 32 bytes; the cookie keys are derived with `auth.DeriveSecretKeys` under `auth.KeyLabelAuthGate`; previous secrets still open |
| `WithBaseURL(origin)` | required | the public origin, http or https, no path; the callback is origin + prefix + `/{provider}/callback` |
| `Allow(func(Profile) bool)` | one rule required | admits a profile; any rule admitting is enough; rechecked on every request, so keep it cheap and offline |
| `AllowEmailDomain(domains...)` | | a verified address at exactly one of the domains, case-blind |
| `AllowEmails(addrs...)` | | a verified address that is one of addrs, case-blind |
| `AllowAnyone()` | | every account the providers sign in |
| `SessionLifetime(d)` | 7 days | absolute; never extended by activity |
| `SessionVersion(n)` | 0 | only cookies stamped with n open; raise it to sign everyone out |
| `KeepTokens()` | off | keep access and refresh token, expiry and scope in the cookie (`Profile.Tokens`) |
| `Prefix(path)` | `/auth` | where `Handler` is mounted |
| `SignInPage(path)` | the only provider's start | where `RequireUser` sends a browser that is not signed in; with several providers and none set, 401 |
| `ErrorHandler(fn)` | JSON error body | render errors as your own page |
| `WithHTTPClient(hc)` | 10 s timeout | the client that reaches the providers |
| `WithLogger(l)` | `slog.Default()` | refused sign-ins (Info), provider failures (Warn), oversized cookies (Error) |
| `WithClock(now)` | `time.Now` | tests |

The limits are constants: [`DefaultSessionLifetime`, `FlowLifetime`, `MaxCookieSize`, `MaxReturnToLength`](ds:block?id=authgate-defaults-7pm2wn4q).

## Routes

| Method and path | What it does |
|---|---|
| `GET {prefix}/{provider}/start?returnTo=/path` | seals state, PKCE verifier and return path into the flow cookie; redirects to the provider |
| `GET {prefix}/{provider}/callback` | checks state and issuer, exchanges the code, applies the rules, writes the session cookie, redirects to the return path |
| `POST {prefix}/{provider}/callback` | form-post providers only: relays to the GET callback |
| `POST {prefix}/sign-out?returnTo=/path` | clears the session cookie; refuses another site's post |
| `GET {prefix}/session` | the profile as JSON (tokens never included), or 401 |

`Middleware` puts the profile in the request context; `RequireUser` also refuses anyone without one (a browser navigation is redirected to sign in, anything else gets 401). Read it with `CurrentProfile(r)` or `ProfileFrom(ctx)`. `Profile.ID()` is `provider:subject`, the stable key for your own data.

## Cookies

[`__Host-authgate_session` and `__Host-authgate_flow`](ds:block?id=authgate-cookienames-3vx8kq2m): `HttpOnly`, `Secure`, `Path=/`, no `Domain`, `SameSite=Lax`. Each is AES-256-GCM sealed under its own purpose, so a flow cookie never opens as a session. A session over 4096 bytes (name, value and attributes) is refused with `authgate.cookie_too_large` instead of written.

## Errors

[The declarations](ds:block?id=authgate-errors-6tq3vm8w): `authgate.not_allowed` (403), `authgate.cookie_too_large` (500), `authgate.bad_return_to` (400), `authgate.unknown_provider` (404), `authgate.cross_site` (403), `authgate.method_not_allowed` (405), plus `plugin/oauth`'s `oauth.state_invalid`, `oauth.denied` and `oauth.provider_failed`, and `auth.signed_out` (401).

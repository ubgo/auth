# Sign in on preview deployments with one registered callback

You will let every preview and development deployment sign in with Google, GitHub or any other provider while the provider's console lists only production's callback URL. This is better-auth's `oauth-proxy` plugin, built so that what travels between deployments is a sealed authorization code rather than a profile.

Use it when your host gives each pull request its own URL (Vercel, Netlify, Render, Fly) and you do not want to register every one at every provider.

## Before you start

- An app signing in with the [oauth plugin](oauth.md) in production.
- The module: `go get github.com/ubgo/auth/plugin/oauthproxy`. It depends on the core only.
- A proxy secret of at least 32 bytes, the same on every deployment. Keep it out of deployments built from untrusted contributors' branches.
- The reference for every option and error is the package's [README](../../plugin/oauthproxy/README.md).
- The runnable program is [`examples/oauth-preview`](../../examples/oauth-preview/): one binary for production and every preview. Its tests run production and a preview side by side against a fake OpenID Connect provider that accepts only production's callback.

## Step 1 — Wrap the providers and register the plugin

The same code runs on every deployment; only the base URL differs:

<!-- ds:block id=oauthpreview-newauth-c9v4mt2q -->
**newAuth** · [`examples/oauth-preview/main.go:141-152`](../../examples/oauth-preview/main.go#L141-L152)

```go
func newAuth(db *sql.DB, d deployment) (*auth.Auth, error) {
	proxy := oauthproxy.New(oauthproxy.ProductionURL(d.ProductionURL), oauthproxy.WithSecret(d.ProxySecret))
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(d.BaseURL),
		auth.WithTrustedOrigins(d.PreviewOrigins...),
		auth.WithPlugins(
			oauth.New(oauth.WithProviders(proxy.Wrap(d.Provider))),
			proxy,
		),
	)
}
```
<!-- /ds:block hash=13b990 -->

On a preview, `oauthproxy.DeploymentURL(os.Getenv, fallback)` reads the URL your host sets (`VERCEL_URL`, `NETLIFY_URL`, `RENDER_URL`, …) for `auth.WithBaseURL`; the example reads every setting in one place:

<!-- ds:block id=oauthpreview-deploymentfromenv-r5n2kx8w -->
**deploymentFromEnv** · [`examples/oauth-preview/main.go:111-133`](../../examples/oauth-preview/main.go#L111-L133)

```go
func deploymentFromEnv(getenv func(string) string) (deployment, error) {
	d := deployment{
		BaseURL:       oauthproxy.DeploymentURL(getenv, cmp.Or(getenv(envBaseURL), localURL)),
		ProductionURL: getenv(envProductionURL),
		ProxySecret:   []byte(getenv(envProxySecret)),
	}
	for _, o := range strings.Split(getenv(envPreviewOrigins), ",") {
		if o = strings.TrimSpace(o); o != "" {
			d.PreviewOrigins = append(d.PreviewOrigins, o)
		}
	}
	iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret)
	switch {
	case d.ProductionURL == "":
		return d, fmt.Errorf("%w: set %s", errConfig, envProductionURL)
	case len(d.ProxySecret) < minProxySecret:
		return d, fmt.Errorf("%w: %s must be at least %d bytes", errConfig, envProxySecret, minProxySecret)
	case iss == "" || id == "" || secret == "":
		return d, fmt.Errorf("%w: set %s, %s and %s", errConfig, envOIDCIssuer, envOIDCID, envOIDCSecret)
	}
	d.Provider = oauth.OIDC(providerName, iss, id, secret)
	return d, nil
}
```
<!-- /ds:block hash=b88fdd -->

 `Wrap` is the whole integration:

<!-- ds:block id=oauthproxy-plugin-wrap-6q3vn8kw -->
**Plugin.Wrap** · [`plugin/oauthproxy/provider.go:29-34`](../../plugin/oauthproxy/provider.go#L29-L34)

```go
func (p *Plugin) Wrap(prov oauth.Provider) *Proxied {
	p.wrapped = append(p.wrapped, prov.Name())
	x := &Proxied{inner: prov, p: p}
	p.providers[prov.Name()] = x
	return x
}
```
<!-- /ds:block hash=60c395 -->

On production (the callback URL is on `ProductionURL`'s origin) a wrapped provider is the provider itself. Production relays only to origins it trusts, so list the preview origins in `auth.WithTrustedOrigins`; a wildcard covers a host's generated subdomains.

## Step 2 — Register only production's callback

At the provider, the redirect URL list holds `https://app.example.com/auth/oauth/google/callback` and nothing else. Deploy a preview and open its sign-in link: the browser goes to the provider with production's callback, comes back to production, is redirected straight to the preview's callback, and lands signed in on the preview.

Check: production's database gains no user and no session for a preview sign-in; the preview's does. `TestPreview_SignsInThroughProductionsCallback` in the example asserts exactly that, and that production exchanged no code; `TestPreview_ProductionSignsInDirectly` and `TestPreview_ProductionRefusesWhatItDoesNotTrust` cover production's own sign-in, an untrusted origin and a different secret.

## Try it

A preview needs a host and a registered provider, so the example's tests are the transcript, run against a fake provider on `httptest`:

```sh
cd examples && go test -v ./oauth-preview
```

```text
=== RUN   TestPreview_SignsInThroughProductionsCallback
--- PASS: TestPreview_SignsInThroughProductionsCallback (0.04s)
=== RUN   TestPreview_ProductionSignsInDirectly
--- PASS: TestPreview_ProductionSignsInDirectly (0.02s)
=== RUN   TestPreview_ProductionRefusesWhatItDoesNotTrust
--- PASS: TestPreview_ProductionRefusesWhatItDoesNotTrust (0.03s)
=== RUN   TestDeploymentFromEnv
--- PASS: TestDeploymentFromEnv (0.00s)
PASS
ok  	github.com/ubgo/auth/examples/oauth-preview	1.061s
```

## What protects the relay

- The state production receives is sealed (AES-256-GCM, a key derived from the proxy secret for this purpose only) and names the preview's callback; production refuses a package that does not open, is older than ten minutes, names another provider, or names an origin it does not trust (`oauthproxy.invalid_state`).
- The code production relays is sealed for that preview callback and provider and accepted for [60 seconds](ds:block?id=oauthproxy-defaultmaxage-4k8wq2nv) (`MaxAge`).
- The preview exchanges the code itself with the PKCE verifier it never sent anywhere, so a code caught on the way is useless, and the preview's own oauth callback still checks the flow cookie, the state and every rule you configured.
- Production exchanges no code and writes nothing for a relayed sign-in (unless you opt in to `PassProfile`, below).

## From TypeScript

Nothing changes in the [typed client](../client/README.md). The proxy wraps the oauth plugin's providers on the server: a preview deployment's sign-in is still a page navigation to its own `/auth/oauth/<provider>/start` route ([Flows › OAuth](../client/flows.md#oauth-continue-with-google)), the relay through production happens in redirects the browser follows, and the session lands on the preview's own origin as on any deployment. The plugin adds no route that a page calls, so it has no factory; `client.oauth.providers()` still lists the buttons to draw.

Pitfalls:

- **Never `fetch` the start route.** It answers with a redirect to the provider (here, through production), which `fetch` cannot follow to another site; assign `location` instead.
- **The preview's `baseURL` is its own origin.** A preview page that points its client at production's `/auth` signs the user in on production, not on the preview.

## What can go wrong

| Answer | When | Fix |
|---|---|---|
| `oauthproxy.invalid_state` (400) at production | The preview's origin is not trusted, the secrets differ, or the sign-in took over ten minutes. | Add the origin to `WithTrustedOrigins`; deploy the same secret. |
| `oauth.provider_failed` at the preview | The relayed code was older than `MaxAge`, or the provider refused the exchange (a different client secret on the preview). | Start again; deploy the same provider credentials. |
| `redirect_uri_mismatch` at the provider | Production's callback is not registered, or the preview mounts the routes elsewhere. | Register it; set `ProductionCallback` if the paths differ. |

A start request with the [`X-Skip-OAuth-Proxy`](ds:block?id=oauthproxy-skipheader-7q4mn2xv) header is not proxied, for a preview whose callback the provider does list.

Known limits: ID-token sign-in and provider-initiated flows are not proxied.

## Opt-in: better-auth's profile passthrough

[`oauthproxy.PassProfile()`](ds:block?id=oauthproxy-passprofile-p3r2mx8v), on every participating deployment, switches to better-auth's own design: the preview seals a fresh PKCE verifier into the state (and sends the provider its challenge instead of the oauth plugin's), production exchanges the code itself with its own `redirect_uri` and that verifier, and relays the profile (subject, email, verified flag, name, image, raw claims and the provider's access, refresh and ID tokens, so `StoreTokens` works on the preview) sealed for the preview's callback and provider, accepted for `MaxAge`. The preview's ordinary oauth callback is better-auth's `/callback/:id/oauth-proxy` completion: it checks the flow cookie and state first (so a relay works once), opens the profile instead of exchanging, and signs in with every rule you configured. A refused exchange at production is relayed as `error=invalid_code` ([`RelayErrorInvalidCode`](ds:block?id=oauthproxy-relayerrorinvalidcode-p3r2kq7m)) and lands on the flow's error page; a relay with neither profile nor error is better-auth's `missing_profile` (`oauthproxy.ErrMissingProfile`, logged, answered `oauth.provider_failed`). Production's exchange uses `oauthproxy.HTTPClient(hc)` or a default client with a [10-second](ds:block?id=oauthproxy-defaultexchangetimeout-p3r2tq5d) timeout that follows no redirect.

Risk, and why it is off: a deployment that accepts a sealed profile trusts whoever holds the proxy secret to say who signed in, which the default relay never does. `Init` logs [`WarnPassProfile`](ds:block?id=oauthproxy-warnpassprofile-p3r2wn4x) at every start. Use it only when production alone can exchange a code (a client secret only production holds), and keep the proxy secret as tightly as the provider's. A production without `PassProfile` refuses a state that asks it to exchange (`oauthproxy.invalid_state`), and a preview without it never opens a profile.

## Next

- [OAuth](oauth.md): the providers and rules the preview's callback applies.
- [Popup sign-in](oauthpopup.md): the other browser-flow companion in this module.

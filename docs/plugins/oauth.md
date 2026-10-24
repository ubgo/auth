# OAuth: sign in with Google, GitHub or any OpenID Connect issuer

You will have "Sign in with Google" and "Sign in with GitHub" (or Okta, Auth0, Keycloak, Entra ID, Zitadel, or anything else that speaks OpenID Connect) next to your existing sign-in, with accounts linked safely to users who already exist, a settings page that links and unlinks providers, and, if you need it, the provider's tokens kept so your app can call its API for the user later.

## Before you start

- [Install](../start/install.md) and [First app](../start/first-app.md): an app with `auth.New`, a database and the HTTP handler mounted at `/auth`.
- The plugin is `github.com/ubgo/auth/plugin/oauth`, in the core module, so there is nothing extra to `go get`. Its README is the [reference](../../plugin/oauth/README.md) for every option, route, column and error.
- Four runnable programs back this guide. [`examples/oauth`](../../examples/oauth/) signs in with GitHub, Google or an OIDC issuer from environment variables. [`examples/oauth-link-and-tokens`](../../examples/oauth-link-and-tokens/) runs a small OpenID Connect issuer in the same process, so linking, unlinking and stored tokens can be tried with curl and no provider account; its transcript is the one in Steps 4 to 7. [`examples/oauth-native`](../../examples/oauth-native/) runs an issuer that signs ID tokens, for Steps 8 to 10: sign-in from a native app, the error page, flow data and the provider logout. [`examples/oauth-providers`](../../examples/oauth-providers/) is Steps 12, 14 and 15: a hand-written provider, a goth one, a broken issuer and explicit sign-up, tested against fake providers on `httptest`.
- The flow in one paragraph: the browser opens `/auth/oauth/<provider>/start`, which redirects to the provider with a PKCE challenge and a single-use `state`, and binds that state to the browser in a cookie. The provider sends the browser back to `/auth/oauth/<provider>/callback?code=…&state=…`. The callback checks the state against the cookie, trades the code for the person's profile, finds or creates the user, issues a session and redirects to `returnTo`. Nothing in that dance is signed by the app; the state row in the database and the cookie are what tie it together.

## Step 1 — Register the app at the provider

Every provider asks for a redirect URL (also called a callback URL or redirect URI) and gives back a client id and a client secret. The URL the plugin uses is your base URL plus [`/auth`](ds:block?id=defaultmountprefix-4xrrxrkb) plus `/oauth/<provider>/callback`, where `<provider>` is the route segment in the table below. Register exactly that string; providers compare it byte for byte.

| Provider | Where | Route segment | Redirect URL to register | Scopes the plugin asks for |
|---|---|---|---|---|
| Google | Google Cloud console, APIs & Services, Credentials, Create credentials, OAuth client ID, type Web application, "Authorized redirect URIs" | `google` | `https://app.example.com/auth/oauth/google/callback` | `openid email profile` |
| GitHub | Settings, Developer settings, OAuth Apps, New OAuth App, "Authorization callback URL" | `github` | `https://app.example.com/auth/oauth/github/callback` | `read:user user:email` |
| An OpenID Connect issuer | The issuer's admin console: create a confidential web client, add the redirect URI, note the issuer URL | the name you give `oauth.OIDC` | `https://app.example.com/auth/oauth/<name>/callback` | `openid email profile` |

The plugin reads no environment variables; how the client id and secret reach your program is your choice. `examples/oauth` reads `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and offers only the providers whose variables are all set:

<!-- ds:block id=providersfromenv-tyx5rn7w -->
**providersFromEnv** · [`examples/oauth/main.go:122-134`](../../examples/oauth/main.go#L122-L134)

```go
func providersFromEnv(getenv func(string) string) []oauth.Provider {
	var out []oauth.Provider
	if id, secret := getenv(envGitHubID), getenv(envGitHubSecret); id != "" && secret != "" {
		out = append(out, oauth.GitHub(id, secret))
	}
	if id, secret := getenv(envGoogleID), getenv(envGoogleSecret); id != "" && secret != "" {
		out = append(out, oauth.Google(id, secret))
	}
	if iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret); iss != "" && id != "" && secret != "" {
		out = append(out, oauth.OIDC(oidcProviderName, iss, id, secret))
	}
	return out
}
```
<!-- /ds:block hash=c5d0f5 -->

The callback URL the plugin builds, spelled out so the program can print it at start:

<!-- ds:block id=callbackurl-k2jdtdxn -->
**callbackURL** · [`examples/oauth/main.go:140-142`](../../examples/oauth/main.go#L140-L142)

```go
func callbackURL(provider string) string {
	return baseURL + authPrefix + "/" + oauth.PluginName + "/" + provider + "/callback"
}
```
<!-- /ds:block hash=bdce26 -->
<!-- /ds:block --> Providers accept a plain `http://localhost` redirect URL for development only; production is HTTPS, and the session cookie requires it anyway.

Check: the provider console shows the redirect URL with the right scheme, host, port and path, and no trailing slash.

## Step 2 — Wire the plugin

Pass the providers to `oauth.New`. The constructors are one line each:

<!-- ds:block id=google-gp5b6e58 -->
**Google** · [`plugin/oauth/provider.go:928-934`](../../plugin/oauth/provider.go#L928-L934)

```go
func Google(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "google", DisplayName: "Google", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: GoogleAuthURL, TokenURL: GoogleTokenURL, Scopes: openIDScopes(),
		FetchProfile: GoogleProfile(GoogleUserInfoURL),
	}
}
```
<!-- /ds:block hash=c8822c -->

<!-- ds:block id=github-xhq2md6c -->
**GitHub** · [`plugin/oauth/provider.go:1018-1024`](../../plugin/oauth/provider.go#L1018-L1024)

```go
func GitHub(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "github", DisplayName: "GitHub", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: GitHubAuthURL, TokenURL: GitHubTokenURL, Scopes: []string{"read:user", "user:email"},
		FetchProfile: GitHubProfile(GitHubAPIURL),
	}
}
```
<!-- /ds:block hash=f2d295 -->

<!-- ds:block id=oidc-eb7uu7dy -->
**OIDC** · [`plugin/oauth/oidc.go:152-155`](../../plugin/oauth/oidc.go#L152-L155)

```go
func OIDC(name, issuer, clientID, clientSecret string) *OIDCProvider {
	return &OIDCProvider{ID: name, Issuer: strings.TrimSuffix(issuer, "/"), ClientID: clientID, ClientSecret: clientSecret,
		Scopes: openIDScopes()}
}
```
<!-- /ds:block hash=a6d9d6 -->

The example wires one OpenID Connect provider named `corp` and keeps its tokens (Step 7); drop `oauth.StoreTokens` if you only need sign-in:

<!-- ds:block id=newoauth-8n39pfue -->
**newOAuth** · [`examples/oauth-link-and-tokens/main.go:146-151`](../../examples/oauth-link-and-tokens/main.go#L146-L151)

```go
func newOAuth(issuer string, key []byte) *oauth.Plugin {
	return oauth.New(
		oauth.WithProviders(oauth.OIDC(providerName, issuer, issuerClientID, issuerClientSecret)),
		oauth.StoreTokens(key),
	)
}
```
<!-- /ds:block hash=1ab790 -->

<!-- ds:block id=newauth-k25sawzu -->
**newAuth** · [`examples/oauth-link-and-tokens/main.go:156-166`](../../examples/oauth-link-and-tokens/main.go#L156-L166)

```go
func newAuth(db *sql.DB, m email.Mailer, oa *oauth.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oa,
		),
	)
}
```
<!-- /ds:block hash=521eb9 -->

`examples/oauth` wires the same three plugins with real providers:

<!-- ds:block id=newauth-rx9h4u84 -->
**newAuth** · [`examples/oauth/main.go:150-160`](../../examples/oauth/main.go#L150-L160)

```go
func newAuth(db *sql.DB, m email.Mailer, providers []oauth.Provider) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oauth.New(oauth.WithProviders(providers...)),
		),
	)
}
```
<!-- /ds:block hash=a63432 -->

The plugin works on its own, but the `email` plugin is what makes Step 5 possible: a provider that vouches for an address someone already verified signs in to that account instead of making a second one. `auth.WithBaseURL` is required unless you set `oauth.CallbackURL`, because the callback URL is built from it.

Check: `auth.New` returns no error. It refuses an empty provider list ("oauth: no providers"), a provider name that is not `^[a-z][a-z0-9_]{0,30}$`, a missing base URL ("oauth: callback URLs need auth.WithBaseURL or oauth.CallbackURL") and a `StoreTokens` key that is not 32 bytes ("oauth: StoreTokens needs a 32-byte key").

## Step 3 — Put a sign-in link on the page

The start route is a plain `GET`, so it is a link, not a form. `returnTo` is where the browser lands after sign-in: a path on your site, an absolute URL on an origin `auth.WithTrustedOrigins` lists, or a deep link back into a native app whose scheme is listed (`auth.WithTrustedOrigins("myapp://")`; see the [mobile apps guide](../integrations/mobile-apps.md)).

<!-- ds:block id=homepage-snyhvk6q -->
**homePage** · [`examples/oauth-link-and-tokens/main.go:182-187`](../../examples/oauth-link-and-tokens/main.go#L182-L187)

```go
var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<title>OAuth: link and tokens</title>
{{if .User}}<p>Signed in as {{.User}}.</p>
<p><a href="/auth/oauth/corp/start?link=true&returnTo=/tokens">Link corp</a> · <a href="/auth/oauth/accounts">Linked accounts</a> · <a href="/tokens">Provider tokens</a></p>
{{else}}<p><a href="/auth/oauth/corp/start?returnTo=/me">Sign in with corp</a></p>
{{end}}`))
```
<!-- /ds:block hash=069583 -->

The input the start route reads from the query string:

<!-- ds:block id=startrequest-q2z8uxqk -->
**StartRequest** · [`plugin/oauth/oauth.go:1339-1374`](../../plugin/oauth/oauth.go#L1339-L1374)

```go
type StartRequest struct {
	// ReturnTo is a path on this site to land on after sign-in.
	ReturnTo string `json:"returnTo,omitempty"`
	// Link, when LinkFlag, links the provider to the signed-in user instead
	// of signing in. A string because it arrives in a URL query.
	Link string `json:"link,omitempty"`
	// Prompt is forwarded to a ParamsProvider as the prompt parameter
	// (select_account, consent, login, none).
	Prompt string `json:"prompt,omitempty"`
	// LoginHint is forwarded as login_hint, to pre-fill the account.
	LoginHint string `json:"loginHint,omitempty"`
	// Scopes are extra scopes, space-separated, each listed in the
	// provider's OptionalScopes; for incremental authorization.
	Scopes string `json:"scopes,omitempty"`
	// Params are extra authorization parameters as a query string
	// ("display=popup&ui_locales=de"), each named in the provider's
	// OptionalParams (ErrBadParam otherwise). A string because it arrives in a
	// URL query; at most maxFlowDataLength characters.
	Params string `json:"params,omitempty"`
	// Data is carried through the flow untouched and handed back in
	// CallbackResult.Data: a referral code, an analytics source. At most
	// maxFlowDataLength characters. It comes from the client, so the app
	// treats it as untrusted input.
	Data string `json:"data,omitempty"`
	// ErrorTo is a path on this site a failed callback redirects to, with
	// the error code in the query; empty takes the plugin's ErrorURL. Without
	// either, a failed callback answers JSON.
	ErrorTo string `json:"errorTo,omitempty"`
	// NewUserTo is where a callback that created the user lands (an
	// onboarding page) instead of ReturnTo; same rules as ReturnTo.
	NewUserTo string `json:"newUserTo,omitempty"`
	// SignUp, when SignUpFlag, says the person meant to sign up, which
	// ExplicitSignUp requires before a user is created. A string because it
	// arrives in a URL query.
	SignUp string `json:"signUp,omitempty"`
}
```
<!-- /ds:block hash=285c82 -->

Check: `GET /auth/oauth/corp/start?returnTo=/me` answers `302` to the provider, with a `__Host-auth_flow` cookie. A `returnTo` that is neither a path nor a trusted origin (`https://evil.example`, `//evil.example`) answers `400 oauth.bad_return_to`.

A page that draws one button per provider need not hard-code the list: `GET /auth/oauth/providers` answers every configured provider's id (the route segment of its start link) and display name, in configuration order, and nothing secret: `{"providers":[{"id":"google","name":"Google"},{"id":"corp","name":"corp"}]}`. Every preset sets a display name (`Google`, `GitHub`, `Hugging Face`, `Amazon Cognito`, …); set `DisplayName` on your own `*oauth.OAuth2` or `*oauth.OIDCProvider` (`"Acme SSO"`), or the id is used. From Go, [`(*Plugin).Providers()`](ds:block?id=plugin-providers-q4wm8xkn) returns the same list.

The plugin also offers those buttons itself to pages that render sign-in methods, the ready-made [authui pages](../integrations/ready-made-pages.md) among them: it implements `authhttp.UIMethod`, and [`(*Plugin).SignInMethods()`](ds:block?id=oauth-signinmethods-8kd3wv5q) lists one `authhttp.SignInMethod` per provider in configuration order, with ID `oauth.<provider>`, Kind `oauth`, label "Continue with <display name>" and the provider's `GET` start route. A provider `SkipBrokenProviders` left out, or whose start operation `auth.WithDisabledOperations` switched off, gets no button. An app that wants another label passes its own method with the same ID to `authui.Methods`, which replaces the plugin's in place.

<!-- ds:block id=providerinfo-x2kt7wnq -->
**ProviderInfo** · [`plugin/oauth/display.go:24-27`](../../plugin/oauth/display.go#L24-L27)

```go
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
```
<!-- /ds:block hash=eeb08a -->

## Step 4 — Follow the flow once with curl

With `examples/oauth-link-and-tokens` running (`cd examples && go run ./oauth-link-and-tokens`), a person signs up with a password first, so the next step has an account to link to:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_mls7ilfozcgjpyjf5heput75","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Starting a flow sends the browser to the provider with the PKCE challenge and the state, and binds the state to this browser in the flow cookie:

```sh
curl -si -b cookies.txt -c cookies.txt 'localhost:8081/auth/oauth/corp/start?link=true&returnTo=/tokens'
```

```text
HTTP/1.1 302 Found
Location: http://localhost:8083/authorize?client_id=dev-client&code_challenge=qya4AMF5K4tDpQa9O90HWGkXRSOIxM_lwVCL8CLCofs&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Foauth%2Fcorp%2Fcallback&response_type=code&scope=openid+email+profile&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM
Set-Cookie: __Host-auth_flow=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM; Path=/; Expires=Tue, 06 Oct 2026 06:33:18 GMT; HttpOnly; Secure; SameSite=Lax
```

The development issuer consents at once and sends the browser back to the registered callback with a code and the same state:

```sh
curl -si 'http://localhost:8083/authorize?client_id=dev-client&…&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM'
```

```text
HTTP/1.1 302 Found
Location: http://localhost:8081/auth/oauth/corp/callback?code=the-code&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM
```

The callback exchanges the code, links or signs in, and redirects to `returnTo`. A link flow (this one, `link=true`) does not issue a new session: the person is already signed in.

```sh
curl -si -b cookies.txt -c cookies.txt 'localhost:8081/auth/oauth/corp/callback?code=the-code&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM'
```

```text
HTTP/1.1 302 Found
Location: /tokens
Set-Cookie: __Host-auth_flow=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
```

The same callback URL opened in another browser, one without the flow cookie, is refused. That is the defence against login CSRF: nobody can hand you a link that signs you in to their account.

```json
{"error":{"code":"oauth.state_invalid","message":"This sign-in link has expired. Start again."}}
```

Through the Go API the same flow is two operations, run the way a transport runs them: `a.Operation(oauth.StartEndpoint("corp"))` then `a.Operation(oauth.CallbackEndpoint("corp"))`, each through `Invoke` with a request context from `a.WithRequest`. The callback's `Flow` field must carry the state the start bound. Most apps never do this; the HTTP routes are the flow.

Check: after the callback the browser has a session cookie (sign-in flow) or still has its old one (link flow), and lands on `returnTo`.

## Step 5 — Understand who the callback signs in

The callback decides whose account this is, in this order. It never guesses from an address the provider has not verified.

1. The provider account (`provider`, `subject`) is already linked: that user signs in. The stored tokens are replaced.
2. The flow was a link flow (`link=true`): the provider account is linked to the user who started it, who must still be the signed-in user at the callback.
3. The provider says the address is verified, and the address is a verified identity of an existing user: the account is linked to that user and they sign in. Both sides verified, never one.
4. The address matches an identity but either side is unverified: `409 oauth.account_exists`. The person signs in the usual way and links from settings.
5. Otherwise a new user is created, with the provider's name and picture, and the address as an identity when the app has the `email` plugin (verified when the provider says so).

The result of a callback, which the Go API returns and the HTTP transport turns into a redirect:

<!-- ds:block id=callbackresult-2a98g7rq -->
**CallbackResult** · [`plugin/oauth/oauth.go:1418-1446`](../../plugin/oauth/oauth.go#L1418-L1446)

```go
type CallbackResult struct {
	User auth.UserView `json:"user"`
	// Created is true when the callback created the user.
	Created bool `json:"created"`
	// Linked is true when the callback linked the provider to the signed-in
	// user.
	Linked     bool   `json:"linked"`
	RedirectTo string `json:"redirectTo"`
	// SecondFactorRequired is true when the session is pending a second
	// factor; the app page at RedirectTo asks for it.
	SecondFactorRequired bool `json:"secondFactorRequired"`
	// EmailVerificationRequired is true when VerifyEmailBeforeSignIn held
	// the sign-in: the user exists, no session was issued, and RedirectTo
	// carries `?error=oauth.email_not_verified`.
	EmailVerificationRequired bool       `json:"emailVerificationRequired,omitempty"`
	Token                     auth.Token `json:"-"`
	// Data is what the start request carried in StartRequest.Data; empty
	// for an id-token sign-in.
	Data string `json:"data"`
	// ServerContext is what the WithServerContext functions returned at
	// the start: server-set values, never sent to the client (json "-"), read
	// by an After hook on the callback.
	ServerContext map[string]string `json:"-"`
	// Reauthentication is the outcome of a re-authentication callback
	// (EndpointReauthenticate), nil for every other flow: the session is
	// fresh, or the second factor is due with a ticket. No session is
	// issued and Token stays empty; RedirectTo carries ParamReauth.
	Reauthentication *auth.Reauthentication `json:"reauthentication,omitempty"`
}
```
<!-- /ds:block hash=b893cb -->

Case 3 is the implicit link, and it is a policy you can tighten or loosen. `oauth.NoImplicitLinking()` turns it off: a verified match is `409 oauth.account_exists` too, and every link is made from settings by a signed-in person. `oauth.TrustedProviders("corp")` goes the other way for one provider: its addresses count as verified even when the profile does not say so, for an issuer you know verifies every address it returns (a company directory). The local identity must still be verified either way. [`examples/oauth-rules`](../../examples/oauth-rules) picks one of the three from `LINKING`:

<!-- ds:block id=oauthrules-linkingrules-7mq2xk4v -->
**linkingRules** · [`examples/oauth-rules/main.go:157-170`](../../examples/oauth-rules/main.go#L157-L170)

```go
func linkingRules(mode linkingMode) ([]oauth.Option, error) {
	switch mode {
	case linkDefault:
		// Both sides verified links; anything less is 409 oauth.account_exists.
		return nil, nil
	case linkStrict:
		// Every link is deliberate: even a verified match is refused.
		return []oauth.Option{oauth.NoImplicitLinking()}, nil
	case linkTrusted:
		// corp's addresses count as verified even without email_verified.
		return []oauth.Option{oauth.TrustedProviders(providerName)}, nil
	}
	return nil, fmt.Errorf("%s=%q: want %q, %q or unset", envLinking, mode, linkStrict, linkTrusted)
}
```
<!-- /ds:block hash=b96d8b -->

Try it: `go run ./oauth-rules`, sign Alice up with a password and verify her address, then sign in through the development issuer as `alice-unflagged` (`409 oauth.account_exists`) and as `alice` (`302 /me`, her password account's user id). The [example's README](../../examples/oauth-rules/README.md#linking-by-email) has the transcript.

Check: in `examples/oauth`, `TestOAuth_VerifiedAddressLinksToTheExistingAccount` walks cases 3 and 4; in `examples/oauth-rules`, `TestRules_DefaultLinksOnlyWhenBothSidesAreVerified`, `TestRules_StrictNeverLinksByEmail` and `TestRules_TrustedProviderLinksAnUnflaggedAddress` walk the three linking rules.

## Step 6 — Link and unlink from settings

Linking is the start route with `link=true`, opened by a signed-in user. The transcript in Step 4 was a link flow; afterwards the account list has the provider:

```sh
curl -s -b cookies.txt localhost:8081/auth/oauth/accounts
```

```json
{"accounts":[{"id":"acc_ngza72ednj6roq33jzwdc6a4","provider":"corp","email":"carol@example.com","createdAt":"2026-10-06T06:23:18.15981Z","scopes":[]}]}
```

Each account carries `scopes`, the scopes the provider said it granted at the last exchange or refresh (kept with `oauth.StoreTokens`, `[]` otherwise; this development issuer names none), so a settings page can tell whether to ask for more with `/start?link=true&scopes=…`. Tokens never appear in the list.

Another user who tries to link the same provider account is refused:

```sh
# dave signed up with a password in his own browser (dave.txt), then ran start?link=true and the consent step
curl -si -b dave.txt 'localhost:8081/auth/oauth/corp/callback?code=the-code&state=…'
```

```text
HTTP/1.1 409 Conflict
{"error":{"code":"oauth.linked_elsewhere","message":"This provider account is linked to another user."}}
```

Unlinking is a `POST` with the provider name. The core refuses to remove the last way into an account (`409 auth.last_sign_in_method`), so a user who has only this provider must add a password or another provider first. Unlinking twice is `404 oauth.not_linked`.

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/oauth/unlink -H 'Origin: http://localhost:8081' -d '{"provider":"corp"}'
curl -s -b cookies.txt localhost:8081/auth/oauth/accounts
curl -s -b cookies.txt -X POST localhost:8081/auth/oauth/unlink -H 'Origin: http://localhost:8081' -d '{"provider":"corp"}'
curl -s -b cookies.txt localhost:8081/tokens
```

```json
{"ok":true}
{"accounts":[]}
{"error":{"code":"oauth.not_linked","message":"Not found."}}
{"error":{"code":"oauth.no_tokens","message":"No provider tokens are stored for this account."}}
```

From Go, for the signed-in user of the request in `ctx`:

<!-- ds:block id=plugin-unlink-x4mcynf2 -->
**Plugin.Unlink** · [`plugin/oauth/oauth.go:2540-2543`](../../plugin/oauth/oauth.go#L2540-L2543)

```go
func (p *Plugin) Unlink(ctx context.Context, provider string) error {
	_, err := p.unlink.Call(ctx, UnlinkRequest{Provider: provider})
	return err
}
```
<!-- /ds:block hash=d730af -->

And for any user, for an admin page:

<!-- ds:block id=plugin-accounts-2c9y8gse -->
**Plugin.Accounts** · [`plugin/oauth/oauth.go:2421-2432`](../../plugin/oauth/oauth.go#L2421-L2432)

```go
func (p *Plugin) Accounts(ctx context.Context, userID string) ([]Account, error) {
	var row Account
	out := []Account{}
	err := p.core.Each(ctx, p.core.Select().Columns(accountBindings(&row)...).From(TableAccount).
		Where(sqlb.Eq(AccountUserID, userID)).Order(sqlb.OrderBy(AccountCreated, sqlb.SortAsc), sqlb.OrderBy(AccountID, sqlb.SortAsc)),
		func() error {
			row.Scopes = strings.Fields(row.scope)
			out = append(out, row)
			return nil
		})
	return out, err
}
```
<!-- /ds:block hash=abc920 -->

A person may link two accounts of one provider (two GitHub accounts); `/auth/oauth/accounts` lists both with their ids, and `{"provider":"github","accountId":"acc_…"}` unlinks the one named (`Plugin.UnlinkAccount` from Go). Without an id the oldest goes, and an id that is not the caller's own is `404 oauth.not_linked`, the same answer as a provider never linked.

Check: `GET /auth/oauth/accounts` lists the provider after a link and not after an unlink.

### Confirm it is still you with a linked provider

Use this when a user who signs in only with a provider (no password, no passkey) hits a change that needs a recent sign-in, `auth.fresh_session_required` on unlink, an address change or account deletion. Signing in again would start a second session; this proves the user on the session they hold, as [password and passkey re-authentication](../concepts/sessions.md#prove-it-is-still-you-re-authentication) do, by a round trip to a provider account already linked to them.

The start is a `POST` from the signed-in page, so the origin check stops another site from starting one, and it answers the provider URL as JSON instead of redirecting (a `fetch` would follow a redirect); the page then navigates to it:

<!-- ds:block id=oauth-endpointreauthenticate-6qv3mx8k -->
**EndpointReauthenticate** · [`plugin/oauth/reauth.go:45`](../../plugin/oauth/reauth.go#L45-L45)

```go
"oauth.reauthenticate"
```
<!-- /ds:block hash=7edfbd -->

<!-- ds:block id=oauth-reauthenticaterequest-9tn4wk2p -->
**ReauthenticateRequest** · [`plugin/oauth/reauth.go:86-103`](../../plugin/oauth/reauth.go#L86-L103)

```go
type ReauthenticateRequest struct {
	// Provider is the provider to confirm with; the user must have an
	// account linked there.
	Provider string `json:"provider"`
	// ReturnTo is where the callback lands, with ParamReauth added: the page
	// that asked, so it can rerun the refused action. Same rules as
	// StartRequest.ReturnTo; empty is the site root.
	ReturnTo string `json:"returnTo,omitempty"`
	// ErrorTo is where a refused callback lands with `?error=<code>`; empty
	// takes ReturnTo, so the user comes back to the page that asked.
	ErrorTo string `json:"errorTo,omitempty"`
	// Prompt is forwarded to a ParamsProvider ("login" asks the provider to
	// sign the person in again rather than answer from its own session).
	Prompt string `json:"prompt,omitempty"`
	// LoginHint pre-fills the account at a ParamsProvider. Empty takes the
	// address of the user's linked account there when there is exactly one.
	LoginHint string `json:"loginHint,omitempty"`
}
```
<!-- /ds:block hash=56baea -->

The flow is the sign-in flow with the current session's id stored in its state, beside the PKCE verifier and the flow cookie. The callback refuses before it exchanges the code when it arrives on another session, signed out, or as an impersonation, a pending session or an API key; after the exchange it refuses any provider account that is not linked to that session's user, another person's included, with one code, `403 oauth.reauth_not_linked`, and links nothing on the way. Then the core asks the second-factor question exactly as the OAuth sign-in callback does (same operation, same method), so under `twofactor.DefaultPolicy`, which asks after password sign-ins only, the session is fresh at once. No session is issued and no cookie is set (in stateless mode the same session is resealed, as a refresh is), the provider's new tokens are kept as at sign-in, and the [`ValidateProfile`](#step-11--validate-the-profile-and-map-its-claims) hooks see `Action: "sign_in"` with `Reauthentication: true`, so a rule that holds sign-ins holds this too.

The browser lands on `returnTo` with the outcome added to its query, or on `errorTo` (default: `returnTo`) with `?error=<code>`:

<!-- ds:block id=oauth-paramreauth-2kd8wq5n -->
**ParamReauth** · [`plugin/oauth/reauth.go:59-64`](../../plugin/oauth/reauth.go#L59-L64)

```go
const (
	ParamReauth        = "reauth"
	ParamReauthTicket  = "reauthTicket"
	ReauthFresh        = "fresh"
	ReauthSecondFactor = "second_factor"
)
```
<!-- /ds:block hash=48523d -->

The start is rate limited per IP like a sign-in start and [per signed-in user](ds:block?id=oauth-reauthuserlimit-5wm2kq7x) in 15 minutes, and every refused callback reaches the [security stream](../concepts/security-events.md) as `session.reauthenticated` with `reauth_step=failed`. From Go, for the signed-in user of the request in `ctx`, `p.Reauthenticate(ctx, oauth.ReauthenticateRequest{Provider: "google", ReturnTo: "/settings"})` returns the URL.

What it proves is control of the linked provider account in this browser, now: a provider with a session of its own may answer without asking anything. Pass `prompt=login` (OpenID Connect) to have it ask again; a `ParamsProvider` forwards it, and the user's linked address goes as `login_hint` when they have exactly one account there. Under `authhttp.SameSiteStrict` the session cookie does not travel on the provider's redirect, so the callback arrives signed out and answers `auth.signed_out`, as a link flow does; use a password or a passkey there.

Check: `TestOAuthReauth_RefreshesTheSameSession`, `TestOAuthReauth_OnlyALinkedAccountOfThisUser` and `TestOAuthReauth_HTTP` in `integration/` refresh one session row with no new token, refuse another user's and an unlinked account, and land on `/settings?reauth=fresh`, on every engine.

#### From a native app: an ID token

Use this in a mobile, desktop or command-line app that holds a bearer token and cannot leave for the provider and come back to a page. The app signs the person in again with the provider's own SDK (Sign in with Apple, Google Sign-In), which hands it a fresh ID token, and posts that token on the session it already holds. The route exists when at least one provider verifies ID tokens, the same providers that offer [native sign-in](#step-8--sign-in-from-a-native-app-with-an-id-token):

<!-- ds:block id=oauth-endpointreauthidtoken-8kw3nq5v -->
**EndpointReauthenticateIDToken** · [`plugin/oauth/reauth.go:156`](../../plugin/oauth/reauth.go#L156-L156)

```go
"oauth.reauthenticate-id-token"
```
<!-- /ds:block hash=e3b8af -->

<!-- ds:block id=oauth-reauthidtokenrequest-3vn8kq2w -->
**ReauthenticateIDTokenRequest** · [`plugin/oauth/reauth.go:165-179`](../../plugin/oauth/reauth.go#L165-L179)

```go
type ReauthenticateIDTokenRequest struct {
	// Provider names the provider that issued IDToken; it must verify ID
	// tokens (an IDTokenVerifier) and the user must have an account linked
	// there.
	Provider string `json:"provider"`
	// IDToken is the provider's ID token, a compact JWS.
	IDToken string `json:"idToken"`
	// Nonce is the value the app sent to the provider, when it sent one,
	// under the same rule as IDTokenRequest.Nonce.
	Nonce string `json:"nonce,omitempty"`
	// AccessToken is the access token the SDK received with the ID token,
	// taken only when the ID token's at_hash binds it, and then stored under
	// StoreTokens, as IDTokenRequest.AccessToken is.
	AccessToken string `json:"accessToken,omitempty"`
}
```
<!-- /ds:block hash=0afd3f -->

The token is verified by the native sign-in's own code: the signature against the provider's key set, the issuer, the audience, the lifetime, the nonce rule, and an access token only when the token's `at_hash` binds it. Then the provider account it names must be one linked to the signed-in user, exactly as at the browser callback: another person's account or one nobody linked is `403 oauth.reauth_not_linked`, and nothing is linked or created. The second-factor question, the [`ValidateProfile`](#step-11--validate-the-profile-and-map-its-claims) hooks (`Reauthentication: true`), the sign-in profile rules (`RequireEmail` and the others) and the refusals of a signed-out caller, a pending session, an API key and an impersonation are the browser flow's, checked before the token is. The answer is an [`auth.Reauthentication`](ds:block?id=core-reauthentication-8hw2nq6t), as after a password: `{"fresh":true,…}`, or `secondFactorRequired` with a `ticket` for [`POST /auth/twofactor/reauthenticate`](twofactor.md#re-authentication). No session is issued and no `Set-Auth-Token` header is sent, except in stateless mode, where the resealed session comes back as a refresh does.

```http
POST /auth/oauth/reauthenticate-id-token
Authorization: Bearer <session token>
Content-Type: application/json

{"provider":"apple","idToken":"eyJ…","nonce":"<the nonce the app sent>"}
```

It is rate limited per IP like a native sign-in ([30 a minute](ds:block?id=idtokeniplimit-r8vq2mzc)) and [per signed-in user](ds:block?id=oauth-reauthuserlimit-5wm2kq7x) in 15 minutes. Every refused proof (a token that does not verify, an unlinked account, a hook's refusal) reaches the [security stream](../concepts/security-events.md) as `session.reauthenticated` with `reauth_step=failed`; a key set that cannot be fetched is `502 oauth.provider_failed` and is not counted as one. From Go, `p.ReauthenticateIDToken(ctx, oauth.ReauthenticateIDTokenRequest{Provider: "apple", IDToken: tok, Nonce: n})`.

What it proves is possession of a valid, unexpired ID token for the linked account, never seen before. Each token is accepted once, shared with the native sign-in ([replay protection](#replay-protection)): the token that signed the person in cannot also re-authenticate them, and a token used once is `401 oauth.id_token_replayed` on any session after that, so the app asks the SDK for a new token every time. Send a fresh nonce with every SDK call and set [`IDTokenConfig.RequireNonce`](ds:block?id=idtokenconfig-k3mq7wzd) so a token issued for another app's flow is refused.

Check: `TestOAuthReauthIDToken_OnlyALinkedAccountOfThisUser`, `TestOAuthReauthIDToken_RealVerification` and `TestOAuthReauthIDToken_HTTPBearerAndCookie` in `integration/` refuse another user's and an unlinked account, a token for another audience, issuer or key, an expired one, a nonce mismatch and a token already used (the sign-in's, or one that re-authenticated before) through the real verifier, and refresh a bearer session with no new token, on every engine.

## Step 7 — Keep the provider's tokens

Without `oauth.StoreTokens` the plugin throws the provider's tokens away after reading the profile. With it, each account's access and refresh token are kept sealed (AES-256-GCM, bound to the account row) and read back with `Tokens`; the sealing key is the one you pass, or with `oauth.StoreTokens()` and no key the one derived from `auth.WithSecret`, so a rotated secret (`auth.WithSecret(new, old)`) still opens the tokens sealed under the old one:

<!-- ds:block id=storetokens-3srdantg -->
**StoreTokens** · [`plugin/oauth/oauth.go:582-589`](../../plugin/oauth/oauth.go#L582-L589)

```go
func StoreTokens(key ...[]byte) Option {
	return func(p *Plugin) {
		p.keepTokens = true
		if len(key) > 0 {
			p.tokenKey = key[0]
		}
	}
}
```
<!-- /ds:block hash=8d3fb6 -->

When the key must stay in a key service (Vault transit, AWS KMS), seal through an [`auth.Sealer`](ds:block?id=core-sealer-4kw9vn2t) instead: [`oauth.StoreTokensWith(s)`](ds:block?id=storetokenswith-8vk2nq5d) for this plugin, or `auth.WithSealer(s)` for every plugin that keeps secrets. The order is a `StoreTokens` key, then `StoreTokensWith`, then `auth.WithSealer`, then the key derived from `auth.WithSecret`. Each token is sealed with the account id as additional data; a seal error fails the sign-in that would have stored it, and an open error comes back from `Tokens` rather than an empty token. See [Security](../concepts/security.md#keys-in-a-kms-the-sealer).

<!-- ds:block id=plugin-tokens-ue968772 -->
**Plugin.Tokens** · [`plugin/oauth/oauth.go:2257-2270`](../../plugin/oauth/oauth.go#L2257-L2270)

```go
func (p *Plugin) Tokens(ctx context.Context, userID, provider string) (TokenSet, error) {
	id, ts, err := p.loadTokens(ctx, userID, provider)
	if err != nil {
		return TokenSet{}, err
	}
	if ts.ExpiresAt.IsZero() || ts.RefreshToken == "" || p.core.Now().Add(RefreshMargin).Before(ts.ExpiresAt) {
		return ts, nil
	}
	r, ok := p.provider(provider).(Refresher)
	if !ok {
		return ts, nil
	}
	return p.refresh(ctx, provider, r, id, ts)
}
```
<!-- /ds:block hash=fa4171 -->

The example's `/tokens` route is how an app would use them before calling the provider's API for the signed-in user. The development issuer numbers its tokens, so a refresh is visible:

<!-- ds:block id=tokens-qns4m67v -->
**tokens** · [`examples/oauth-link-and-tokens/main.go:231-243`](../../examples/oauth-link-and-tokens/main.go#L231-L243)

```go
func tokens(oa *oauth.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts, err := oa.Tokens(r.Context(), authhttp.MustUser(r).ID, providerName)
		if err != nil {
			if !errors.Is(err, oauth.ErrNoTokens) {
				log.Printf("tokens: %v", err)
			}
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, tokensResponse{AccessToken: ts.AccessToken.Reveal(), RefreshToken: ts.RefreshToken.Reveal(), ExpiresAt: ts.ExpiresAt})
	})
}
```
<!-- /ds:block hash=5864d9 -->

With the default lifetime the stored pair comes back as is:

```sh
curl -s -b cookies.txt localhost:8081/tokens
curl -s -b cookies.txt localhost:8081/tokens
```

```json
{"accessToken":"access-1","refreshToken":"refresh-1","expiresAt":"2026-10-06T07:23:18.159524Z"}
{"accessToken":"access-1","refreshToken":"refresh-1","expiresAt":"2026-10-06T07:23:18.159524Z"}
```

An access token that expires within [`RefreshMargin`](ds:block?id=refreshmargin-xnszv5aq) (1 minute) is refreshed first, when a refresh token is stored and the provider can refresh (`*oauth.OAuth2` and `*oauth.OIDCProvider` can; see `oauth.Refresher`). Run the example with `ISSUER_EXPIRES_IN=30` and every read refreshes, keeping the rotated refresh token:

```sh
ISSUER_EXPIRES_IN=30 go run ./oauth-link-and-tokens   # then sign up and link as above
curl -s -b cookies.txt localhost:8081/tokens
curl -s -b cookies.txt localhost:8081/tokens
```

```json
{"accessToken":"access-2","refreshToken":"refresh-2","expiresAt":"2026-10-01T05:19:15.32424Z"}
{"accessToken":"access-3","refreshToken":"refresh-3","expiresAt":"2026-10-01T05:19:15.346944Z"}
```

```text
2026/10/01 10:48:45 issuer: refresh 1, rotating the refresh token
2026/10/01 10:48:45 issuer: refresh 2, rotating the refresh token
```

The key comes from your app, 32 bytes from your secret store. Losing it loses the stored tokens, not the accounts: `Tokens` answers `auth: sealed value does not open; was the key changed?` and the user links the provider again.

Check: `TestTokens_StoredAndRefreshedBeforeExpiry` in the example asserts both behaviours.

### Hand the access token to the page (opt-in)

When the page itself must call the provider's API (a Google Drive picker in the browser), `oauth.ExposeAccessTokens()` adds `POST /auth/oauth/access-token {"provider":"google"}` for the client. It answers the signed-in caller's own token at that provider, refreshed when it is within a minute of expiring, with `accessTokenExpiresAt`, `scopes` and `idToken`; the refresh token never leaves the server. It needs `oauth.StoreTokens` (`auth.New` refuses it otherwise), a session and the origin check, and is limited to [30](ds:block?id=accesstokeniplimit-x4wn8kqt) reads per IP a [minute](ds:block?id=accesstokenipwindow-m7qk2xwn); a provider the caller never linked answers `404 oauth.no_tokens`.

**The risk, stated plainly:** this moves a bearer credential for another service into the browser. Any script that runs on your origin, one XSS away, can read it and call the provider as the user until it expires, and no sign-out here revokes it. Leave it off unless the page truly needs the token; server code reads tokens with `Plugin.Tokens` and never needs this route.

Check: `TestTokensOAuth_ExposeAccessTokens`, `TestTokensOAuth_AccessTokenRouteIsRateLimited`, `TestTokensOAuth_AccountsListGrantedScopes`.

## Step 8 — Sign in from a native app with an ID token

A phone app does not run the redirect dance against your server: the provider's SDK (Google Sign-In, Sign in with Apple, One Tap) signs the person in and hands the app an ID token, a signed JWT naming the person. The app posts that token to `/auth/oauth/<provider>/id-token` and gets a session back. The plugin verifies the token against the provider's published keys (`jwks_uri`), checks the issuer, the audience, the lifetime and the nonce, then resolves the person exactly as a callback would (Step 5): a linked account signs in, a verified address links, a signed-in caller links the provider, otherwise a user is created.

The route exists for every `*oauth.OIDCProvider` (the key set and issuer come from discovery) and for an `*oauth.OAuth2` with an `IDToken` configuration:

<!-- ds:block id=idtokenconfig-k3mq7wzd -->
**IDTokenConfig** · [`plugin/oauth/idtoken.go:35-57`](../../plugin/oauth/idtoken.go#L35-L57)

```go
type IDTokenConfig struct {
	// JWKSURL is where the provider publishes its signing keys. Required.
	JWKSURL string
	// Issuers are the iss values accepted; Google uses two spellings. At
	// least one is required.
	Issuers []string
	// Audiences are accepted aud values besides ClientID: an iOS bundle id,
	// an Android client id. The web ClientID is always accepted.
	Audiences []string
	// ProfileFromToken makes Exchange read the profile from the id_token in
	// the token response instead of calling FetchProfile, for a provider that
	// has no userinfo endpoint. The token's nonce is the flow's PKCE
	// challenge, which AuthCodeURL sends as the nonce parameter.
	ProfileFromToken bool
	// RequireNonce refuses an ID token that carries no nonce claim
	// (ErrNonceRequired), for an app whose clients always send one: a token
	// replayed from another app's sign-in then has no way in.
	RequireNonce bool
	// HostedDomain refuses a token whose hd claim is not this Google
	// Workspace domain (ErrIDTokenInvalid), the native counterpart of
	// GoogleProfileFor; empty accepts every account. Only Google sets hd.
	HostedDomain string
}
```
<!-- /ds:block hash=3f6083 -->

`Audiences` matters for native apps: an ID token from the iOS SDK names the iOS client id as `aud`, not the web client id, so list it. The example's issuer plays both roles; its `/mint` route stands in for the SDK on the phone:

<!-- ds:block id=newoauth-native-b7xk4rqm -->
**newOAuth** · [`examples/oauth-native/main.go:159-167`](../../examples/oauth-native/main.go#L159-L167)

```go
func newOAuth(issuer string, key []byte) *oauth.Plugin {
	corp := oauth.OIDC(providerName, issuer, issuerClientID, issuerClientSecret)
	corp.IDToken.Audiences = []string{issuerNativeClientID}
	return oauth.New(
		oauth.WithProviders(corp),
		oauth.ErrorURL(signInPage),
		oauth.StoreTokens(key),
	)
}
```
<!-- /ds:block hash=00b734 -->

The request body, and the call a native app makes (in bearer mode, so the session arrives in a header rather than a cookie):

<!-- ds:block id=idtokenrequest-g7mw4ztk -->
**IDTokenRequest** · [`plugin/oauth/native.go:41-58`](../../plugin/oauth/native.go#L41-L58)

```go
type IDTokenRequest struct {
	// IDToken is the provider's ID token, a compact JWS.
	IDToken string `json:"idToken"`
	// Nonce is the value the app sent to the provider, when it sent one;
	// the token's nonce claim must be it or its SHA-256 hex.
	Nonce string `json:"nonce,omitempty"`
	// SignUp says the person meant to sign up, which ExplicitSignUp
	// requires before a user is created.
	SignUp bool `json:"signUp,omitempty"`
	// AccessToken is the access token the native SDK received with the ID
	// token. It is taken only when the ID token binds it: an at_hash claim
	// (OpenID Connect Core 3.1.3.6) equal to the hash of this value, so a
	// client cannot attach a stolen or unrelated token to a verified identity.
	// A token without at_hash, or with another hash, is ErrIDTokenInvalid. Once
	// taken, it is the account's stored access token under StoreTokens, like a
	// callback's.
	AccessToken string `json:"accessToken,omitempty"`
}
```
<!-- /ds:block hash=4f5b37 -->

```sh
TOKEN=$(curl -s 'localhost:8083/mint?nonce=n-1' | jq -r .id_token)
curl -si -X POST localhost:8081/auth/oauth/corp/id-token -H 'Auth-Token-Mode: bearer' -d "{\"idToken\":\"$TOKEN\",\"nonce\":\"n-1\"}"
```

```text
HTTP/1.1 200 OK
Set-Auth-Token: …
{"user":{"id":"usr_…","name":"Carol","image":""},"created":true,"linked":false,"redirectTo":"","secondFactorRequired":false,"data":""}
```

The nonce ties a token to the app's own request: the app chooses a random value, hands it to the SDK, and sends it along with the token; a token whose `nonce` claim is neither that value nor its SHA-256 hex (Apple's SDK hashes it) is refused. A wrong nonce, a forged signature, an expired token and a token for another audience all answer the same `401 oauth.id_token_invalid`; the reason is in the log. `IDToken.RequireNonce` refuses tokens that carry no nonce at all. The nonce alone does not stop a replay, because the client chooses it and sends it beside the token: whoever captured both can send both again. That is what the replay guard below is for.

```sh
curl -s -X POST localhost:8081/auth/oauth/corp/id-token -d "{\"idToken\":\"$TOKEN\",\"nonce\":\"other\"}"
```

```json
{"error":{"code":"oauth.id_token_invalid","message":"The sign-in token was not accepted."}}
```

### Replay protection

Every ID token the plugin accepts, on this route and on [the ID-token re-authentication](#from-a-native-app-an-id-token), is accepted once. After the signature and the claims verify, and before anything is created, linked or refreshed, the plugin claims the token with its [replay guard](ds:block?id=oauth-idtokenreplayguard-3kw9nq7m); the same token again answers `401 oauth.id_token_replayed` "This sign-in token was already used. Sign in with the provider again.", issues nothing, and reaches the [security stream](../concepts/security-events.md) as `token.replay` (severity `alert`, attribute `provider`). A token refused for any other reason (a bad signature, an unbound access token) is never claimed, so it costs nothing. The app asks the SDK for a new token for every sign-in and every re-authentication; an SDK that caches its last token (Google Sign-In's restored session) must be asked to refresh it first.

The claim is keyed by the [SHA-256 of the token's signed part](ds:block?id=oauth-idtokenclaim-6vn3kw8q), the JWS header and payload without the signature: an ES256 signature has a second valid spelling, so the raw token would let one issuance in twice, and issuer, subject and `jti` are not enough because `jti` is optional and two tokens of one second would share the rest. It is held until the token's `exp` plus the verifier's [30 seconds](ds:block?id=idtokenleeway-vb6nz8kq) of leeway, when the token is refused as expired anyway.

The default guard stores the claim as a verification row of purpose [`oauth.id_token_claim`](ds:block?id=oauth-purposeidtokenclaim-4mw8kq2n), filed under the provider name and keyed by the hash, so it needs no table of its own, joins the operation's transaction (a sign-in that fails after the claim leaves the token unclaimed) and is removed by `a.Sweep` / `auth sweep` once expired. Of several requests posting one token at once, exactly one signs in. It needs a verification store that refuses a duplicate ([`auth.ExclusiveVerificationStore`](ds:block?id=core-exclusiveverificationstore-2kd9wm4q)): the SQL table does, and so does `auth.NewStorageVerificationStore` over storage with an atomic `SetIfAbsent` ([`auth.SetIfAbsenter`](ds:block?id=core-setifabsenter-8vn2kq5w)), which `auth.NewMemoryVerificationStore` and contrib/redis (`SET NX`) have. With any other store `auth.New` fails with `oauth.ErrIDTokenReplayConfig` rather than run unprotected.

Two options change it, and nothing else does:

- [`oauth.WithIDTokenReplayGuard(g)`](ds:block?id=oauth-withidtokenreplayguard-8qn2wk4v) swaps the guard: a shared cache, a table of your own, a service. `g.Claim(ctx, claim)` returns nil the first time and `oauth.ErrIDTokenReplayed` for a key already claimed; of concurrent claims of one key exactly one may succeed; any other error fails the request rather than accept an unchecked token. `oauth.IDTokenReplayGuardFunc` adapts a function, and over Redis it is `SET NX` with the claim's lifetime. A nil guard is refused.
- [`oauth.AllowIDTokenReplay()`](ds:block?id=oauth-allowidtokenreplay-5wq8nk3d) turns the check off by name, for a client that must post one token twice and cannot ask for another. A captured token then signs in, or re-authenticates its user, until it expires; `auth.New` logs a warning. Setting both options is `oauth.ErrIDTokenReplayConfig`.

A server-issued nonce (the server hands out a single-use nonce, the app passes it to the SDK, the server spends it on the way back) is a second defence that also stops a token minted for another app's flow; it is not built in yet, and `IDToken.RequireNonce` with a nonce the app generates per sign-in covers that case today.

Check: `TestOAuthIDTokenReplay_SignInOnce`, `TestOAuthIDTokenReplay_ConcurrentSignIn`, `TestOAuthIDTokenReplay_ClaimHeldUntilExpiry` and `TestOAuthIDTokenReplay_SwapAndEscapeHatch` in `integration/` run on every engine.

Sign in with Apple is the provider that needs this most, because Apple has no userinfo endpoint and its client secret is a signed assertion rather than a string:

<!-- ds:block id=apple-h9kq3vmn -->
**Apple** · [`plugin/oauth/apple.go:70-76`](../../plugin/oauth/apple.go#L70-L76)

```go
func Apple(clientID string, secret func(ctx context.Context) (string, error), audiences ...string) *OAuth2 {
	return &OAuth2{
		ID: "apple", DisplayName: "Apple", ClientID: clientID, ClientSecretFunc: secret,
		AuthURL: AppleAuthURL, TokenURL: AppleTokenURL,
		IDToken: IDTokenConfig{JWKSURL: AppleJWKSURL, Issuers: []string{AppleIssuer}, Audiences: audiences, ProfileFromToken: true},
	}
}
```
<!-- /ds:block hash=e380f7 -->

<!-- ds:block id=appleclientsecret-r3bn8kzt -->
**AppleClientSecret** · [`plugin/oauth/apple.go:155-161`](../../plugin/oauth/apple.go#L155-L161)

```go
func AppleClientSecret(teamID, clientID, keyID string, key *ecdsa.PrivateKey) (func(ctx context.Context) (string, error), error) {
	if teamID == "" || clientID == "" || keyID == "" || key == nil {
		return nil, ErrAppleSecret
	}
	s := &appleSecret{teamID: teamID, clientID: clientID, keyID: keyID, key: key, now: time.Now}
	return s.secret, nil
}
```
<!-- /ds:block hash=4c3ae0 -->

`oauth.ParseAppleKey` reads the `.p8` file from the Apple developer account. On the web flow Apple's profile comes from the `id_token` the token endpoint returns (`IDToken.ProfileFromToken`), bound to the flow by the PKCE challenge, which doubles as the nonce; the native flow is the route above. `oauth.Apple` requests no scopes, so on the web it yields the subject alone. `oauth.AppleWithEmail(clientID, secret, bundleIDs...)` requests `email` and `name` too: Apple answers such a flow with a cross-site POST (`response_mode=form_post`), which carries no flow cookie, so the plugin serves `POST /auth/oauth/apple/callback` as a relay that redirects the browser to the GET callback with the same fields, and the GET checks the state as always. The email arrives in the ID token (a private relay address when the person hid theirs), the name in the `user` field Apple sends once, on first consent, and both reach the profile and the hooks of Step 11. Register the same callback URL at Apple either way.

Check: `TestIDToken_NativeAppSignsInWithoutABrowser` in the example signs in twice with the same subject and gets one user.

## Step 9 — Sign out at the provider too

A single sign-on setup expects "sign out" to end the session at the identity provider as well, or the next "sign in with corp" silently signs the person back in. `POST /auth/oauth/<provider>/logout` ends the session here, through the core's own sign-out, and redirects the browser to the provider's `end_session_endpoint` (from discovery, or `OAuth2.EndSessionURL`) with `id_token_hint` (when `oauth.StoreTokens` kept the ID token), `client_id` and `post_logout_redirect_uri`, which defaults to your base URL and must be registered at the provider (`oauth.PostLogoutURL` changes it).

```sh
curl -si -b cookies.txt -X POST localhost:8081/auth/oauth/corp/logout -H 'Origin: http://localhost:8081'
```

```text
HTTP/1.1 302 Found
Location: http://localhost:8083/logout?client_id=dev-client&id_token_hint=eyJ…&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8081
Set-Cookie: __Host-auth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
```

The request body may name where the provider sends the browser afterwards, for this logout only: `{"returnTo":"/signed-out"}`. It passes the same check as a sign-in's `returnTo` (a path on this site, a URL on an origin from `auth.WithTrustedOrigins`, or a trusted deep-link scheme), a path is made absolute against the base URL because `post_logout_redirect_uri` must be absolute, and it replaces `oauth.PostLogoutURL` in the redirect. An untrusted one answers `400 oauth.bad_return_to` and the session is not ended. The provider still refuses an address that is not registered there, on its own page, so register every one you send.

<!-- ds:block id=logoutrequest-q7hn2vwc -->
**LogoutRequest** · [`plugin/oauth/native.go:108-123`](../../plugin/oauth/native.go#L108-L123)

```go
type LogoutRequest struct {
	// Provider names the provider to sign out of on the general logout
	// route (POST /logout), which needs it (ErrLogoutProvider). On a
	// provider's own route (/<provider>/logout) it may be left empty; any
	// other value than that provider is ErrLogoutProvider.
	Provider string `json:"provider,omitempty"`
	// ReturnTo is where the provider sends the browser after its logout, as
	// post_logout_redirect_uri, instead of PostLogoutURL. It passes the same
	// TrustsReturnURL check as a sign-in's returnTo, so it is a path on this
	// site, a URL on a trusted origin or a trusted deep-link scheme;
	// anything else is ErrBadReturnTo and the session is not ended. A path
	// is made absolute against the base URL, because the parameter must be
	// an absolute URI. It must still be registered at the provider, which
	// refuses an unregistered one on its own page.
	ReturnTo string `json:"returnTo,omitempty"`
}
```
<!-- /ds:block hash=a79e13 -->

The local sign-out comes first and does not depend on the provider: a provider that is down answers `502 oauth.provider_failed` and the session is still ended. A provider with no end-session endpoint answers `404 oauth.logout_unsupported`.

<!-- ds:block id=logouter-x3nd8bqv -->
**Logouter** · [`plugin/oauth/native.go:25-30`](../../plugin/oauth/native.go#L25-L30)

```go
type Logouter interface {
	Provider
	// EndSession returns the provider's end_session_endpoint, or "" when the
	// provider has none.
	EndSession(ctx context.Context, hc *http.Client) (string, error)
}
```
<!-- /ds:block hash=45698d -->

Check: after the redirect, `/me` answers `401 auth.signed_out`, and the issuer logs the end-session request.

One route for every provider: `POST /auth/oauth/logout` with `{"provider":"corp","returnTo":"/signed-out"}` runs the same code, with the same `returnTo` check, for the provider the body names. It exists beside the per-provider routes, for a client that keeps the provider in a variable rather than in a path. The provider must be named: an empty one answers `400 oauth.logout_provider`, because guessing from the most recently used account picks the wrong provider as soon as someone links a second one; an unknown one, or one without an end-session endpoint, answers `404 oauth.logout_unsupported`. The session survives every refusal. On a provider's own route the `provider` field may be left out, and naming another provider there is `400 oauth.logout_provider`.

```sh
curl -si -b cookies.txt -X POST localhost:8081/auth/oauth/logout -H 'Origin: http://localhost:8081' -d '{"provider":"corp"}'
```

The answer is the per-provider route's: `302` to the end-session endpoint, with the session cookie cleared.

## Step 10 — Send errors to a page, and carry data through the flow

A callback that fails answers JSON, which is right for an API and wrong for a browser halfway through sign-in. With `oauth.ErrorURL("/sign-in")` a failed callback redirects to that page with the error code in the query, and the page shows a message; a start request may name another page with `errorTo=`. The code is the same one the JSON would have carried (`oauth.denied`, `oauth.state_invalid`, `oauth.account_exists`, …).

```sh
curl -si 'localhost:8081/auth/oauth/corp/callback?error=access_denied&state=x'
```

```text
HTTP/1.1 302 Found
Location: /sign-in?error=oauth.denied
```

A start request may also carry data the app wants back at the end, such as a referral code or an analytics source: `data=` travels with the state row and comes back in `CallbackResult.Data`. Over HTTP the callback redirects, so the place an app reads it is an After hook on the callback operation; the data came from the client, so treat it as untrusted input. The example logs the referral code with the user it reached:

<!-- ds:block id=referralhook-d2wn7pvc -->
**referralHook** · [`examples/oauth-native/main.go:175-185`](../../examples/oauth-native/main.go#L175-L185)

```go
func referralHook(logf func(string, ...any)) auth.OperationHook {
	return auth.OperationHook{
		Match: []auth.EndpointID{oauth.CallbackEndpoint(providerName)},
		After: func(_ context.Context, c *auth.Call, res any) error {
			if r, ok := res.(oauth.CallbackResult); ok && r.Data != "" {
				logf("user %s (created: %v) arrived with data %q", r.User.ID, r.Created, r.Data)
			}
			return nil
		},
	}
}
```
<!-- /ds:block hash=c3689f -->

```text
2026/10/02 21:48:53 user usr_… (created: false) arrived with data "ref=friend-42"
```

Check: `TestCallback_ErrorsRedirectToTheSignInPage` and `TestFlow_DataReachesTheHookAndLogoutEndsBothSessions` in the example.

### Carry server-set values across the redirect

`StartRequest.Data` comes from the client, so the callback must validate it. A value the server decided (the tenant the request resolved, a plan) travels with `oauth.WithServerContext(fn)`: `fn(ctx, call, provider)` runs at every start and id-token sign-in, what it returns is stored with the state where no client can set it, and it comes back in `CallbackResult.ServerContext` (an After hook on `oauth.CallbackEndpoint(provider)` reads it; it is never in the JSON) and in `ProfileEvent.ServerContext` for `ValidateProfile` and `OnResolved`. Several functions merge, a later key winning; an error refuses the start; the JSON of the values is at most [1024](ds:block?id=maxservercontextlength-w4xk9nqt) characters.

Without `oauth.ErrorURL` and without `errorTo`, a failed callback falls back to the core's `auth.WithErrorURL` page; with none of the three it answers JSON.

Check: `TestTokensOAuth_ServerContextCrossesTheRedirect`, `TestTokensOAuth_ServerContextFailures`, `TestTokensOAuth_FailedCallbackFallsBackToTheCoreErrorURL`.

## Step 11 — Validate the profile and map its claims

Two decisions are the app's, not the plugin's: whether a provider account may sign in at all (an allow-list of Workspace domains, a refusal of addresses from a provider you do not trust), and what to copy from the provider into your own user columns (a login handle, a locale, an employee id). Both see the provider's answer, which no `DataHooks` hook does. `oauth.ValidateProfile` runs once the plugin knows what it is about to do and before it writes anything:

<!-- ds:block id=profilehook-y8rm2vkn -->
**ProfileHook** · [`plugin/oauth/oauth.go:802`](../../plugin/oauth/oauth.go#L802-L802)

```go
type ProfileHook func(ctx context.Context, c *auth.Call, ev ProfileEvent) error
```
<!-- /ds:block hash=e7051a -->

<!-- ds:block id=profileevent-n3kw7xqt -->
**ProfileEvent** · [`plugin/oauth/oauth.go:769-793`](../../plugin/oauth/oauth.go#L769-L793)

```go
type ProfileEvent struct {
	Provider string
	Profile  Profile
	Action   ProfileAction
	// UserID is the user the flow resolves to; "" for ActionSignUp, where
	// the user does not exist yet.
	UserID string
	// Data is what the start request carried (StartRequest.Data); "" for an
	// id-token sign-in.
	Data string
	// ProviderInitiated is true for a sign-in the provider started
	// (AllowProviderInitiated), which no request of this app began: a hook
	// may hold such a sign-in to a stricter rule.
	ProviderInitiated bool
	// ServerContext is what the WithServerContext functions returned at
	// the start of this flow, or at the id-token call: trusted, because no
	// client can set it. Nil when none ran or none returned anything.
	ServerContext map[string]string
	// Reauthentication is true when a signed-in user is confirming who they
	// are with a linked account (EndpointReauthenticate, or
	// EndpointReauthenticateIDToken). Action is then
	// ActionSignIn, so a hook that holds sign-ins to a rule holds this to
	// it too; refusing it leaves the session as it was.
	Reauthentication bool
}
```
<!-- /ds:block hash=21a14e -->

`Profile.Claims` is the raw userinfo or ID-token payload, so a hook can read `hd`, `login` or any provider-specific field. Return an `*auth.Error` to answer the user with your own code and message, or any other error to answer `403 oauth.profile_refused` and log the reason. Nothing is created when the hook refuses, not even for a brand-new user.

`oauth.OnResolved` runs after the flow resolved its user, inside the same transaction and before the session is issued, with the user id, `Created` and `Linked`:

<!-- ds:block id=resolvedhook-c2nv8mkt -->
**ResolvedHook** · [`plugin/oauth/oauth.go:834`](../../plugin/oauth/oauth.go#L834-L834)

```go
type ResolvedHook func(ctx context.Context, c *auth.Call, ev ResolvedEvent) error
```
<!-- /ds:block hash=cd771f -->

Declare the column with `auth.WithUserColumns` and write it with `auth.SetUserColumn(ctx, c.Auth, auth.AppName, ev.UserID, col, value)`; an error from the hook rolls the whole sign-up back, so a user never exists without the column you meant to fill. Both hooks run on the id-token route too, with the same event.

In [`examples/oauth-rules`](../../examples/oauth-rules), an internal tool admits only its company's Google Workspace or Okta domain, read from the `hd` claim, and answers its own error code:

<!-- ds:block id=oauthrules-onlyourdomain-r4tk9pz2 -->
**onlyOurDomain** · [`examples/oauth-rules/main.go:192-197`](../../examples/oauth-rules/main.go#L192-L197)

```go
func onlyOurDomain(_ context.Context, _ *auth.Call, ev oauth.ProfileEvent) error {
	if claimString(ev.Profile.Claims, claimHostedDomain) != allowedDomain {
		return errDomainNotAllowed
	}
	return nil
}
```
<!-- /ds:block hash=229f23 -->

and keeps the provider's login handle in an app column declared with `auth.WithUserColumns`:

<!-- ds:block id=oauthrules-keeplogin-w6hz2nd8 -->
**keepLogin** · [`examples/oauth-rules/main.go:204-210`](../../examples/oauth-rules/main.go#L204-L210)

```go
func keepLogin(ctx context.Context, c *auth.Call, ev oauth.ResolvedEvent) error {
	login := claimString(ev.Profile.Claims, claimLogin)
	if login == "" {
		return nil
	}
	return auth.SetUserColumn(ctx, c.Auth, auth.AppName, ev.UserID, Login, login)
}
```
<!-- /ds:block hash=468f6a -->

Try it: `go run ./oauth-rules`, then sign in as `dave` (a `contractor.test` account): the callback answers `403 app.domain_not_allowed` and no user exists. Signed in as `carol`, `/me` shows `"login":"carol"`.

Check: `TestRules_OtherDomainIsRefusedBeforeAnythingIsWritten` and `TestRules_NewPersonGetsAnAccountWithTheirLogin` in the example; `TestTokensOAuth_ProfileHooks` in the integration suite drives a sign-up, a returning sign-in, a link flow and a link by verified email through both hooks, and proves that a refusal and a failing resolved hook leave no user behind.

## Step 12 — Separate sign-up from sign-in

A page with a "Sign in with Google" button and a "Sign up with Google" button has a problem the plugin cannot see: a person who meant to sign in, with a different Google account than the one on file, ends up with a second account. `oauth.ExplicitSignUp()` (or `oauth.ExplicitSignUp("google")` for one provider) makes a flow create a user only when the request said so: `GET /auth/oauth/google/start?signUp=true` from the sign-up button, `{"signUp": true}` on the id-token route. Without the flag, a provider account nobody holds is `403 oauth.sign_up_not_requested`, and the page tells the person to sign up. Linked accounts, verified-email matches and link flows are unaffected, and `oauth.NoSignUp` still wins where both apply.

The same start request may say where a new user lands: `newUserTo=/welcome` sends a callback that created the user to the onboarding page and a returning user to `returnTo`. Both take the same destinations `returnTo` does.

<!-- ds:block id=oauthproviders-newauth-h5r9wc3d -->
**newAuth** · [`examples/oauth-providers/main.go:184-196`](../../examples/oauth-providers/main.go#L184-L196)

```go
func newAuth(db *sql.DB, providers ...oauth.Provider) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			oauth.New(
				oauth.WithProviders(providers...),
				oauth.SkipBrokenProviders(),
				oauth.ExplicitSignUp(),
			),
		),
	)
}
```
<!-- /ds:block hash=9c93b8 -->

Check: `TestTokensOAuth_ExplicitSignUp` and `TestTokensOAuth_NewUserToAndIssuerCheck`; `TestProviders_SignUpMustBeAsked` in the example walks the refusal, the sign-up landing on `newUserTo` and the returning sign-in.

## Step 13 — More providers, and more of each provider

Beyond Google, GitHub and Apple, the package ships a constructor per provider: `oauth.Microsoft(tenant, id, secret)`, `oauth.Discord`, `oauth.Facebook`, `oauth.Slack`, `oauth.LinkedIn`, `oauth.GitLab`, `oauth.Twitch`, `oauth.X`, `oauth.Reddit`, `oauth.Spotify`, `oauth.Dropbox`, `oauth.Atlassian`, `oauth.Zoom`, `oauth.Figma`, `oauth.Kakao`, `oauth.Naver`, `oauth.LINE`, `oauth.Kick`, `oauth.Linear`, `oauth.Cloudflare`, `oauth.PayPal`, `oauth.Polar`, `oauth.Vercel`, `oauth.Patreon`, `oauth.Gumroad`, `oauth.HubSpot`, `oauth.Yandex`, `oauth.HuggingFace`, `oauth.Roblox`, `oauth.Salesforce`, `oauth.Paybin`, `oauth.Railway`, and the identity providers `oauth.Auth0`, `oauth.Okta`, `oauth.Keycloak`, `oauth.Zitadel` and `oauth.Cognito`. Each is an `*oauth.OAuth2` or `*oauth.OIDCProvider` with the provider's endpoints, default scopes, token-endpoint authentication and a reader for its profile shape; the [README table](../../plugin/oauth/README.md#built-in-providers) says which ones mark the email verified and which do not (those never link by email on their own; `oauth.TrustedProviders` trusts the ones you choose). The shapes are pinned by fixture tests, not by calls to the live provider: if a provider changes its answer, the fixture is where to fix it.

Google One Tap and the Google mobile SDKs hand your app a Google ID token. `g := oauth.Google(id, secret); g.IDToken = oauth.GoogleIDTokens("ios-client-id")` opens the id-token route of Step 8 for it, with the web client id and the extra audiences accepted; `oauth.GoogleIDTokensFor("acme.example")` refuses tokens from another Workspace domain, the native counterpart of `oauth.GoogleProfileFor`.

Per provider, five more knobs. `Headers` go on every token, refresh and revocation request (a `User-Agent` naming the app, an API version header; `Authorization` and `Content-Type` stay the grant's own), and on an OIDC issuer `DiscoveryHeaders` go on the discovery request. `TokenAuth: oauth.PrivateKeyJWT` with `ClientAssertion: oauth.ClientAssertion(clientID, kid, key)` authenticates to the token endpoint with an RFC 7523 assertion signed by your P-256 or RSA key instead of a shared secret, which is how Entra ID workload identity and certificate credentials work. `RefreshParams` go on the refresh grant only. `RevokeURL` (discovered as `revocation_endpoint` on an OIDC issuer) makes unlink revoke the stored tokens at the provider, best effort. `AuthorizationIssuer` (filled from discovery when the issuer supports RFC 9207) makes the callback require a matching `iss`, the defence against a mix-up between two providers. From Go, `Plugin.Start(ctx, provider, in)` and `Plugin.Callback(ctx, provider, in)` run the start and callback routes' operations with typed input, for a GraphQL resolver or a handler of your own; ctx must carry the request (the authhttp middleware or an adapter), because the flow cookie is set on its response and checked on the callback's. And from Go, `Plugin.Refresh(ctx, userID, provider)` renews the stored tokens now rather than within a minute of expiry, and `Plugin.Profile(ctx, userID, provider)` reads the provider's current profile with them; with `StoreTokens` the granted scope and the refresh token's expiry are kept too, in `TokenSet.Scope` and `TokenSet.RefreshExpiresAt`.

Check: `TestPresets_ProfileReaders`, `TestPresets_Constructors`, `TestTokenAuth_PrivateKeyJWT`, `TestGoogleIDTokens_HostedDomain`, `TestTokensOAuth_RefreshAndProfile`, `TestTokensOAuth_UnlinkRevokes`.

Round 6 added [`oauth.TikTok(clientKey, secret)`](ds:block?id=tiktok-w8nq3xkt), [`oauth.Notion(id, secret)`](ds:block?id=notion-p7kw3xqn), [`oauth.VK(id, secret)`](ds:block?id=vk-t5qw8xkn) and [`oauth.WeChat(appID, secret, lang)`](ds:block?id=wechat-q2xn8kwt), whose token requests are not plain RFC 6749. The knobs they use are open to any provider: `ClientIDParam` and `ClientSecretParam` rename the client credentials (`client_key`, `appid`, `secret`), `ScopeSeparator` joins scopes with a comma, `AuthURLFragment` ends the URL with `#wechat_redirect`, and `CallbackParams` forwards the callback's `device_id` and `state` to the token request (VK ID; a provider of your own reads them with `oauth.CallbackValuesOf(ctx)`). `NoPKCE` drops PKCE for one provider, never globally, and only for a provider whose web flow has none (TikTok, Notion and WeChat set it): the state stays single use and bound to the browser and the secret still guards the exchange, but a code stolen in transit could be injected into another browser's callback, so `auth.New` refuses it on a `PublicClient`. VK ID refreshes through the plugin: its refresh grant needs the callback's `device_id`, which `RefreshCallbackParams` keeps, sealed, with the stored tokens (`StoreTokens`) and sends with every refresh. For Microsoft, [`oauth.MicrosoftPhoto(m.FetchProfile, oauth.MicrosoftPhoto48)`](ds:block?id=microsoftphoto-r3nw8kqx) puts the Graph photo in the profile as a `data:` URL, left out when it would exceed [the image column](ds:block?id=maxphotodataurl-k9xw2nqt).

Check: `TestTikTok_ClientKeyCommaScopesAndNoPKCE`, `TestNotion_JSONBasicGrantAndOwnerProfile`, `TestVK_DeviceIDStateAndPostedUserInfo`, `TestWeChat_AppIDFragmentGETGrantsAndOpenIDProfile`, `TestNoPKCE_LeavesTheChallengeAndVerifierOut`, `TestMicrosoftPhoto`, `TestTokensOAuth_CallbackValuesReachTheExchange`.

Four more presets: [`oauth.Dub(id, secret)`](ds:block?id=dub-p3k8wn2x) (PKCE, `user.read`, the authorized workspace in `Profile.Claims["workspace"]`), [`oauth.Instagram(appID, secret)`](ds:block?id=instagram-p3n6xk2q) (Instagram professional accounts through Instagram Login; no PKCE, comma-joined scopes, a non-standard token answer read in both its shapes, a one-hour token that does not refresh, `force_reauth` allowed per request), [`oauth.Snapchat(id, secret)`](ds:block?id=snapchat-p3c4kn9w) (Login Kit: full-URL scopes, HTTP Basic at the token endpoint, PKCE, the Bitmoji avatar as the image) and [`oauth.Zoho(region, id, secret)`](ds:block?id=zoho-p3w7nq4k) (OpenID Connect at the data centre an [`oauth.ZohoRegion`](ds:block?id=zohoregions-p3z4kw8n) names). Dub, Instagram and Snapchat send no email, so their sign-ups have no address; the community plugins make one up (`<id>@instagram.com`), which these presets refuse to do.

Check: `TestPresetsP3_Constructors`, `TestZohoRegions`, `TestDub_PKCEUserReadAndUserInfo`, `TestInstagram_CommaScopesWrappedOrFlatTokenAndProfile`, `TestInstagram_Refusals`, `TestSnapchat_FullScopeURLsBasicPKCEAndMe`, `TestSnapchatProfile_Refusals`.

## Step 14 — Bring your own provider, or a goth one

A provider the package has no constructor for is an `*oauth.OAuth2` with its endpoints and a `FetchProfile`, or a type of your own implementing `oauth.Provider` (`Name`, `AuthCodeURL`, `Exchange`). Either way, prove it with the conformance kit before it meets a real user: [`oauthtest.Run`](ds:block?id=oauthtest-run-h4kw9qzt) starts a fake authorization server, builds the provider against it, and checks the authorization URL (client id, redirect, state, scopes, the S256 challenge), the exchange (subject, email, and the verified flag exactly as the server reported it, plus the access token), and that every failure is an error: the token endpoint's `invalid_grant`, a wrong verifier, a token answer that is not JSON or has no access token, a failing profile endpoint, a profile without a subject. Every built-in provider shape runs it; the [oauthtest README](../../plugin/oauth/oauthtest/README.md) lists the cases and options (`WantScopes`, `NoPKCE`, `NeverVerified`, `PublicClient`, `Route` for a profile API that is not userinfo).

<!-- ds:block id=testconformance-oauth2userinfo-z75vqp6t -->
**TestConformance_OAuth2UserInfo** · [`plugin/oauth/oauthtest/providers_test.go:76-81`](../../plugin/oauth/oauthtest/providers_test.go#L76-L81)

```go
func TestConformance_OAuth2UserInfo(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return pointAt(&oauth.OAuth2{ID: "corp", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
	}, oauthtest.WantScopes("openid", "email"))
}
```
<!-- /ds:block hash=7b7d83 -->

The example's company server has its own profile shape, so its provider carries a reader for it, and the kit runs it with that shape:

<!-- ds:block id=oauthproviders-corpprovider-x4n8tq2w -->
**corpProvider** · [`examples/oauth-providers/main.go:112-124`](../../examples/oauth-providers/main.go#L112-L124)

```go
func corpProvider(base, clientID, clientSecret string) *oauth.OAuth2 {
	return &oauth.OAuth2{
		ID:           corpName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      base + corpAuthorizePath,
		TokenURL:     base + corpTokenPath,
		Scopes:       corpScopes,
		FetchProfile: func(ctx context.Context, hc *http.Client, accessToken string) (oauth.Profile, error) {
			return fetchCorpProfile(ctx, hc, base+corpProfilePath, accessToken)
		},
	}
}
```
<!-- /ds:block hash=7f6a8e -->

<!-- ds:block id=oauthproviders-fetchcorpprofile-b6v2kw9p -->
**fetchCorpProfile** · [`examples/oauth-providers/main.go:132-154`](../../examples/oauth-providers/main.go#L132-L154)

```go
func fetchCorpProfile(ctx context.Context, hc *http.Client, profileURL, accessToken string) (oauth.Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return oauth.Profile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := hc.Do(req)
	if err != nil {
		return oauth.Profile{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return oauth.Profile{}, fmt.Errorf("%w: status %d", errCorpProfile, res.StatusCode)
	}
	var u corpUser
	if err := json.NewDecoder(io.LimitReader(res.Body, maxProfileBody)).Decode(&u); err != nil {
		return oauth.Profile{}, fmt.Errorf("%w: %w", errCorpProfile, err)
	}
	if u.ID == "" {
		return oauth.Profile{}, fmt.Errorf("%w: no id", errCorpProfile)
	}
	return oauth.Profile{Subject: u.ID, Email: u.Mail, EmailVerified: u.MailConfirmed, Name: u.DisplayName}, nil
}
```
<!-- /ds:block hash=335cc1 -->

<!-- ds:block id=oauthproviders-conformance-n7w2xk5r -->
**TestCorpProvider_PassesTheConformanceKit** · [`examples/oauth-providers/main_test.go:23-30`](../../examples/oauth-providers/main_test.go#L23-L30)

```go
func TestCorpProvider_PassesTheConformanceKit(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return corpProvider(u, oauthtest.ClientID, oauthtest.ClientSecret)
	}, oauthtest.WantScopes(corpScopes...),
		oauthtest.Route(corpProfilePath, func(p oauthtest.Person) any { // any: the kit's Route signature
			return corpUser{ID: p.Subject, Mail: p.Email, MailConfirmed: p.EmailVerified, DisplayName: p.Name}
		}))
}
```
<!-- /ds:block hash=8d76cf -->

If the app already configures its providers with [goth](https://github.com/markbates/goth), or needs one of goth's providers, the separate module `github.com/ubgo/auth/contrib/goth` wraps any goth provider: [`authgoth.Wrap`](ds:block?id=authgoth-wrap-m7tq3xnv)`(gp)` is an `oauth.Provider`, and the state, flow cookie, linking and email rules stay the plugin's. Build the goth provider with the plugin's callback URL and rename it to a route segment (`gp.SetName("corp")`). goth sends no PKCE challenge, so a wrapped provider is protected by the state alone, and its email counts as verified only when goth reports the `email_verified` claim; the [contrib/goth README](../../contrib/goth/README.md) lists every limit. Swapping later is one line: a linked account is stored as the provider name plus the subject, both the plugin's, so replacing `authgoth.Wrap(gp)` with `oauth.OIDC("corp", …)` keeps every account.

<!-- ds:block id=oauthproviders-partnerprovider-q8m3zf6c -->
**partnerProvider** · [`examples/oauth-providers/main.go:164-171`](../../examples/oauth-providers/main.go#L164-L171)

```go
func partnerProvider(issuer, clientID, clientSecret string) (oauth.Provider, error) {
	gp, err := openidConnect.New(clientID, clientSecret, callbackURL(partnerName), issuer+"/.well-known/openid-configuration", partnerScopes...)
	if err != nil {
		return nil, err
	}
	gp.SetName(partnerName)
	return authgoth.Wrap(gp), nil
}
```
<!-- /ds:block hash=a75db6 -->

A provider whose token endpoint is the only odd part (it wants a GET, a JSON body, another parameter name) does not need a whole `Provider`: set `GetToken` on the `*oauth.OAuth2` (or `*oauth.OIDCProvider`). It receives the callback's code, the flow's PKCE verifier and the redirect URI, and returns the provider's tokens; the plugin keeps the state, PKCE, the profile read from those tokens, linking and the session. An error it returns comes out of `Exchange` unchanged, and the callback answers `502 oauth.provider_failed` with the reason in the log, as for any failed exchange. With `GetToken`, `TokenURL` may be empty; it is then needed only for `Refresh`.

The conformance kit runs a provider whose hook posts the grant by hand, so every rule around the hook is proven: a refused grant, a wrong verifier, an answer that is not JSON or has no access token each fail the exchange.

<!-- ds:block id=testconformance-oauth2gettoken-8mz8ze65 -->
**TestConformance_OAuth2GetToken** · [`plugin/oauth/oauthtest/providers_test.go:144-157`](../../plugin/oauth/oauthtest/providers_test.go#L144-L157)

```go
func TestConformance_OAuth2GetToken(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		o := pointAt(&oauth.OAuth2{ID: "custom", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
		o.TokenURL = "" // the hook is the only way to the token endpoint
		o.GetToken = func(ctx context.Context, code, verifier, redirectURI string) (oauth.TokenSet, error) {
			return postGrant(ctx, u+oauthtest.TokenPath, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirectURI},
				"client_id": {oauthtest.ClientID}, "client_secret": {oauthtest.ClientSecret},
			})
		}
		return o
	}, oauthtest.WantScopes("openid", "email"))
}
```
<!-- /ds:block hash=744755 -->

Check: `TestCorpProvider_PassesTheConformanceKit` and `TestProviders_GothPartnerSignsIn` in the example; `go test ./plugin/oauth/oauthtest/` runs the kit against the built-in providers (one of them through a `GetToken` hook) and against providers that each break one rule; `cd contrib/goth && go test ./...` runs it against goth's openidConnect with `NoPKCE`.

## Step 15 — Keep signing in when an issuer is down

An OpenID Connect provider reads its endpoints from the issuer's discovery document at the first flow. When that document cannot be fetched, the flow fails with `502 oauth.provider_failed` and the next one tries again. Two switches change that, both off by default.

`OIDCProvider.Fallback` holds the issuer's endpoints written down by hand, used only while discovery is unreachable: a transport error, a status other than 2xx, or a body that is not JSON. Each use is logged at Warn, and discovery is tried again after [one minute](ds:block?id=discoveryretryinterval-k7xq3wnt), so a recovered issuer is back on its own document within the minute. A document that arrives but names another issuer, or lacks an endpoint, is still refused: the issuer answered, and what it said is wrong, which no hand-written copy should paper over.

The conformance kit runs an issuer that publishes no discovery document at all, so every case runs on the fallback:

<!-- ds:block id=testconformance-oidcfallback-9hh5cuuv -->
**TestConformance_OIDCFallback** · [`plugin/oauth/oauthtest/providers_test.go:189-196`](../../plugin/oauth/oauthtest/providers_test.go#L189-L196)

```go
func TestConformance_OIDCFallback(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		o := oauth.OIDC("corp", u+"/no-discovery", oauthtest.ClientID, oauthtest.ClientSecret)
		o.Fallback = oauth.Endpoints{AuthURL: u + oauthtest.AuthorizePath, TokenURL: u + oauthtest.TokenPath, UserInfoURL: u + oauthtest.UserInfoPath}
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		return o
	}, oauthtest.WantScopes("openid", "email", "profile"))
}
```
<!-- /ds:block hash=b26f3a -->

The fields:

<!-- ds:block id=oidc-endpoints-r6tw2nqk -->
**Endpoints** · [`plugin/oauth/oidc.go:113-126`](../../plugin/oauth/oidc.go#L113-L126)

```go
type Endpoints struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	// JWKSURL is the key set, for ID tokens; empty accepts none while the
	// fallback is in use.
	JWKSURL       string
	EndSessionURL string
	RevokeURL     string
	// IssParameterSupported is the discovery flag of RFC 9207: set it when
	// the issuer sends iss on every authorization response, so the callback
	// keeps checking it while the fallback is in use.
	IssParameterSupported bool
}
```
<!-- /ds:block hash=c4f78c -->

`oauth.SkipBrokenProviders()` keeps the other providers working when one is broken. At `auth.New` it loads every discovery document and key set at once, in parallel, and a provider whose configuration fails its check or whose document or key set cannot be loaded is logged at Error and left out: its routes are not mounted, `GET /auth/oauth/providers` does not list it, and nothing finds it by name. A `Fallback` in use counts as loaded. It comes back when the app restarts with it fixed. If every provider is broken, `auth.New` still fails, with `oauth.ErrAllProvidersBroken`, since nothing would be left. Without the switch nothing is fetched at start and a bad configuration fails `auth.New`, which is the right default for an app that would rather not boot than boot without its sign-in button.

Check: `TestFallback_*`, `TestSkipBroken_*`, `TestConformance_OIDCFallback`, `TestTokensOAuth_ProvidersFallbackSkipAndGetTokenOverHTTP`; `TestProviders_ABrokenIssuerIsLeftOut` in the example points one issuer at a closed server and sees `GET /auth/oauth/providers` list the other two and the broken one's start answer 404.

## Step 16 — Let the identity provider start the sign-in

A company identity provider (Okta, Entra ID, Google Workspace) has a dashboard of app tiles. A tile sends the browser straight to your callback with a code and no `state`, because your app never started the flow. By default that is `400 oauth.state_invalid`: a callback without a state bound to the browser is how login forgery works. Two opt-ins accept it, per provider.

`oauth.RestartProviderInitiated("okta")` is the one to reach for first: the tile's code is dropped unread and the callback answers an ordinary start in its place, a fresh state bound to this browser plus PKCE. The browser goes back to the provider, which signs a person who is signed in there straight through (a provider that shows a consent or account-picker page shows it again), and the callback that follows is checked like any other, landing on `/`. Because the forged code is never exchanged, nobody can sign someone else's browser in this way; it works for every provider, at the price of one more round trip.

<!-- ds:block id=restartproviderinitiated-q3wn8xkt -->
**RestartProviderInitiated** · [`plugin/oauth/oauth.go:983-985`](../../plugin/oauth/oauth.go#L983-L985)

```go
func RestartProviderInitiated(provider string, more ...string) Option {
	return func(p *Plugin) { p.restart = append(append(p.restart, provider), more...) }
}
```
<!-- /ds:block hash=73d91b -->

`oauth.AllowProviderInitiated("okta")` signs the person in from the tile's own code, with no second trip. It accepts it for the providers you name, and only for providers that verify ID tokens (an `oauth.OIDC` issuer, or an `*oauth.OAuth2` with `IDToken`; anything else fails `auth.New` with `oauth.ErrProviderInitiatedConfig`).

On that path the code is exchanged without PKCE, and the sign-in is accepted only when the token response carries an ID token whose signature, issuer, audience and lifetime verify, which carries no nonce (one would mean it was issued for another flow), and whose subject is the profile's. Then:

- the person is signed in as the user already linked to that provider subject, or a new user is created (`NoSignUp`, `ExplicitSignUp`, `RequireVerifiedEmail` and your hooks still apply; `ProfileEvent.ProviderInitiated` tells a hook which path it is on);
- an address that matches an existing account is `409 oauth.account_exists`, never a link, however verified;
- a browser that was signed in as someone else is signed out first, and nothing is linked to that account; a refused sign-in leaves it as it was;
- the browser lands on `/`.

<!-- ds:block id=allowproviderinitiated-t8kw3nqm -->
**AllowProviderInitiated** · [`plugin/oauth/oauth.go:965-967`](../../plugin/oauth/oauth.go#L965-L967)

```go
func AllowProviderInitiated(provider string, more ...string) Option {
	return func(p *Plugin) { p.initiated = append(append(p.initiated, provider), more...) }
}
```
<!-- /ds:block hash=bbf747 -->

The risk, plainly: without a state bound to the browser, anyone who holds a code for their own account at the provider can send someone else's browser to your callback with it, and that browser is signed in as the attacker. The victim then works inside the attacker's account: what they type, upload or connect lands there. The ID-token checks prove the code came from your provider for your client; they cannot prove that the person at the keyboard asked for it. Turn it on only for a workforce provider whose dashboard people actually use, keep it off for consumer providers, and consider a `ValidateProfile` hook that holds `ProviderInitiated` sign-ins to a stricter rule (only your Workspace domain, only existing users). The callback of a provider you named is rate-limited to [30](ds:block?id=initiatediplimit-m3xq8wkt) requests per IP per minute, since each state-less request costs a token exchange.

[`examples/oauth-rules`](../../examples/oauth-rules) restarts the tiles of its `corp` issuer, whose development server plays the dashboard at `/tile`:

<!-- ds:block id=oauthrules-newoauth-c8vn3wq5 -->
**newOAuth** · [`examples/oauth-rules/main.go:176-186`](../../examples/oauth-rules/main.go#L176-L186)

```go
func newOAuth(issuer string, linking ...oauth.Option) *oauth.Plugin {
	corp := oauth.OIDC(providerName, issuer, issuerClientID, issuerClientSecret)
	return oauth.New(append([]oauth.Option{
		oauth.WithProviders(corp),
		oauth.ValidateProfile(onlyOurDomain),
		oauth.OnResolved(keepLogin),
		// A tile's code arrives with no state: drop it and start a flow
		// bound to this browser instead of answering 400.
		oauth.RestartProviderInitiated(providerName),
	}, linking...)...)
}
```
<!-- /ds:block hash=a59163 -->

Try it: `go run ./oauth-rules`, then `curl -si -c tile.txt localhost:8083/tile` and request the `Location` it answers with the same cookie file. The callback answers `302` to the issuer's `/authorize` with a new `state` and sets `__Host-auth_flow`; following that lands on `/` signed in, and the tile's code was never exchanged. The [example's README](../../examples/oauth-rules/README.md#the-dashboard-tile) has the transcript.

Check: `TestRules_DashboardTileRestartsAFlow` in the example walks the restart over HTTP; `TestTokensOAuth_RestartProviderInitiated` proves the restart answers a flow bound to the browser and signs in on its callback; `TestTokensOAuth_ProviderInitiatedSignIn` proves that a provider you did not name still refuses a state-less callback, that the opted-in one signs up, signs in through the linked subject, replaces another person's session and never links by address; `TestExchangeInitiated_*` and `TestVerifyInitiated_NonceRules` prove the ID-token checks.

## Options you may want

| Option | Use it when |
|---|---|
| `oauth.ErrorURL("/sign-in")` | A failed callback should land on a page with `?error=<code>` instead of answering JSON; `errorTo=` on a start names another page for one flow |
| `oauth.WithServerContext(fn)` | Server-set values must reach the callback without the client being able to set them (Step 10) |
| `oauth.ExposeAccessTokens()` | The page itself must call the provider's API with the user's token; read the risk in Step 7 first |
| `OAuth2.NoPKCE` | One provider's web flow has no PKCE and refuses the parameters; per provider, never on a public client |
| `oauth.PostLogoutURL(fn)` | The provider should send the browser somewhere other than the base URL after a logout (register it at the provider) |
| `OAuth2.IDToken` / `OIDCProvider.IDToken` | A native app sends the provider's ID token (Step 8); `Audiences` for the app's own client ids, `RequireNonce` to refuse tokens without one, `ProfileFromToken` for a provider with no userinfo endpoint |
| `OAuth2.EndSessionURL` | A plain OAuth 2.0 provider with an RP-initiated logout endpoint; discovered for an OIDC issuer |
| `OAuth2.ClientSecretFunc` | The client secret is computed per request, as Apple's is (`oauth.AppleClientSecret`) |
| `oauth.Apple(clientID, secret, bundleIDs...)` | Sign in with Apple, web and native |
| `oauth.AppleWithEmail(clientID, secret, bundleIDs...)` | Sign in with Apple on the web with the person's email and name (Apple's form post, relayed through `POST …/apple/callback`) |
| `OAuth2.Headers`, `OIDCProvider.DiscoveryHeaders` | The provider wants a header on its token or discovery requests |
| `/start?data=…` | A referral code or source should come back in `CallbackResult.Data` (at most [1024](ds:block?id=maxflowdatalength-q9tz3nwm) characters) |
| `oauth.WithStateTTL(d)` | People need more or less than [10 minutes](ds:block?id=defaultstatettl-zsf722py) at the provider before the callback is refused as expired |
| `oauth.CallbackURL(fn)` | The handler is not mounted at `/auth`, or the callback host differs from the base URL |
| `oauth.WithHTTPClient(hc)` | Provider calls need a proxy, a CA bundle or a timeout other than 10 seconds |
| `oauth.WithIDTokenReplayGuard(g)` | ID-token claims should live somewhere other than the verification store, such as a shared cache ([replay protection](#replay-protection)) |
| `oauth.AllowIDTokenReplay()` | A native client must post one ID token more than once and cannot ask the SDK for another; a captured token then works until it expires |
| (always) | Provider calls never follow a redirect (`oauth.ErrRedirectRefused`, logged, answered `502 oauth.provider_failed`), an SSRF rule; a client given to `WithHTTPClient` gets the same policy unless it sets its own `CheckRedirect` |
| `oauth.StoreTokens(key)` | Your app calls the provider's API for the user later (Step 7); `oauth.StoreTokens()` with no key seals under the `auth.WithSecret` key instead, and a rotated secret keeps old tokens opening |
| `oauth.NoSignUp(providers...)` | Accounts are invited, not opened: a stranger's callback is `403 oauth.sign_up_disabled`, while linked accounts, verified-email matches and link flows still work; name providers to close only those |
| `oauth.RequireVerifiedEmail()` | No session may rest on an address the provider has not verified: such a callback is `403 oauth.email_unverified` (link flows excepted) |
| `oauth.RequireEmail()` | Every user must be reachable: a provider account that shares no email is `403 oauth.email_not_found` before anything is written (link flows excepted) |
| `oauth.VerifyEmailBeforeSignIn()` | The user is created, but no session is issued until the address is verified; the browser lands on the error page with `?error=oauth.email_not_verified` and the result says `emailVerificationRequired: true` (the id-token and provider-initiated routes too). The person verifies through plugin/email's resend and verify routes and signs in again |
| `oauth.AllowUnlinkingAll()` | Unlink may remove the last sign-in method (default: `409 auth.last_sign_in_method`) |
| `oauth.LinkUnverifiedLocalEmail()` | An escape hatch warned about at start: a verified provider address links to a local account whose address was never verified. Risk: account pre-hijacking (someone registers the victim's address first with a password of their own). |
| `oauth.StateInCookie()` | Keep the flow in a sealed flow cookie instead of a verification row; needs `auth.WithSecret`. |
| `oauth.UpdateProfileOnSignIn()` | A new name or avatar at the provider should show up here on the next sign-in, not only at creation |
| `oauth.NoImplicitLinking()` | Every link must be deliberate: a verified-email match is `409 oauth.account_exists` until the person links from settings |
| `oauth.TrustedProviders("github")` | A provider you know verifies addresses but does not flag them, so its address may link to a verified identity; never for one that does not verify |
| `oauth.RequireSameEmailOnLink()` | Settings may only attach a provider account whose address is already on the user (`409 oauth.email_mismatch` otherwise) |
| A `Provider` of your own | A provider the library does not ship: fill an `*oauth.OAuth2` with its URLs and a `FetchProfile`, or implement the interface |
| `OAuth2.TokenAuth` | The provider wants the secret as HTTP Basic (`oauth.ClientSecretBasic`: Reddit, PayPal, Zoom, X, Cloudflare) or is a public client with no secret (`oauth.PublicClient`, PKCE alone) |
| `OAuth2.AuthParams` | Static authorization parameters: `prompt=select_account`, `access_type=offline`, `hd=acme.example`, `display=popup`; the protocol's own keys are ignored |
| `OAuth2.TokenParams` | Static token-request parameters, such as an `audience` |
| `OAuth2.OptionalScopes` | Incremental authorization: `/start?scopes=calendar` adds an allow-listed scope for one flow (`oauth.bad_scope` otherwise), also on a link flow |
| `OAuth2.OptionalParams` | Per-request authorization parameters: `/start?params=display%3Dpopup%26ui_locales%3Dde` forwards each listed name (`oauth.bad_param` otherwise; `state`, `redirect_uri` and the other protocol parameters never pass) |
| `OAuth2.TokenLifetime` | The provider's token response has no `expires_in`, and `Tokens` should still refresh |
| `oauth.ValidateProfile(fn)` | Some provider accounts must not sign in: a Workspace domain allow-list, a refused address; the hook sees the profile and the raw claims before anything is written (Step 11) |
| `oauth.OnResolved(fn)` | Provider claims belong in your own user columns, written in the same transaction as the sign-up (Step 11) |
| `oauth.ExplicitSignUp(providers...)` | Sign-up and sign-in are separate buttons, and a sign-in must never create an account (Step 12); `signUp=true` on the start marks a sign-up |
| `/start?newUserTo=/welcome` | A brand-new user should land on an onboarding page (Step 12) |
| `oauth.Microsoft`, `oauth.Discord`, … | One of the providers the package ships a preset for (Step 13); `oauth.Presets` lists them |
| `g.IDToken = oauth.GoogleIDTokens(audiences...)` | Google One Tap or the Google mobile SDKs hand your app a Google ID token (Step 13); `GoogleIDTokensFor(domain, …)` restricts it to one Workspace |
| `OAuth2.TokenAuth = oauth.PrivateKeyJWT` + `ClientAssertion` | The provider takes a signed assertion instead of a client secret (Entra ID workload identity, certificate credentials) |
| `OAuth2.RefreshParams` | The refresh grant takes a parameter the code exchange does not |
| `OAuth2.RevokeURL` | Unlinking should revoke the stored tokens at the provider too (RFC 7009); discovered for an OIDC issuer |
| `OAuth2.AuthorizationIssuer` | The provider sends the RFC 9207 `iss` and the callback should require it; filled from discovery for an OIDC issuer |
| `OAuth2.FetchProfileFromTokens` | The profile call needs more than the access token (a field of the token response, through `TokenSet.Raw`) |
| `OIDCProvider.SubjectClaim`, `oauth.UserInfoProfile(url, claim)` | The issuer's stable identifier is a claim other than `sub` (Entra ID's `oid`) |
| `Plugin.Refresh`, `Plugin.Profile` | The app needs the tokens renewed now, or the provider's current profile, without a new sign-in |
| `/start?prompt=…&loginHint=…` | Per-request `prompt` and `login_hint` for any `*oauth.OAuth2` or `*oauth.OIDCProvider` |
| `oauth.GoogleProfileFor(url, "acme.example")` | Only accounts of one Google Workspace domain may sign in; the `hd` claim is checked, not just hinted |
| `OAuth2.DisplayName`, `GET /auth/oauth/providers`, `SignInMethods()` | A sign-in page draws its buttons from the configured providers (Step 3) |
| `POST /auth/oauth/logout {"provider"}` | One logout route with the provider in the body instead of the path (Step 9) |
| `OAuth2.GetToken` | The provider's token endpoint is not RFC 6749 and the rest is (Step 14) |
| `OIDCProvider.Fallback` | Sign-in should keep working while the issuer's discovery document is down (Step 15) |
| `oauth.SkipBrokenProviders()` | One broken provider must not take the others down at start (Step 15) |
| `oauth.SkipStateCookieCheck()` | A callback must succeed without the flow cookie (it lands on another domain, or an embedded browser drops cookies), and you accept login CSRF: the state is still single use and checked in the database, but nothing ties it to the browser that started the flow, so an attacker can sign a victim in to the attacker's account. Off by default; logged as a warning at every start. Prefer authhttp's `CookieDomain` or the desktop hand-off. See [Security](../concepts/security.md) |
| `oauth.RestartProviderInitiated("okta")` | People start sign-in from their identity provider's dashboard; the tile's code is dropped and a normal flow restarts (Step 16) |
| `oauth.AllowProviderInitiated("okta")` | The same, signed in from the tile's own code without the second trip; read the risk in Step 16 first |

The same fields exist on `*oauth.OIDCProvider` and are copied onto the discovered endpoints. A `Provider` of your own accepts the per-request parameters by implementing `oauth.ParamsProvider`; otherwise a start carrying them is `400 oauth.params_unsupported` rather than silently dropping them.

<!-- ds:block id=provider-9wm45phy -->
**Provider** · [`plugin/oauth/provider.go:75-84`](../../plugin/oauth/provider.go#L75-L84)

```go
type Provider interface {
	// Name is the route segment and the stored provider name, such as
	// "google". It must match auth.KindNamePattern and never change.
	Name() string
	// AuthCodeURL is where the browser goes to sign in. PKCE is not
	// optional: every URL carries the S256 challenge.
	AuthCodeURL(state, codeChallenge, redirectURI string) string
	// Exchange turns the callback's code into the person's profile.
	Exchange(ctx context.Context, hc *http.Client, code, codeVerifier, redirectURI string) (Profile, error)
}
```
<!-- /ds:block hash=1df656 -->

The option signatures:

<!-- ds:block id=withstatettl-chn8ez43 -->
**WithStateTTL** · [`plugin/oauth/oauth.go:571`](../../plugin/oauth/oauth.go#L571-L571)

```go
func WithStateTTL(d time.Duration) Option { return func(p *Plugin) { p.stateTTL = d } }
```
<!-- /ds:block hash=9289db -->

<!-- ds:block id=callbackurl-drghsqqe -->
**CallbackURL** · [`plugin/oauth/oauth.go:655-662`](../../plugin/oauth/oauth.go#L655-L662)

```go
func CallbackURL(fn func(provider string) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.CallbackURL", fn) {
			return
		}
		p.callback = fn
	}
}
```
<!-- /ds:block hash=880a6e -->

<!-- ds:block id=withhttpclient-yfjw32mp -->
**WithHTTPClient** · [`plugin/oauth/oauth.go:497`](../../plugin/oauth/oauth.go#L497-L497)

```go
func WithHTTPClient(hc *http.Client) Option { return func(p *Plugin) { p.hc = refuseRedirects(hc) } }
```
<!-- /ds:block hash=aa96ac -->

A provider that can also refresh tokens, and one that must discover its endpoints first:

<!-- ds:block id=refresher-vxfv33e5 -->
**Refresher** · [`plugin/oauth/provider.go:605-607`](../../plugin/oauth/provider.go#L605-L607)

```go
type Refresher interface {
	Refresh(ctx context.Context, hc *http.Client, refreshToken auth.Token) (TokenSet, error)
}
```
<!-- /ds:block hash=fe039b -->

<!-- ds:block id=discoverer-rc677yzv -->
**Discoverer** · [`plugin/oauth/oidc.go:26-28`](../../plugin/oauth/oidc.go#L26-L28)

```go
type Discoverer interface {
	Discover(ctx context.Context, hc *http.Client) error
}
```
<!-- /ds:block hash=2a9de7 -->

The generic OAuth 2.0 provider the built-in ones are values of; fill one for a provider the library does not ship:

The field table in the [package README](../../plugin/oauth/README.md) lists every field of [`oauth.OAuth2`](ds:block?id=oauth2-vwfanjbg) with its default.

The start route is rate-limited to [30](ds:block?id=startiplimit-rfjh9rkw) per IP per minute, because every start writes a state row. The count is per process unless you pass `auth.WithRateStore`; see [Rate limits](../concepts/rate-limits.md).

## From TypeScript

Use this when the account page runs in a browser. The [typed client](../client/README.md) names every route of this guide as a method of `client.oauth`, typed from the Go structs; list `oauth()` in `plugins`. Signing in and linking are page navigations to the start route, never a `fetch`, because the start binds the flow to the browser with a cookie and redirects ([Flows › OAuth](../client/flows.md)):

<!-- ds:block id=flows-oauth-9vk3qm8w -->
**continueWith** · [`clients/ts/examples/flows.ts:80-83`](../../clients/ts/examples/flows.ts#L80-L83)

```typescript
export function continueWith(provider: string, returnTo = "/"): void {
  const query = new URLSearchParams({ returnTo });
  location.assign(`/auth/oauth/${encodeURIComponent(provider)}/start?${query}`);
}
```
<!-- /ds:block hash=06e2d9 -->

The account page lists the configured providers beside the user's linked accounts:

<!-- ds:block id=tsp-oauth-accounts-3wk8qm5x -->
**linkedProviders** · [`clients/ts/examples/plugin-oauth.ts:16-24`](../../clients/ts/examples/plugin-oauth.ts#L16-L24)

```typescript
export async function linkedProviders(): Promise<{ id: string; name: string; linked: OauthAccount[] }[]> {
  const [providers, accounts] = await Promise.all([auth.oauth.providers(), auth.oauth.accounts()]);
  if (providers.error || accounts.error) return [];
  return (providers.data.providers ?? []).map((p) => ({
    id: p.id,
    name: p.name,
    linked: (accounts.data.accounts ?? []).filter((a) => a.provider === p.id),
  }));
}
```
<!-- /ds:block hash=c6f7ec -->

Unlinking needs a recent sign-in. A user with a password re-proves it as [password's From TypeScript](password.md#from-typescript) shows; a user who signs in only with a provider [confirms with a linked provider](#confirm-it-is-still-you-with-a-linked-provider), which leaves the page and comes back:

<!-- ds:block id=tsp-oauth-unlink-9kw3mx6q -->
**unlink** · [`clients/ts/examples/plugin-oauth.ts:87-89`](../../clients/ts/examples/plugin-oauth.ts#L87-L89)

```typescript
export async function unlink(account: OauthAccount): Promise<AuthResult<unknown>> {
  return auth.oauth.unlink({ provider: account.provider, accountId: account.id });
}
```
<!-- /ds:block hash=c4d436 -->

<!-- ds:block id=tsp-oauth-reauth-start-7mq2wk9x -->
**reauthenticateWith** · [`clients/ts/examples/plugin-oauth.ts:33-42`](../../clients/ts/examples/plugin-oauth.ts#L33-L42)

```typescript
export async function reauthenticateWith(provider: string): Promise<string | null> {
  const here = location.pathname + location.search;
  const { data, error } = await auth.oauth.reauthenticate({ provider, returnTo: here, errorTo: here });
  if (error) {
    // oauth.reauth_not_linked: no account of this user at that provider.
    return error.message;
  }
  location.assign(data.url);
  return null;
}
```
<!-- /ds:block hash=dd83f4 -->

<!-- ds:block id=tsp-oauth-reauth-return-4xn8kq2w -->
**afterReauthentication** · [`clients/ts/examples/plugin-oauth.ts:48-60`](../../clients/ts/examples/plugin-oauth.ts#L48-L60)

```typescript
export async function afterReauthentication(askForCode: () => Promise<string>): Promise<"fresh" | "failed" | null> {
  const url = new URL(location.href);
  const outcome = url.searchParams.get("reauth");
  const ticket = url.searchParams.get("reauthTicket");
  for (const name of ["reauth", "reauthTicket"]) url.searchParams.delete(name);
  history.replaceState(history.state, "", url);
  if (outcome === "fresh") return "fresh";
  if (outcome === "second_factor" && ticket) {
    const { data, error } = await auth.twofactor.reauthenticate({ code: await askForCode(), ticket });
    return error === null && data.fresh ? "fresh" : "failed";
  }
  return null;
}
```
<!-- /ds:block hash=cba22d -->

A native app re-authenticates with the ID token its provider SDK just returned, [on the session it holds](#from-a-native-app-an-id-token), and finishes a due second factor with the ticket:

<!-- ds:block id=tsp-oauth-reauth-idtoken-6wq3kn8m -->
**reauthenticateWithIdToken** · [`clients/ts/examples/plugin-oauth.ts:70-80`](../../clients/ts/examples/plugin-oauth.ts#L70-L80)

```typescript
export async function reauthenticateWithIdToken(provider: string, idToken: string, nonce: string, askForCode: () => Promise<string>): Promise<"fresh" | AuthError["code"]> {
  const { data, error } = await auth.oauth.reauthenticateIdToken({ provider, idToken, nonce });
  if (error) return error.code;
  if (data.fresh) return "fresh";
  if (data.secondFactorRequired && data.ticket) {
    const second = await auth.twofactor.reauthenticate({ code: await askForCode(), ticket: data.ticket });
    if (second.error) return second.error.code;
    if (second.data.fresh) return "fresh";
  }
  return "auth.fresh_session_required";
}
```
<!-- /ds:block hash=8fc784 -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `oauth.state_invalid` and `oauth.denied` on the page `errorTo` names, `oauth.account_exists` and `oauth.linked_elsewhere` after a sign-in or a link, `auth.fresh_session_required` and `auth.last_sign_in_method` on unlink, `oauth.reauth_not_linked` after a re-authentication with the wrong account, `oauth.id_token_invalid` for an ID token that does not verify, and `auth.rate_limited`.

Try it: `task demo` runs the [React demo](../client/react.md); sign in with "Continue with Demo provider", wait past the fresh window, change the email, and the dialog offers "Continue with Demo provider" (the headless `task ui:e2e` does exactly this, with a pick of another persona refused first).

Pitfalls:

- **The refused action does not rerun by itself after a provider round trip.** The page reloaded, so whatever closure asked is gone; read `?reauth=` once, remove it from the address, and tell the user the change can be made now (the React kit's `useReauthReturn` does this).
- **`returnTo` and `errorTo` must pass the same rule as the sign-in start** (a path on this site or a trusted origin), checked before any state is written.

Every method with its route and types: [TypeScript client reference › oauth](../reference/ts-client.md#oauth).

## What can go wrong

- `403 oauth.sign_up_not_requested` "No account is linked to this provider account. Use sign-up to create one." — `oauth.ExplicitSignUp` applies and the start had no `signUp=true` (or the id-token request no `"signUp": true`).
- `403 oauth.profile_refused` "This account cannot sign in here." — a `ValidateProfile` hook refused with a plain error; the reason is in the log. A hook that returns an `*auth.Error` is answered with that error instead.
- `404 oauth.cannot_refresh` from `Refresh` — the account has no refresh token, or the provider is not an `oauth.Refresher`.
- `404 oauth.profile_unsupported` from `Profile` — the provider is not an `oauth.ProfileFetcher`, or its profile exists only in the exchange's ID token.
- `400 oauth.state_invalid` on a callback that looks right — the provider sends RFC 9207 `iss` and the value did not match `AuthorizationIssuer`; the log says nothing more, on purpose.
- `auth.New` fails with "oauth: ClientAssertion goes with TokenAuth PrivateKeyJWT, and PrivateKeyJWT needs one" — set both or neither; a `ClientSecret` beside `PrivateKeyJWT` is `ErrProviderIncomplete`.

- `400 oauth.state_invalid` "This sign-in link has expired. Start again." — the state is missing, was already used, expired (`WithStateTTL`), belongs to another provider, or the browser has no flow cookie (the callback URL was opened elsewhere). Also a link flow finished by a browser that is no longer signed in as the user who started it.
- `400 oauth.denied` "Sign-in was cancelled at the provider." — the provider sent `error=access_denied`.
- `502 oauth.provider_failed` "The provider could not be reached. Try again." — discovery or the code exchange failed. The log has the reason (`oauth: exchange failed provider=… error=…`); the client never does. A wrong client secret, a redirect URL that does not match the registered one, and an unreachable issuer all end here.
- `409 oauth.account_exists` — the provider's address matches an existing identity, but the provider did not mark it verified. The user signs in normally and links from settings.
- `409 oauth.linked_elsewhere` — this provider account already belongs to another user.
- `403 oauth.sign_up_disabled` — `oauth.NoSignUp` is set and nothing matched: the person needs an invitation or an existing account.
- `403 oauth.email_unverified` — `oauth.RequireVerifiedEmail` is set and the provider did not vouch for the address.
- `409 oauth.email_mismatch` — `oauth.RequireSameEmailOnLink` is set and the provider account's address is not one of the user's identities.
- `400 oauth.bad_scope` — `/start?scopes=` named a scope the provider does not list in `OptionalScopes`.
- `400 oauth.bad_param` — `/start?params=` named a parameter the provider does not list in `OptionalParams`, or did not parse.
- `403 oauth.email_not_found` — `RequireEmail` or `VerifyEmailBeforeSignIn` is set and the provider shared no address; ask for the email scope, or let the person allow it at the provider.
- `?error=oauth.email_not_verified` — not a failure: `VerifyEmailBeforeSignIn` created the user and is waiting for the address to be verified.
- `400 oauth.params_unsupported` — `prompt`, `loginHint` or `scopes` were sent to a custom `Provider` that does not implement `oauth.ParamsProvider`.
- `401 oauth.id_token_invalid` "The sign-in token was not accepted." — the ID token is malformed, forged, expired, for another issuer or audience, or its nonce does not match what the app sent. The log says which (`oauth: id token refused provider=… error=…`).
- `401 oauth.id_token_replayed` "This sign-in token was already used. Sign in with the provider again." — the ID token was already accepted once, by a sign-in or a re-authentication ([replay protection](#replay-protection)). The app asks the SDK for a new token; one that keeps its last token must refresh it. Repeated from devices you do not know, it is a stolen token: watch for `token.replay` on the security stream.
- `auth.New` fails with `oauth.ErrIDTokenReplayConfig` — `WithIDTokenReplayGuard` and `AllowIDTokenReplay` are both set, or the verification store cannot refuse a duplicate (a custom store without `auth.ExclusiveVerificationStore`, or a key-value storage without `SetIfAbsent`).
- `400 oauth.id_token_unsupported` — the provider has no key set: an issuer whose discovery document lacks `jwks_uri`, or an `*oauth.OAuth2` without `IDToken`.
- `401 oauth.nonce_required` — `IDToken.RequireNonce` is set and the token carries no nonce.
- `404 oauth.logout_unsupported` — the provider has no end-session endpoint; on `POST /auth/oauth/logout`, also a provider that is not configured.
- `400 oauth.logout_provider` "Name the provider to sign out of." — `POST /auth/oauth/logout` without a `provider`, or a provider's own logout route with another provider in the body.
- `400 oauth.state_invalid` on a dashboard tile — the provider is named in neither `oauth.RestartProviderInitiated` nor `oauth.AllowProviderInitiated`, so its state-less callback is refused as login forgery would be (Step 16).
- `auth.New` fails with `oauth.ErrProviderInitiatedConfig` — a provider-initiated option names a provider that is not configured, both name the same one, or `AllowProviderInitiated` names one that cannot verify ID tokens.
- `auth.New` fails with `oauth.ErrFallbackIncomplete` — an OIDC `Fallback` sets some endpoints but not `AuthURL`, `TokenURL` and `UserInfoURL`.
- `auth.New` fails with `oauth.ErrAllProvidersBroken` — `SkipBrokenProviders` left every provider out; the error names each one's reason.
- `400 oauth.data_too_long` — `data=` on the start link is longer than 1024 characters.
- `auth.New` fails with "oauth: IDToken needs JWKSURL and Issuers (ProfileFromToken needs both)" — an `IDToken` configuration is half filled.
- `auth.New` fails with "oauth: a provider needs AuthURL, TokenURL (or GetToken), ClientID, FetchProfile (or IDToken.ProfileFromToken) and a known TokenAuth (no secret for a PublicClient)" — an `*oauth.OAuth2` is incomplete or contradictory.
- `409 auth.last_sign_in_method` — unlinking would leave no way in.
- `404 oauth.not_linked` — unlinking a provider the user does not have.
- `403 oauth.reauth_not_linked` "Continue with the provider account that is linked to this account." — a re-authentication named a provider the user has no account at, or the person picked another account at the provider (someone else's, or one never linked). Nothing changed; the session stays signed in and stale.
- `400 oauth.state_invalid` after a re-authentication — the callback arrived on another session than the one that started it (a sign-out and sign-in in between, or the URL opened in another browser); `auth.signed_out` when it arrived with no session at all, which is what `authhttp.SameSiteStrict` causes.
- `404 oauth.no_tokens` — `Tokens` without `StoreTokens`, for a user who has not linked the provider, or for an account linked before tokens were stored.
- `502 oauth.refresh_failed` — the provider refused the refresh; the user links again.
- `auth.New` fails with "oauth: provider name "…" must match …" — provider names are lowercase letters, digits and underscores, up to 31 characters, because they are route segments and stored values.
- A callback that lands on your app over plain HTTP sets no session: the `__Host-` cookie needs HTTPS. Development on `localhost` works because browsers treat it as secure.

## Next

- [Sessions](../concepts/sessions.md): what the callback issued.
- [Security](../concepts/security.md): the state, the flow cookie and the origin check in one place.
- [Password](password.md) and [Email](email.md): the "other way in" that makes unlinking possible.
- Reference: [plugin/oauth/README.md](../../plugin/oauth/README.md), [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/oauth).

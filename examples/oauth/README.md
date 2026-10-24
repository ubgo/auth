# OAuth: sign in with GitHub, Google or any OpenID Connect issuer

People sign in with a provider account next to an email and password. Providers come from environment variables, state and PKCE are always on, and a provider that vouches for an address someone already verified signs in to that account instead of creating a second one.

## Run it

Register an OAuth app at the provider with the callback URL `http://localhost:8081/auth/oauth/<provider>/callback`, then:

```sh
cd examples
GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… go run ./oauth
```

| Provider | Variables | Callback URL |
|---|---|---|
| GitHub | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | `http://localhost:8081/auth/oauth/github/callback` |
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | `http://localhost:8081/auth/oauth/google/callback` |
| Any OpenID Connect issuer (Okta, Auth0, Keycloak, Entra ID, Zitadel) | `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | `http://localhost:8081/auth/oauth/oidc/callback` |

Only the providers whose variables are all set are offered. With none set, the program refuses to start:

```text
2026/09/29 13:46:19 no provider configured: set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET
exit status 1
```

Without that check the library would refuse anyway: `oauth.New` with no providers fails `auth.New` with `oauth: no providers`, rather than serving a sign-in page with nothing on it.

Open `http://localhost:8081/` in a browser and click the link. Run the tests with `go test ./oauth`.

## Walkthrough

This transcript was captured with placeholder GitHub credentials (`GITHUB_CLIENT_ID=Iv1.example`), so it stops where GitHub would take over: a real round trip needs a real client id and a browser signed in at GitHub. The full round trip runs in the tests against a fake issuer, below.

The server prints the callback URL to register:

```text
2026/09/29 13:45:36 provider github: callback URL http://localhost:8081/auth/oauth/github/callback
2026/09/29 13:45:36 listening on http://localhost:8081
```

The home page offers the configured providers:

```sh
curl -s localhost:8081/
```

```html
<!doctype html>
<title>OAuth example</title>
<p><a href="/auth/oauth/github/start?returnTo=/me">Sign in with github</a></p>
```

Start sends the browser to GitHub with a PKCE challenge and a single-use state, and binds the same state to this browser in the `__Host-auth_flow` cookie:

```sh
curl -si -c cookies.txt 'localhost:8081/auth/oauth/github/start?returnTo=/me'
```

```text
HTTP/1.1 302 Found
Location: https://github.com/login/oauth/authorize?client_id=Iv1.example&code_challenge=JymiEwmenTwULUszX0Z9UH7044dpQ_O12Dlo8gyjXTg&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Foauth%2Fgithub%2Fcallback&response_type=code&scope=read%3Auser+user%3Aemail&state=yOjFaAPqcEySrPN1bbEbbtLdAuP3LFfg7gCPFq-reEc
Set-Cookie: __Host-auth_flow=yOjFaAPqcEySrPN1bbEbbtLdAuP3LFfg7gCPFq-reEc; Path=/; Expires=Tue, 29 Sep 2026 08:25:36 GMT; HttpOnly; Secure; SameSite=Lax
```

A callback whose state is not the one bound to this browser is refused. This is the defence against login CSRF: an attacker cannot hand a victim a callback link that signs them in to the attacker's account.

```sh
curl -s -b cookies.txt 'localhost:8081/auth/oauth/github/callback?code=anything&state=forged'
```

```json
{"error":{"code":"oauth.state_invalid","message":"This sign-in link has expired. Start again."}}
```

A person who clicks "Cancel" at the provider comes back with an error, which is reported as such:

```sh
curl -s -b cookies.txt 'localhost:8081/auth/oauth/github/callback?error=access_denied'
```

```json
{"error":{"code":"oauth.denied","message":"Sign-in was cancelled at the provider."}}
```

With real credentials, the callback exchanges the code, creates or finds the user, sets the session cookie, and redirects to `returnTo` (`/me` here).

## The tests

`main_test.go` runs a fake OpenID Connect issuer on `httptest` (discovery, authorize, a token endpoint that checks the client secret and the PKCE verifier, userinfo) and configures it exactly as main does, through `providersFromEnv` with `OIDC_ISSUER` pointing at the fake. No test-only code path exists in the app.

```text
=== RUN   TestOAuth_NewPersonGetsAnAccount
--- PASS: TestOAuth_NewPersonGetsAnAccount (0.12s)
=== RUN   TestOAuth_VerifiedAddressLinksToTheExistingAccount
--- PASS: TestOAuth_VerifiedAddressLinksToTheExistingAccount (0.21s)
=== RUN   TestOAuth_NoProvidersNoStart
--- PASS: TestOAuth_NoProvidersNoStart (0.00s)
PASS
```

- A new person goes start, consent, callback, lands on `/me` with a session; the same person again is the same account.
- Someone who signed up with a password and verified `alice@example.com`, then signs in with a provider that says `alice@example.com` is verified, lands in the same account.
- A provider that returns the same address unverified is refused with `oauth.account_exists` (409): linking on an unverified claim would hand the account to whoever controls the provider account.

## The code

Providers from the environment, one line each. `oauth.OIDC` discovers the issuer's endpoints on the first sign-in and refuses a discovery document naming another issuer:

```go
if id, secret := getenv(envGitHubID), getenv(envGitHubSecret); id != "" && secret != "" {
	out = append(out, oauth.GitHub(id, secret))
}
if iss, id, secret := getenv(envOIDCIssuer), getenv(envOIDCID), getenv(envOIDCSecret); iss != "" && id != "" && secret != "" {
	out = append(out, oauth.OIDC(oidcProviderName, iss, id, secret))
}
```

The plugin list: the email plugin is what makes linking by verified address possible, and the password plugin is a second way in.

```go
auth.WithPlugins(
	email.New(email.Login(), email.Recover(), email.WithMailer(m)),
	password.New(),
	oauth.New(oauth.WithProviders(providers...)),
)
```

Every provider gets `GET /auth/oauth/<provider>/start` and `/callback`; `GET /auth/oauth/accounts` lists a user's linked providers and `POST /auth/oauth/unlink` removes one (refused if it is the last way in).

Limits of this example: provider tokens are not kept (add `oauth.StoreTokens(key)` with a 32-byte key to call the provider's API later and read them with `Tokens`), and the app runs on plain HTTP on localhost, which providers accept for development only.

## What this used

- [`plugin/oauth`](https://pkg.go.dev/github.com/ubgo/auth/plugin/oauth): `New`, `WithProviders`, `GitHub`, `Google`, `OIDC`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, `CurrentUser`
- Related: [quickstart](../quickstart) (the same app without providers), [ready-made-pages](../ready-made-pages).

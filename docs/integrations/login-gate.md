# Login gate: sign-in with no database

You will have an internal dashboard that only people with a verified address at your company's domain can open, signed in with Google or any OpenID Connect provider, with no database, no user table and no `auth.New`. The sign-in lives in a sealed cookie.

## When to use it, and when not to

`authgate` is a login gate, not user accounts. It is a separate, opt-in package next to the library; nothing in `auth.New` changes because it exists.

Use it for:

- an internal tool behind company login (an admin page, a metrics dashboard, a staging site);
- a prototype that needs "who is this" before it needs a database;
- a tool that acts on the person's own GitHub or Google account, with the provider's tokens kept in the cookie;
- a serverless function with nowhere to keep rows.

What it does not have, because each of these needs a stored row it does not keep:

- **No per-device sign-out and no "sign out everywhere" for one person.** Revocation is all or nothing: raise `authgate.SessionVersion` (or rotate the secret without keeping the old one) and everyone signs in again. Each cookie also has an absolute expiry, [a week by default](ds:block?id=authgate-defaults-7pm2wn4q), never extended by activity.
- **No passwords, magic links, passkeys or second factors.** Sign-in is a provider's, and so is its second factor.
- **No bans, no admin, no user list.** Shutting someone out means changing the Allow rule and deploying; rules are rechecked on every request, so that takes effect at once.
- **No account linking.** The same person through Google and through GitHub is two profiles; `Profile.ID()` is provider and subject.

When any of these is needed, use `auth.New` with [`plugin/oauth`](../plugins/oauth.md). The provider values you configured carry over unchanged, because the gate runs `plugin/oauth`'s own providers.

## Before you start

- The example is [`examples/login-gate`](../../examples/login-gate/main.go). Its test runs the whole sign-in against a fake OpenID Connect issuer.
- `authgate` is in the core module (`github.com/ubgo/auth/authgate`): it needs nothing beyond the standard library.
- A secret of at least [32 bytes](ds:block?id=minsecretsize-7wq2kx9m): `openssl rand -base64 32`.
- A client id and secret at the provider, with the callback URL `<base URL>/auth/<provider>/callback` registered. `Gate.CallbackURL` prints it.

## Step 1 — Build the gate

`authgate.New` takes the providers, the secret, the public origin and at least one Allow rule. The example reads them from the environment:

<!-- ds:block id=logingate-newgate-5wn8qk3t -->
**newGate** · [`examples/login-gate/main.go:84-118`](../../examples/login-gate/main.go#L84-L118)

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

`AllowEmailDomain` admits only an address the provider marked verified, and matches the domain exactly: `mycompany.com` does not admit `eu.mycompany.com`. Several rules admit when any one does; `authgate.Allow(func(p authgate.Profile) bool)` is the general form, and `authgate.AllowAnyone()` is the explicit choice for a tool that guards nothing of yours. With no rule at all `New` fails, because "everyone with a Google account" is never what a company dashboard means.

`New` refuses a configuration nobody could sign in with: no provider, a provider `oauth.ValidateProvider` refuses (the check `plugin/oauth` runs), a missing or short secret, a base URL that is not an http or https origin, two providers with one name.

Check: with no provider variables, the program says what to set and stops:

```sh
go run ./login-gate
```

```text
2026/10/05 20:39:19 no provider configured: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET
```

## Step 2 — Mount the routes and protect the pages

<!-- ds:block id=logingate-newhandler-8tq2vm6r -->
**newHandler** · [`examples/login-gate/main.go:124-129`](../../examples/login-gate/main.go#L124-L129)

```go
func newHandler(g *authgate.Gate) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", g.Handler())
	mux.Handle("/{$}", g.RequireUser(http.HandlerFunc(dashboard)))
	return mux
}
```
<!-- /ds:block hash=35e6c7 -->

`g.Handler()` serves, under `/auth`:

| Route | What it does |
|---|---|
| `GET /auth/{provider}/start?returnTo=/path` | seals a fresh state and PKCE verifier into the `__Host-authgate_flow` cookie and redirects to the provider |
| `GET /auth/{provider}/callback` | checks the state against the flow cookie, exchanges the code, applies the Allow rules, writes the `__Host-authgate_session` cookie and redirects to `returnTo` |
| `POST /auth/{provider}/callback` | for a form-post provider (Apple): relays the answer to the GET callback, where the flow cookie travels |
| `POST /auth/sign-out?returnTo=/path` | clears the session cookie; refused from another site |
| `GET /auth/session` | the signed-in profile as JSON, or 401 `auth.signed_out` |

`g.RequireUser` serves the page only to a signed-in, allowed person. A browser navigation that is not signed in is sent to sign in, with `returnTo` the page it asked for; any other request gets 401. `g.Middleware` puts the profile in the context without refusing anyone, for pages that greet a signed-in visitor. Either way, the handler reads it with `authgate.CurrentProfile(r)`.

```sh
AUTH_SECRET=0123456789abcdef0123456789abcdef ALLOWED_DOMAIN=mycompany.com \
GOOGLE_CLIENT_ID=example.apps.googleusercontent.com GOOGLE_CLIENT_SECRET=placeholder go run ./login-gate
```

```text
2026/10/05 20:39:19 provider google: callback URL http://localhost:8081/auth/google/callback
2026/10/05 20:39:19 listening on http://localhost:8081
```

A browser opening the dashboard is sent to sign in; an API call gets 401:

```sh
curl -si -H 'Accept: text/html' localhost:8081/
```

```text
HTTP/1.1 302 Found
Location: /auth/google/start?returnTo=%2F
```

```sh
curl -s localhost:8081/
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## Step 3 — Follow a sign-in

Start redirects to the provider with a PKCE challenge and a random state, and binds both to this browser in a sealed, `HttpOnly`, `Secure`, `SameSite=Lax` cookie that lasts [ten minutes](ds:block?id=authgate-defaults-7pm2wn4q):

```sh
curl -si -c cookies.txt 'localhost:8081/auth/google/start?returnTo=/'
```

```text
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?client_id=example.apps.googleusercontent.com&code_challenge=1YoCLB0XgCCyK7Mn1MsLb_x8IObmNQ1I0m7eY05-fk8&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Fgoogle%2Fcallback&response_type=code&scope=openid+email+profile&state=f0FYfiwz02nsYYRQ3Of4zgNizUrlT4Ku55JdU-5JEVM
Set-Cookie: __Host-authgate_flow=BlvfgGSCQhTXX3v8DCHZbssSX7rQAwcqQFNdv+PVIwBmGl2/uhTRAPkXCzCAtL8aIhOp9+PS59rInhqsloYx1qE+YlcMAYEu6fj5UZIvGueU9hY1b90Z3q0sm0afgYbWCbl+9yzkG1lGCgVDwTmeom0NS3tNWVd3AnoTmP1f7Lr4Ww8EDPfhmzuJ9Ib6Ha7dmN55LIKw8ugPyDNCz0FU7e7cNboiMJY; Path=/; Expires=Mon, 05 Oct 2026 15:19:19 GMT; HttpOnly; Secure; SameSite=Lax
```

A callback whose state is not the one sealed into this browser's flow cookie is refused. This is the defence against login CSRF, the same one `authhttp`'s flow cookie gives, with nothing stored: an attacker cannot hand a victim a callback link that signs them in as the attacker.

```sh
curl -s -b cookies.txt 'localhost:8081/auth/google/callback?code=anything&state=forged'
```

```json
{"error":{"code":"oauth.state_invalid","message":"This sign-in link has expired. Start again."}}
```

A return address must be a path on this site:

```sh
curl -s 'localhost:8081/auth/google/start?returnTo=https://evil.example/'
```

```json
{"error":{"code":"authgate.bad_return_to","message":"The return address must be a path on this site."}}
```

The rest of the round trip needs a real provider and a browser signed in there; it runs in the example's test against a fake issuer: the dashboard answers `Hello Ada (ada@mycompany.com), signed in with oidc until …`, an address at another domain or an unverified company address gets 403 `authgate.not_allowed` and no cookie, and a restart with a higher `SESSION_VERSION` sends everyone back to sign in.

## Step 4 — Sign out

Sign-out is a `POST`, so a link or an image on another site cannot sign anyone out, and a post from another site is refused:

```sh
curl -s -X POST -H 'Sec-Fetch-Site: cross-site' localhost:8081/auth/sign-out
```

```json
{"error":{"code":"authgate.cross_site","message":"This request came from another site."}}
```

The dashboard's own form (`<form method="post" action="/auth/sign-out">`) clears the cookie and lands on `/`. Sign-out ends the session in this browser only; there is no list of the person's other browsers to end.

## Keeping the provider's tokens

`authgate.KeepTokens()` keeps the access token, refresh token, their expiry and the granted scope in the sealed session cookie, read back as `Profile.Tokens`, for a tool that calls the provider's API as the person. It is off by default, so a cookie normally holds nothing that works at the provider. The ID token and the raw token answer are never kept. Nothing refreshes the tokens into the cookie: when the access token expires before the session, the person signs in again. A session that would exceed [4096 bytes](ds:block?id=authgate-defaults-7pm2wn4q), the per-cookie size every browser accepts, is refused with `authgate.cookie_too_large` and logged, never written for the browser to drop silently; Entra ID tokens can be large enough to hit it.

## Rotating the secret

`authgate.WithSecret(newSecret, oldSecret)` seals with the first and opens with every one, so cookies from before the rotation keep working until they expire; drop the old secret after one session lifetime. The keys come from the secret by the same HKDF rule `auth.WithSecret` uses, under the gate's own label, so sharing `AUTH_SECRET` with an `auth.New` app shares no key with it.

## Errors

| Code | Status | When |
|---|---|---|
| [`authgate.not_allowed`](ds:block?id=authgate-errors-6tq3vm8w) | 403 | no Allow rule admits the profile |
| `authgate.cookie_too_large` | 500 | the session would not fit in one cookie |
| `authgate.bad_return_to` | 400 | `returnTo` is not a path on this site |
| `authgate.unknown_provider` | 404 | the route names a provider the gate was not given |
| `authgate.cross_site` | 403 | a sign-out posted from another site |
| `authgate.method_not_allowed` | 405 | a POST on the callback of a provider that does not post back |
| `oauth.state_invalid` | 400 | the state or the flow cookie is missing, forged, expired or for another provider, or the issuer does not match |
| `oauth.denied` | 400 | the person cancelled at the provider |
| `oauth.provider_failed` | 502 | discovery or the code exchange failed; the log says why |
| `auth.signed_out` | 401 | `RequireUser` or `/auth/session` without a session |

`authgate.ErrorHandler` answers every one of them with the app's own page instead of the JSON body.

## What can go wrong

Every one of these is pinned by a test in [`authgate/authgate_test.go`](../../authgate/authgate_test.go) (`TestNew_RefusesBrokenConfiguration`, `TestGate_AllowRules`, `TestGate_Revocation`, `TestGate_KeepTokens`).

| You see | Why | Fix |
|---|---|---|
| `authgate: no Allow rule; pass Allow, AllowEmailDomain, AllowEmails or AllowAnyone` from `New` | A gate with no rule would let in anyone a provider vouches for, a whole consumer Google included, so it refuses to start. | Add a rule. `AllowAnyone()` is the explicit way to say "any signed-in account". |
| `authgate: no providers; pass WithProviders` or `authgate: two providers share a name` | No provider was given, or two have one name, so the callback URL would be ambiguous. | Give each provider its own name (`oauth.OIDC("okta", …)`). |
| `authgate: WithSecret: auth: the secret must be at least 32 bytes` from `New` | `WithSecret` was given less than 32 bytes, or a previous secret in the rotation list is short. | `openssl rand -base64 32`, for every secret in the list. |
| `authgate: WithBaseURL must be an http or https origin …` | The base URL has a path, a query, a user or another scheme. It is an origin only; the routes add the prefix themselves. | Pass `https://tools.example.com`, not `https://tools.example.com/app`. `http://localhost:8082/` is accepted for development. |
| `authgate: bad option` from `New` | An option's value cannot work: a zero `SessionLifetime`, an empty `AllowEmailDomain` or `AllowEmails` list, a `nil` rule, a `SignInPage` on another site, or a `Prefix` that is not a path. | The wrapped message names the option. |
| `authgate.not_allowed` (403) for a colleague | `AllowEmailDomain` matches the domain exactly and only when the provider marked the address verified: `example.com` does not admit `eu.example.com`, nor an unverified `ada@example.com`. | List each subdomain. For a provider that does not verify addresses, admit by subject with `Allow(func(p authgate.Profile) bool { … })` instead. |
| Everyone is signed out after a deploy | `SessionVersion` was raised, or the secret was rotated without keeping the old one in `WithSecret(new, old)`. Both are the gate's only revocation, by design. | To rotate without signing people out, keep the old secret until one session lifetime has passed. |
| A signed-in person is suddenly anonymous, and their cookie is cleared | Rules are checked again on every request, so a narrower rule shuts out existing cookies at once. | Expected. Widen the rule if it was a mistake. |
| `authgate.cookie_too_large` (500) after a sign-in with `KeepTokens` | The sealed profile plus the provider's tokens would exceed 4096 bytes, which browsers drop without a word. Entra ID tokens are the usual cause. | Drop `KeepTokens`, or ask for fewer scopes. |
| `oauth.state_invalid` (400) on the callback | The flow cookie is missing: the browser blocked it, the sign-in started on another host than `WithBaseURL`, or it took longer than the flow lifetime. | Start the sign-in from the base URL's own host. |
| The person must sign in again although the session is young | The access token in `Profile.Tokens` expired. Nothing refreshes tokens into the cookie. | Sign in again, or keep your own store and use `auth.New` with `plugin/oauth`. |

## Next

- [OAuth](../plugins/oauth.md) for every provider the gate can use and their options.
- [net/http, chi and gorilla](net-http.md) for the user accounts, sessions and routes `auth.New` gives when the gate is not enough.
- The package's [README](../../authgate/README.md) is the reference for every option.

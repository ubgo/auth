# github.com/ubgo/auth/plugin/oauth/oauthtest

A conformance kit for `oauth.Provider` implementations. One call drives the provider against a fake authorization server and checks every rule the OAuth plugin relies on, so a provider written for one app, a preset, or an adapter over another OAuth library proves itself in a test rather than in production.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module and imports only the standard library, the core and `plugin/oauth`, so a provider's tests can use it from any module.

## Use it

[`oauthtest.Run`](ds:block?id=oauthtest-run-h4kw9qzt)`(t, newProvider, opts...)` starts the server and calls `newProvider(serverURL)` once per case. Build the provider with `oauthtest.ClientID`, `oauthtest.ClientSecret` and the server's endpoints; the kit passes `oauthtest.RedirectURI` to `AuthCodeURL` and `Exchange`, and a provider that fixes its own redirect URI (goth) is built with that value.

<!-- ds:block id=testconformance-oauth2userinfo-z75vqp6t -->
**TestConformance_OAuth2UserInfo** · [`plugin/oauth/oauthtest/providers_test.go:76-81`](providers_test.go#L76-L81)

```go
func TestConformance_OAuth2UserInfo(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return pointAt(&oauth.OAuth2{ID: "corp", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
	}, oauthtest.WantScopes("openid", "email"))
}
```
<!-- /ds:block hash=7b7d83 -->

An OpenID Connect provider takes the server URL as its issuer (`oauth.OIDC("corp", u, oauthtest.ClientID, oauthtest.ClientSecret)`); the discovery document at `DiscoveryPath` names every endpoint. A provider whose profile API is not userinfo adds the endpoints it calls with `Route` and renders the person the way its API does; [providers_test.go](providers_test.go) does that for GitHub, Discord and Zoom:

<!-- ds:block id=testconformance-github-8d2nun37 -->
**TestConformance_GitHub** · [`plugin/oauth/oauthtest/providers_test.go:61-73`](providers_test.go#L61-L73)

```go
func TestConformance_GitHub(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		g := pointAt(oauth.GitHub(oauthtest.ClientID, oauthtest.ClientSecret), u)
		g.FetchProfile = oauth.GitHubProfile(u + "/github")
		return g
	}, oauthtest.WantScopes("user:email"),
		oauthtest.Route("/github/user", func(p oauthtest.Person) any {
			return numericID(map[string]any{"login": "octo", "name": p.Name}, p.Subject)
		}),
		oauthtest.Route("/github/user/emails", func(p oauthtest.Person) any {
			return []map[string]any{{"email": "old@example.com", "primary": false, "verified": true}, {"email": p.Email, "primary": true, "verified": p.EmailVerified}}
		}))
}
```
<!-- /ds:block hash=26d3b1 -->

## The server

| Path | Constant | Answers |
|---|---|---|
| `/.well-known/openid-configuration` | `DiscoveryPath` | the discovery document; the server URL is the issuer |
| `/authorize` | `AuthorizePath` | a 302 to the redirect URI with a code and the state, after checking `response_type=code`, the client id, the redirect URI, a state and (when sent) an S256 challenge; 400 with the reason otherwise |
| `/token` | `TokenPath` | the `authorization_code` grant: the client secret in the form or as HTTP Basic (the id alone under `PublicClient`), a single-use code, the same redirect URI and the PKCE verifier when a challenge was sent; an `id_token` (ES256) when `openid` was granted, with the nonce the request sent |
| `/userinfo` | `UserInfoPath` | `sub`, `email`, `email_verified` and `name` of the bearer token's person |
| `/jwks` | `JWKSPath` | the ID-token key |

## The rules

| Case | What the provider must do |
|---|---|
| the name is a route segment | `Name()` matches `auth.KindNamePattern` |
| the authorization URL carries the client, redirect, state, scope and PKCE challenge | the server's authorization endpoint, `response_type=code`, `ClientID`, `RedirectURI`, the state it was given, every scope `WantScopes` names, and `code_challenge` = the challenge it was given with method `S256` |
| a verified address signs in with the subject, email and verified flag | the subject and email exactly, `EmailVerified` true, and the issued access token in `Profile.Tokens` |
| an unverified address is never reported verified | `EmailVerified` false when the server said false |
| the token endpoint's error answer is an error | an unknown or reused code (`invalid_grant`) fails |
| a wrong PKCE verifier is refused | the verifier it was given is the one sent |
| a token answer that is not JSON is an error | an HTML answer fails |
| a token answer without an access token is an error | `{"token_type":"Bearer"}` fails |
| a failing profile endpoint is an error | a 500 from the profile endpoint fails; skipped for a provider that reads its profile from the ID token |
| a profile without a subject is refused | an answer with no subject fails, so no account is keyed on "" |

## Options

| Option | Effect |
|---|---|
| `WantScopes(scopes...)` | the authorization URL must carry each one; without it the scope is not checked (Zoom sets scopes on the app) |
| `NoPKCE()` | for a provider that cannot send a challenge: the URL must then carry none (so the declaration cannot go stale), the verifier case is skipped, `Report.PKCE` is false and the run logs it |
| `NeverVerified()` | for a provider whose API says nothing about verification: `EmailVerified` must be false even for a verified person |
| `PublicClient()` | the token endpoint expects the client id and no secret |
| `Route(path, render)` | an extra bearer-protected GET profile endpoint answering `render(person)` as JSON; leave the subject out when `Person.Subject` is "" |

`Run` returns a `Report` (`Provider`, `PKCE`, `ReportsVerified`, `ProfileCall`) and logs it, so a provider's weaker guarantees show in the test output.

## Tests

The kit is itself tested by breaking it: [oauthtest_test.go](oauthtest_test.go) runs every case against providers that each break one rule (another client id, a dropped state, no challenge, a stale `NoPKCE`, a verified claim for an unverified address, a swallowed error, a missing access token) and asserts which case refuses it and why; `TestServer_Refusals` checks the server's own refusals directly.

| Run against | Test |
|---|---|
| `oauth.Google`, `oauth.GitHub`, `*oauth.OAuth2` (userinfo, ID-token profile, public client), `oauth.OIDC`, `oauth.Okta`, `oauth.Keycloak`, `oauth.GitLab`, `oauth.Zitadel`, `oauth.Discord`, `oauth.Zoom` | [providers_test.go](providers_test.go) |
| any goth provider through `authgoth.Wrap` | [contrib/goth](../../../contrib/goth/goth_test.go) |

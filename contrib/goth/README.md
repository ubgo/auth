# github.com/ubgo/auth/contrib/goth

Lets the OAuth plugin sign people in through any [goth](https://github.com/markbates/goth) provider. An app that already configures goth keeps its provider setup, and an app that needs one of goth's providers the plugin has no preset for gets it, while state, the flow cookie, account linking, the verified-email rules, rate limits and hooks stay in `plugin/oauth`.

## Install

```sh
go get github.com/ubgo/auth/contrib/goth
```

This is its own module because it imports `github.com/markbates/goth` and `golang.org/x/oauth2`; the core module depends on the standard library and sqlb only. The package name is `authgoth`.

## Wire it

[`authgoth.Wrap`](ds:block?id=authgoth-wrap-m7tq3xnv)`(gothProvider)` returns an `oauth.Provider`. Build the goth provider with the plugin's callback URL, rename it to a route segment, and pass `authgoth.Wrap(gp)` to `oauth.WithProviders` like any other provider. The conformance test builds one, pointed at a test server; in production the URL is the issuer's discovery document and the callback is `BaseURL + "/auth/oauth/corp/callback"`:

<!-- ds:block id=testconformance-openidconnect-2pka7v7u -->
**TestConformance_OpenIDConnect** · [`contrib/goth/goth_test.go:17-29`](goth_test.go#L17-L29)

```go
func TestConformance_OpenIDConnect(t *testing.T) {
	rep := oauthtest.Run(t, func(u string) oauth.Provider {
		gp, err := openidConnect.New(oauthtest.ClientID, oauthtest.ClientSecret, oauthtest.RedirectURI, u+oauthtest.DiscoveryPath, "email", "profile")
		if err != nil {
			t.Fatalf("openidConnect.New: %v", err)
		}
		gp.SetName("corp")
		return authgoth.Wrap(gp)
	}, oauthtest.NoPKCE(), oauthtest.WantScopes("openid", "email", "profile"))
	if rep.PKCE || !rep.ReportsVerified || rep.Provider != "corp" {
		t.Fatalf("report = %+v", rep)
	}
}
```
<!-- /ds:block hash=ca353a -->

No goth type appears in the adapter's API: it takes a `goth.Provider` and returns the plugin's `oauth.Profile`. It only translates.

## The swap story

A linked account is stored as the provider name plus the provider's subject, both the plugin's own values. To move a provider from goth to a built-in constructor (or the other way), replace the `authgoth.Wrap(gp)` call with `oauth.OIDC("corp", issuer, id, secret)` and drop the import. Nothing else changes: the routes, the callback URL, the stored accounts and every session stay as they were, as long as the name and the provider's subject are the same.

## What the adapter maps

| goth | `oauth.Profile` |
|---|---|
| `UserID` | `Subject`; empty is refused (`oauth.ErrExchange`), so no account is keyed on "" |
| `Email` | `Email` |
| `RawData["email_verified"]` true (or `"true"`) | `EmailVerified`; absent or anything else is unverified, because `goth.User` has no verified field and an unverified address must never link to an existing account |
| `Name`, else `FirstName LastName`, else `NickName` | `Name` |
| `AvatarURL` | `Image` |
| `AccessToken`, `RefreshToken`, `IDToken`, `ExpiresAt` | `Tokens`, kept only with `oauth.StoreTokens` |
| `RawData` | `Claims`, for `oauth.ValidateProfile` and `oauth.OnResolved` |

## Limits, honestly

| Limit | Why | What it means |
|---|---|---|
| No PKCE | goth's `BeginAuth(state)` takes no code challenge | the authorization URL carries none and the code is protected by the state and the flow cookie alone; the built-in providers always send S256. `oauthtest` runs it with `NoPKCE()`, which fails the run if a challenge ever appears |
| The redirect URI is goth's | goth fixes the callback URL when the provider is built | build it with `BaseURL + "/auth/oauth/<name>/callback"`; `Exchange` refuses a mismatch with an error naming both |
| The HTTP client and context are goth's | goth's calls take neither | set the goth provider's own `HTTPClient` where it has one; a cancelled context is checked before the exchange starts |
| Plain OAuth 2.0 authorization-code providers only | the plugin keeps none of goth's session between start and callback | providers whose session carries a secret of their own (OAuth 1.0a request tokens, `twitterv2`'s PKCE verifier) do not work |
| No refresh, revocation, logout or ID-token route | the adapter implements `oauth.Provider` and `oauth.Discoverer` only | `Plugin.Refresh`, unlink revocation, the provider logout and native ID-token sign-in need a built-in provider |

Name: goth's own names (`openid-connect`, `corp-oidc`) do not match `auth.KindNamePattern`, so `auth.New` refuses them; call `SetName` first.

## Tests

| Property | Test |
|---|---|
| goth's openidConnect, pointed at the conformance kit's server, passes every case with `NoPKCE` | `TestConformance_OpenIDConnect` |
| The email is verified only on goth's explicit `email_verified`, never for an empty address | `TestWrap_VerifiedOnlyWhenGothSaysSo` |
| Every goth failure, a missing subject, a mismatched callback and a cancelled context are `oauth.ErrExchange` | `TestWrap_Failures` |
| `Discover` fails a start goth cannot begin, before any state is written | `TestWrap_Start` |

Proven by breaking: with the verified rule removed, `TestConformance_OpenIDConnect` fails its unverified-address case.

# OAuth rules: who the callback signs in, which accounts may, and dashboard tiles

The decisions an app makes once provider sign-in works. When a provider account's address matches an account that already exists, the callback links them only when both sides are verified; `LINKING=strict` never links by email and `LINKING=trusted` trusts one provider's addresses. A `ValidateProfile` hook refuses accounts from another company domain before anything is written, and an `OnResolved` hook copies the provider's login handle into the app's own column. A sign-in started from the identity provider's dashboard tile, which carries no `state`, is restarted as an ordinary flow bound to the browser instead of failing.

It needs no provider account. A small OpenID Connect issuer for development runs in the same process on `http://localhost:8083`: discovery, an authorize endpoint that consents at once for the person the start request's `loginHint` names, a token endpoint that checks the client secret and PKCE, userinfo with the `hd` and `preferred_username` claims, and a `/tile` page that plays the dashboard tile. Its directory, in [`issuer.go`](issuer.go):

| loginHint | Address | `email_verified` | `hd` | What it shows |
|---|---|---|---|---|
| `carol` (default) | carol@example.com | true | example.com | a new person gets an account |
| `alice` | alice@example.com | true | example.com | links to Alice's verified password account (refused under `strict`) |
| `alice-unflagged` | alice@example.com | false | example.com | refused (linked under `trusted`) |
| `dave` | dave@contractor.test | true | contractor.test | refused by the domain rule |

## Run it

```sh
cd examples
go run ./oauth-rules                  # both sides verified links
LINKING=strict go run ./oauth-rules   # oauth.NoImplicitLinking()
LINKING=trusted go run ./oauth-rules  # oauth.TrustedProviders("corp")
```

It creates `oauth-rules.db` (SQLite) and serves the app on `http://localhost:8081`; `PORT` and `ISSUER_PORT` move the two servers. Any other `LINKING` value is refused at start. Mail is printed to the log. Run the tests with `go test ./oauth-rules`.

The transcripts below were captured with `PORT=8091 ISSUER_PORT=8093`, because 8081 was taken on the machine that ran them; with the defaults, read 8081 and 8083.

```text
2026/10/09 15:50:44 issuer listening on http://localhost:8093; dashboard tile at http://localhost:8093/tile
2026/10/09 15:50:44 app listening on http://localhost:8091; linking rule ""; callback URL http://localhost:8091/auth/oauth/corp/callback
```

## Walkthrough

One flow by hand: the start route sends the browser to the issuer with the login hint, the issuer consents and sends it back to the callback, and the callback signs Carol up. `/me` shows the login the `OnResolved` hook wrote into `app_login`:

```sh
curl -si -c carol.txt 'localhost:8091/auth/oauth/corp/start?returnTo=/me&loginHint=carol' | grep -E '^(HTTP|Location)'
```

```text
HTTP/1.1 302 Found
Location: http://localhost:8093/authorize?client_id=dev-client&code_challenge=E2PuRtcA5ppkZAGP6DUt8AoNmWKB2A-szuVYy5-blDw&code_challenge_method=S256&login_hint=carol&redirect_uri=http%3A%2F%2Flocalhost%3A8091%2Fauth%2Foauth%2Fcorp%2Fcallback&response_type=code&scope=openid+email+profile&state=6fLtRRf43ErLa4t8a94S9xQy6neazcjstOcXtbDmSLs
```

After the issuer's consent and the callback (`Location: /me`):

```sh
curl -s -b carol.txt localhost:8091/me
```

```json
{"id":"usr_hnuokwes3wkasjo4acppffsn","name":"Carol","login":"carol"}
```

The rest uses a small shell function that runs the three steps and prints the callback's answer:

```sh
# signin <cookie-file> <login hint>: start, the issuer's consent, the callback.
signin() {
  consent=$(curl -s -c "$1" -o /dev/null -w '%{redirect_url}' "localhost:8091/auth/oauth/corp/start?returnTo=/me&loginHint=$2")
  callback=$(curl -s -o /dev/null -w '%{redirect_url}' "$consent")
  curl -s -b "$1" -c "$1" -w ' -> %{http_code} %{redirect_url}\n' "$callback"
}
```

### The domain rule

Dave's account is at `contractor.test`. The `ValidateProfile` hook returns the app's own `*auth.Error`, answered as it is, and nothing is written:

```sh
signin dave.txt dave
```

```text
{"error":{"code":"app.domain_not_allowed","message":"Sign in with your example.com work account."}}
 -> 403
```

### Linking by email

Alice signs up with a password and verifies her address from the mailed link:

```sh
curl -s -c pw.txt -X POST localhost:8091/auth/password/sign-up -H 'Origin: http://localhost:8091' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -X POST localhost:8091/auth/email/verify -H 'Origin: http://localhost:8091' -d '{"token":"WXJsxik-22Daxc5TUZ7eLmDrRIl79-y4g9DIZDd2UvA"}'
```

```json
{"user":{"id":"usr_is6e2zs6dngoaeqepb3g64le","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
```

The issuer returns her address without saying it verified it: refused, because a link needs both sides verified. Then with `email_verified: true`: linked to her password account, the same user id:

```sh
signin a1.txt alice-unflagged
signin a2.txt alice
curl -s -b a2.txt localhost:8091/me
```

```text
{"error":{"code":"oauth.account_exists","message":"An account with this email already exists. Sign in, then link this provider in settings."}}
 -> 409
 -> 302 http://localhost:8091/me
{"id":"usr_is6e2zs6dngoaeqepb3g64le","name":"Alice","login":"alice"}
```

Under `LINKING=strict` (a fresh database, Alice signed up and verified the same way) the verified match is refused too; she signs in with her password and links from settings:

```text
2026/10/09 15:51:42 app listening on http://localhost:8091; linking rule "strict"; callback URL http://localhost:8091/auth/oauth/corp/callback
{"error":{"code":"oauth.account_exists","message":"An account with this email already exists. Sign in, then link this provider in settings."}}
 -> 409
```

Under `LINKING=trusted`, `alice-unflagged` links like `alice` does; `TestRules_TrustedProviderLinksAnUnflaggedAddress` pins it.

### The dashboard tile

The tile sends the browser to the callback with a code and no `state`:

```sh
curl -si -c tile.txt localhost:8093/tile | grep -E '^Location'
curl -si -b tile.txt -c tile.txt 'localhost:8091/auth/oauth/corp/callback?code=tile-carol' | grep -E '^(HTTP|Location)'
```

```text
Location: http://localhost:8091/auth/oauth/corp/callback?code=tile-carol
HTTP/1.1 302 Found
Location: http://localhost:8093/authorize?client_id=dev-client&code_challenge=ZKiYJallpawrwzW_MnTfAuaUNpc7fKL2OHTIz6rCpGk&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8091%2Fauth%2Foauth%2Fcorp%2Fcallback&response_type=code&scope=openid+email+profile&state=fQXkvnDgDIg4URNHEf-bL-3YzHEHMcCX0clHUpmbedk
```

The code was dropped unread; the answer is a fresh flow with a state bound to this browser (the `__Host-auth_flow` cookie) and PKCE. The issuer signs Carol straight through, and the second callback is checked like any other and lands on `/`:

```text
Location: http://localhost:8091/auth/oauth/corp/callback?code=code-carol&state=fQXkvnDgDIg4URNHEf-bL-3YzHEHMcCX0clHUpmbedk
HTTP/1.1 302 Found
Location: /
{"id":"usr_hnuokwes3wkasjo4acppffsn","name":"Carol","login":"carol"}
```

## The code

<!-- ds:block id=oauthrules-newoauth-c8vn3wq5 -->
**newOAuth** · [`examples/oauth-rules/main.go:176-186`](main.go#L176-L186)

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

`onlyOurDomain` reads the `hd` claim from `ev.Profile.Claims`; `keepLogin` writes `preferred_username` with `auth.SetUserColumn(ctx, c.Auth, auth.AppName, ev.UserID, Login, login)` inside the sign-in's transaction, so a failed write rolls the sign-up back. The column is declared with `auth.WithUserColumns`.

`main_test.go` runs the same wiring behind an `httptest` TLS server with the issuer on `httptest`: a new person gets an account with their login, the default links only a verified match, `strict` refuses it, `trusted` links an unflagged address, the domain rule leaves no user and no cookie, the tile restarts a flow and the issuer never sees its code exchanged, and an unknown `LINKING` value is refused.

## What this used

- [`plugin/oauth`](https://pkg.go.dev/github.com/ubgo/auth/plugin/oauth): `OIDC`, `ValidateProfile`, `OnResolved`, `NoImplicitLinking`, `TrustedProviders`, `RestartProviderInitiated`, `ProfileEvent`, `ResolvedEvent`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithUserColumns`, `SetUserColumn`, `LoadUserColumns`, `NewError`
- Related: [oauth](../oauth) is the plain sign-in; [oauth-link-and-tokens](../oauth-link-and-tokens) links from settings and keeps the provider's tokens; the guide is [docs/plugins/oauth.md](../../docs/plugins/oauth.md) Steps 5, 11 and 16.

# OAuth: link a provider from settings and keep its tokens

The rest of the OAuth story once sign-in works: a person with a password account links an OpenID Connect provider from settings, sees it listed and unlinks it; and the app keeps the provider's tokens, sealed, and refreshes them before they expire so it can call the provider's API for the user.

It needs no provider account. A small OpenID Connect issuer for development runs in the same process on `http://localhost:8083`: discovery, an authorize endpoint that consents at once for a configurable person, a token endpoint that checks the client secret and PKCE and rotates refresh tokens, and userinfo. Every token it issues is numbered (`access-1`, `refresh-1`, …), so a refresh is visible.

## Run it

```sh
cd examples
go run ./oauth-link-and-tokens
```

It creates `oauth-link-and-tokens.db` (SQLite) and serves the app on `http://localhost:8081`. Set `TOKEN_KEY` to 32 bytes (base64url, no padding) to keep stored tokens readable across restarts; unset, a key is generated and the log says so. `ISSUER_SUBJECT` and `ISSUER_EMAIL` change the person the issuer vouches for (default `idp-1`, `carol@example.com`, verified); `ISSUER_EXPIRES_IN` sets the access-token lifetime in seconds (default 3600; use 30 to watch refreshes). Run the tests with `go test ./oauth-link-and-tokens`.

```text
2026/10/01 10:48:40 TOKEN_KEY is not set: sealing provider tokens with a new key; tokens stored before a restart will not open
2026/10/01 10:48:40 issuer listening on http://localhost:8083, signing in idp-1 <carol@example.com>, access tokens live 3600s
2026/10/01 10:48:40 app listening on http://localhost:8081; callback URL http://localhost:8081/auth/oauth/corp/callback
```

## Walkthrough

Alice signs up with a password, then links the provider from settings. The link flow is the start route with `link=true`; the development issuer consents at once and sends the browser back to the registered callback, which redirects to `returnTo` without issuing a new session.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_mls7ilfozcgjpyjf5heput75","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

```sh
curl -si -b cookies.txt -c cookies.txt 'localhost:8081/auth/oauth/corp/start?link=true&returnTo=/tokens'
```

```text
HTTP/1.1 302 Found
Location: http://localhost:8083/authorize?client_id=dev-client&code_challenge=qya4AMF5K4tDpQa9O90HWGkXRSOIxM_lwVCL8CLCofs&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Foauth%2Fcorp%2Fcallback&response_type=code&scope=openid+email+profile&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM
Set-Cookie: __Host-auth_flow=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM; Path=/; Expires=Tue, 06 Oct 2026 06:33:18 GMT; HttpOnly; Secure; SameSite=Lax
```

```sh
curl -si 'http://localhost:8083/authorize?client_id=dev-client&…&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM'
```

```text
HTTP/1.1 302 Found
Location: http://localhost:8081/auth/oauth/corp/callback?code=the-code&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM
```

```sh
curl -si -b cookies.txt -c cookies.txt 'localhost:8081/auth/oauth/corp/callback?code=the-code&state=VoEDr_NCNQFdYkf8OMEW0OQbeKh3ZCbydkndDvsHMlM'
```

```text
HTTP/1.1 302 Found
Location: /tokens
Set-Cookie: __Host-auth_flow=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
```

The account is listed (its `scopes` are the ones the provider said it granted; this development issuer names none), and the provider's tokens were kept:

```sh
curl -s -b cookies.txt localhost:8081/auth/oauth/accounts
```

```json
{"accounts":[{"id":"acc_ngza72ednj6roq33jzwdc6a4","provider":"corp","email":"carol@example.com","createdAt":"2026-10-06T06:23:18.15981Z","scopes":[]}]}
```

```sh
curl -s -b cookies.txt localhost:8081/tokens
curl -s -b cookies.txt localhost:8081/tokens
```

```json
{"accessToken":"access-1","refreshToken":"refresh-1","expiresAt":"2026-10-06T07:23:18.159524Z"}
{"accessToken":"access-1","refreshToken":"refresh-1","expiresAt":"2026-10-06T07:23:18.159524Z"}
```

Dave cannot link the same provider account to his own:

```sh
# dave signed up with a password in his own browser (dave.txt), then ran start?link=true and the consent step
curl -si -b dave.txt 'localhost:8081/auth/oauth/corp/callback?code=the-code&state=…'
```

```text
HTTP/1.1 409 Conflict
{"error":{"code":"oauth.linked_elsewhere","message":"This provider account is linked to another user."}}
```

Unlinking removes it; a second unlink and a token read afterwards are refused:

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

With `ISSUER_EXPIRES_IN=30` the access token is inside the plugin's refresh margin, so every read refreshes it and keeps the rotated refresh token:

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

## The tests

`main_test.go` runs the same issuer on `httptest` and drives the app over HTTPS with a cookie jar, step by step without following redirects:

- `TestLink_FromSettingsThenUnlink`: link from settings, the account list, another user refused with `oauth.linked_elsewhere`, unlink, `oauth.not_linked` on the second unlink, `oauth.no_tokens` afterwards.
- `TestTokens_StoredAndRefreshedBeforeExpiry`: with an hour left no refresh happens; with 30 seconds left every read refreshes and keeps the rotated refresh token.
- `TestSignIn_VerifiedAddressReachesTheExistingAccount`: the issuer vouches for the address a password user verified, so provider sign-in lands in that account.
- `TestTokenKey_FromTheEnvironment`: the key and the lifetime from the environment, and malformed values refused.

## What this used

- [`plugin/oauth`](https://pkg.go.dev/github.com/ubgo/auth/plugin/oauth): `New`, `WithProviders`, `OIDC`, `StoreTokens`, `Tokens`, the `start?link=true`, `accounts` and `unlink` routes
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, `CurrentUser`, `WriteError`
- Related: [oauth](../oauth) (sign-in with real providers from environment variables), the guide [docs/plugins/oauth.md](../../docs/plugins/oauth.md).

# OAuth popup: sign in from an app embedded in another site

An app that runs inside a customer's page signs its users in with an OpenID Connect provider even when the browser blocks or partitions third-party cookies. The embedded page opens a first-party popup on the auth origin; the provider sign-in completes there; the popup posts the new session token to the page, which sends it as `Authorization: Bearer` from then on.

The guide is [docs/plugins/oauthpopup.md](../../docs/plugins/oauthpopup.md).

## Run it

Register `http://localhost:8081/auth/oauth/oidc/callback` at an OpenID Connect provider, then:

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) OIDC_ISSUER=https://… OIDC_CLIENT_ID=… OIDC_CLIENT_SECRET=… go run ./oauth-popup
```

The auth app listens on `http://localhost:8081` and a stand-in for the customer's page on `http://localhost:8082`, the one origin the app trusts to open a popup. Open `http://localhost:8082` and press the button. `AUTH_SECRET` seals the popup's marker cookie; a missing or short one fails at start.

## Test it

The tests need no provider account: a fake OpenID Connect issuer on `httptest` stands in, and the app is driven in memory.

```sh
cd examples
go test -v ./oauth-popup
```

```text
=== RUN   TestPopup_HandsTheNewSessionToTheOpener
--- PASS: TestPopup_HandsTheNewSessionToTheOpener (0.03s)
=== RUN   TestPopup_RefusesAnUntrustedOpener
--- PASS: TestPopup_RefusesAnUntrustedOpener (0.01s)
=== RUN   TestPopup_OpenerPageNamesTheAuthOrigin
--- PASS: TestPopup_OpenerPageNamesTheAuthOrigin (0.00s)
PASS
ok  	github.com/ubgo/auth/examples/oauth-popup	0.696s
```

| Test | What it checks |
|---|---|
| `TestPopup_HandsTheNewSessionToTheOpener` | Start sets the marker; the provider callback answers with the completion page itself (`RewriteCallback`) under a CSP pinning its script; the posted message carries the opener's origin and nonce and the session the callback issued; that token works on `/api/me` as a bearer token; a second load of `/complete` posts `popup_sign_in_failed` |
| `TestPopup_RefusesAnUntrustedOpener` | A page on an origin the app does not trust gets 403 at start |
| `TestPopup_OpenerPageNamesTheAuthOrigin` | The customer's page checks messages against the auth origin and the message type |

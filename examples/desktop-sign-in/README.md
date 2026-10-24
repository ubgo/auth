# Desktop sign-in: through the system browser and back

A desktop app, a CLI or an Electron shell has no cookies and should not show its own password form: it opens the web app in the system browser, the person signs in there with whatever the web app offers (password, Google, a magic link, a passkey), and the browser hands the result back to the app. The hand-off is a three-minute single-use token from the [handoff plugin](../../plugin/handoff), sent to the app on a loopback address it listens on (RFC 8252) or on the app's own URL scheme, or shown for the person to paste when neither works. The app exchanges it for a bearer session of its own.

## Run it

Two processes. The web app:

```sh
cd examples
go run ./desktop-sign-in
```

It creates `desktop-sign-in.db` (SQLite), creates the tables and listens on `http://localhost:8081`; mail is printed to the log. Sign up once with curl (below) or through any client. Then the "desktop app", in a second terminal:

```sh
go run ./desktop-sign-in -app
```

It listens on a loopback port the OS picks, prints the URL to open, waits for the browser to come back, closes the listener, exchanges the token and prints who it is signed in as. Run the tests with `go test ./desktop-sign-in`.

## Walkthrough

Sign up on the web app, as a browser with a cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery","name":"Alice"}'
```

Start the app. It prints:

```text
open this URL in your browser:
http://localhost:8081/open-in-app?challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&returnTo=http%3A%2F%2F127.0.0.1%3A53241%2Fcallback
```

The `challenge` is the SHA-256 of a verifier the app made and kept (`handoff.NewVerifier`): the token the page mints will be exchanged only together with that verifier. Opening that URL as the signed-in browser shows a confirmation page with one button, "Open the app". The button POSTs; the page mints a hand-off token bound to the challenge and redirects the browser to `http://127.0.0.1:53241/callback?token=…`, which the app is serving. With curl, the two steps:

```sh
curl -s -b cookies.txt 'localhost:8081/open-in-app?challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&returnTo=http%3A%2F%2F127.0.0.1%3A53241%2Fcallback'
curl -s -i -b cookies.txt -X POST -H 'Origin: http://localhost:8081' \
  -d 'returnTo=http%3A%2F%2F127.0.0.1%3A53241%2Fcallback&challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' localhost:8081/open-in-app
```

```text
HTTP/1.1 302 Found
Location: http://127.0.0.1:53241/callback?token=9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA
```

The browser follows it; the app's listener answers "You are signed in to the app. You can close this tab." and the app prints:

```text
signed in as usr_dgdffrxo4lcj4vt5qodbgggn (Alice), /me answered usr_dgdffrxo4lcj4vt5qodbgggn with credential "bearer"
```

A return address the web app does not trust is refused before any token exists, on the GET and on the POST alike:

```sh
curl -s -b cookies.txt 'localhost:8081/open-in-app?returnTo=https://evil.example/cb'
```

```text
the return address is not trusted
```

The app's own scheme is trusted too (`myapp://signed-in?req=7` becomes `myapp://signed-in?req=7&token=…`); a token on that link is exchanged only with the app's verifier, so another program registered for `myapp://` that receives it gets `auth.token_invalid` and leaves the token unspent. A POST with no `returnTo` answers a page showing the token to paste, minted without a challenge because the app asked for nothing. The raw `POST /auth/handoff/generate` is closed (`auth.unknown_operation`): only the confirmed page mints.

## The code

The web app accepts the two return addresses and keeps the mint to its own page:

```go
hp := handoff.New(handoff.ServerOnly())
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithTrustedOrigins("myapp://"),
	auth.WithLoopbackReturn(), // http://127.0.0.1:<any port>/… as a return address, never as an origin
	auth.WithPlugins(email.New(...), password.New(), hp),
)
```

`openInApp` is behind `authhttp.RequireUser`. It checks `returnTo` with `a.TrustsReturnURL`, shows the confirmation on a GET (the form carries `returnTo` and `challenge` through), and on the POST calls `hp.GenerateWith(r.Context(), handoff.GenerateRequest{Challenge: challenge})` and redirects with the token appended to the query. The mint is a POST because a browser sends no `Origin` on a navigation, so a GET could never pass the origin check that protects every cookie-authenticated mutation; it also means a link cannot hand a session off without a click.

The app (`app.go`) listens on the loopback interface only, on a port the OS picks, makes a verifier with `handoff.NewVerifier`, opens the browser with the challenge, receives the token on `/callback`, closes the listener, and exchanges the token and the verifier with `POST /auth/handoff/verify` under `Auth-Token-Mode: bearer`; the new session arrives in `Set-Auth-Token`, and `Authorization: Bearer` reaches `/me`. The app never sends a cookie or an `Origin`: it is not a browser.

Why a loopback port before a URL scheme: a custom scheme can be registered by any program on the machine, so a token on a `myapp://` link can be caught by whichever app the OS routes it to; a loopback port is answered by the process that holds it. The verifier binding (RFC 7636 PKCE) is what makes the scheme path safe to offer at all: the catcher has the token but not the verifier. On mobile the equivalents are universal links and app links, which the OS verifies against a domain. The paste fallback covers a browser that will not open either.

`main_test.go` drives the whole flow against an `httptest` TLS server: a browser signs up, the app's `runApp` listens on a free port, the "browser" confirms and is redirected, the app reaches `/me` as a bearer; then the refusals (untrusted and protocol-relative return addresses, a cross-site POST, the closed generate route, a malformed challenge, a signed-out visitor), the deep-link path with and without the verifier, the paste path, a token used twice, and the app's own failures (no browser, cancelled, a taken port, a bad token).

## What this used

- [`plugin/handoff`](https://pkg.go.dev/github.com/ubgo/auth/plugin/handoff): `ServerOnly`, `Generate`, the `verify` route
- [`auth.TrustsReturnURL`](https://pkg.go.dev/github.com/ubgo/auth#Auth.TrustsReturnURL), `auth.WithLoopbackReturn`, `auth.WithTrustedOrigins` with a scheme
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `TokenModeHeader`, `SetTokenHeader`, `RequireUser`, `WriteError`
- Related: [handoff](../handoff) is the token exchange on its own; [mobile-bearer](../mobile-bearer) is bearer mode for a phone app.

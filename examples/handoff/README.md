# Hand-off: a web session into a native app

A person signs in on the web, taps "open in the app", and the app is signed in too, without typing the password again. The web page asks the server for a short-lived, single-use token, hands it to the app (a deep link, a QR code, a localhost redirect), and the app exchanges it for a bearer session of its own.

## Run it

```sh
cd examples
go run ./handoff
```

It creates `handoff.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./handoff`.

## Walkthrough

Sign up on the "web", with a cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery"}'
```

```json
{"user":{"id":"usr_dgdffrxo4lcj4vt5qodbgggn","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The signed-in page asks for a hand-off token. It lives three minutes and works once:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/handoff/generate -H 'Origin: http://localhost:8081' -d '{}'
```

```json
{"token":"9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA","expiresAt":"2026-10-02T15:47:35.188082Z"}
```

The "app" has no cookies. It exchanges the token with `Auth-Token-Mode: bearer`, and receives its own session token in `Set-Auth-Token`; a client that wanted a cookie would leave the header off and get `Set-Cookie`:

```sh
curl -s -i -X POST localhost:8081/auth/handoff/verify -H 'Origin: http://localhost:8081' -H 'Auth-Token-Mode: bearer' \
  -d '{"token":"9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA"}'
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Auth-Token: -y3ORvQ1LHBjFsZ3mhwDkeXd0Sy6-A0JIkzv2C5vSp4
Set-Auth-Token-Expires: 2026-10-09T15:44:35Z
Content-Length: 68

{"user":{"id":"usr_dgdffrxo4lcj4vt5qodbgggn","name":"","image":""}}
```

The token is spent:

```sh
curl -s -X POST localhost:8081/auth/handoff/verify -H 'Origin: http://localhost:8081' -H 'Auth-Token-Mode: bearer' \
  -d '{"token":"9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA"}'
```

```json
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

The web session is untouched; the two sessions are independent from here on:

```sh
curl -s -b cookies.txt localhost:8081/me
```

```json
{"id":"usr_dgdffrxo4lcj4vt5qodbgggn"}
```

## The code

Email, passwords and the hand-off plugin:

```go
auth.WithPlugins(
	email.New(email.Login(), email.Recover(), email.WithMailer(m)),
	password.New(),
	handoff.New(),
)
```

The exchange creates a new session rather than copying the web one: the web session's raw token is never stored, and two clients sharing one session would let either end the other's. The new session is full even for a user with two-factor, because the web session already passed it. A token of a session that has since signed out is refused, as is one minted while an admin impersonates the user.

`handoff.ServerOnly()` keeps the `generate` route from the client, so only the app's own Go code (`hp.Generate(ctx)`) mints tokens, after whatever check it wants to make first. `handoff.WithTTL` changes the three minutes.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: a browser with a cookie jar signs up and mints a token, a second client with no cookies exchanges it in bearer mode and reaches `/me`, the token is refused a second time, and signing the browser out leaves the app signed in.

## What this used

- [`plugin/handoff`](https://pkg.go.dev/github.com/ubgo/auth/plugin/handoff): `Generate`, `Verify`, `ServerOnly`, `WithTTL`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `TokenModeHeader`, `SetTokenHeader`
- Related: [mobile-bearer](../mobile-bearer) is the bearer mode on its own; [api-keys-and-jwt](../api-keys-and-jwt) covers tokens for other services rather than other clients.

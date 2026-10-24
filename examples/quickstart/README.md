# Quick start: email and password on net/http

The smallest complete app: people sign up and sign in with an email address and a password, verify the address from a mailed link, and reach a page only a signed-in user may see. This is the program behind the quick start in the [project README](../../README.md).

## Run it

```sh
cd examples
go run ./quickstart
```

It creates `quickstart.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./quickstart`.

## Walkthrough

Sign up. The session arrives as a cookie; the body never carries a token.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_sln4sw4ixsjemgutqsqskmah","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The server log shows the verification mail, whose link the app's `/verify-email` page would pass to `POST /auth/email/verify`:

```text
2026/09/29 13:40:16 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=IFMMt4zTNXfGjjZfLNMtYk64nv4KVy0SEwYJrFU_rGg

If you did not ask for this, ignore this email.
```

The app's own page, behind `RequireUser`:

```sh
curl -s -b cookies.txt localhost:8081/me
```

```json
{"id":"usr_sln4sw4ixsjemgutqsqskmah","hello":"Alice"}
```

Every mutation sent with a cookie must come from the app's own origin. A page on another site that tries to sign Alice out is refused before anything runs:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Sign out, and the page refuses the old cookie:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A wrong password gets the same answer whether or not the account exists, and costs the same time:

```sh
curl -s -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"wrong"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

The right one sets a new session cookie:

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=5i6jcWG86blAAJzzZnAbCFybx2eXGLRgy9ioqvMYyoU; Path=/; Expires=Tue, 06 Oct 2026 08:10:16 GMT; HttpOnly; Secure; SameSite=Lax

{"user":{"id":"usr_sln4sw4ixsjemgutqsqskmah","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The cookie is `Secure`. Browsers and curl accept it on `http://localhost` for development; anywhere else, serve the app over HTTPS.

## The code

The plugin list is the whole answer to "how can someone sign in". A list that cannot work, such as a password with no way to recover it, fails here at start-up:

```go
auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)
```

One handler serves every route of every plugin; `Middleware` resolves the session for the app's own pages:

```go
mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
```

The log line `WARN auth: rate limits are counted per process` is expected: one process is exactly what this is. See [multi-instance](../multi-instance) for more than one.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server and walks the flow above, including the verification link from the recorded mail and the refused cross-site POST.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `auth.New`, `a.Migrate`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, `MustUser`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- Next: the same app with [ready-made pages](../ready-made-pages), on [gin](../gin), [echo](../echo) or [fiber](../fiber), or with [two-factor](../two-factor) added.

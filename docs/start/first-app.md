# Your first app

You will have a running Go program where people sign up with an email address and a password, verify the address from a mailed link, reach a page only a signed-in user may see, and sign out. The program is [examples/quickstart](../../examples/quickstart) in the repository; every code block below is copied from it, and every transcript is from running it.

## Before you start

- [Install](install.md): Go, the core module, `plugin/password` and the SQLite driver.
- Thirty minutes. Nothing else: no mail server (mail is printed to the log), no database server (SQLite is a file).

## Step 1 — Start a module

```sh
mkdir myapp && cd myapp
go mod init example.com/myapp
go get github.com/ubgo/auth github.com/ubgo/auth/plugin/password github.com/ubgo/sqlb modernc.org/sqlite
```

Check: `go.mod` lists the four modules.

## Step 2 — Decide the constants

The app's public URL matters for two things: links in mail point at it, and its origin is the only one allowed to send cookie-authenticated `POST`s, which is the library's CSRF defence. Both derive from one port, read from `PORT` with 8081 as the default so two programs can run side by side; in production the URL comes from the environment too ([production](production.md)).

<!-- ds:block id=addr-gefhyvsy -->
**port** · [`examples/quickstart/main.go:40-50`](../../examples/quickstart/main.go#L40-L50)

```go
var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)
```
<!-- /ds:block hash=26fd54 -->

The SQLite file is opened with the pragmas from [install](install.md): WAL, a busy timeout, and foreign keys on.

## Step 3 — Wire the library

`auth.New` takes the database and its dialect, the base URL, and the plugin list. The list is the whole answer to "how can someone sign in": here, an email address that can sign in and recover the account, and a password. A list that cannot work fails right here, at start-up, not when the first user is stuck.

<!-- ds:block id=newauth-smwje7vu -->
**newAuth** · [`examples/quickstart/main.go:99-108`](../../examples/quickstart/main.go#L99-L108)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=6b7d2a -->

The mailer is anything with a `Send(ctx, email.Mail) error` method. For now it prints:

<!-- ds:block id=logmailer-send-457tbsyq -->
**logMailer.Send** · [`examples/quickstart/main.go:145-148`](../../examples/quickstart/main.go#L145-L148)

```go
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
```
<!-- /ds:block hash=589b81 -->

Check: `auth.New` returns no error. Try removing `email.Recover()` and running again; the program stops with `auth: plugin "password": password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()`.

## Step 4 — Mount the routes and protect a page

One handler serves every route of every plugin under the prefix. For the app's own pages, `authhttp.Middleware` resolves the session from the cookie, and `authhttp.RequireUser` refuses anyone signed out with `401 auth.signed_out` before your handler runs.

<!-- ds:block id=newhandler-zmz4j9w2 -->
**newHandler** · [`examples/quickstart/main.go:114-119`](../../examples/quickstart/main.go#L114-L119)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=9e6587 -->

Inside a handler behind `RequireUser`, `authhttp.MustUser` returns the user:

<!-- ds:block id=meresponse-zccxxpf9 -->
**meResponse** · [`examples/quickstart/main.go:124-127`](../../examples/quickstart/main.go#L124-L127)

```go
type meResponse struct {
	ID    string `json:"id"`
	Hello string `json:"hello"`
}
```
<!-- /ds:block hash=f13116 -->

<!-- ds:block id=me-6d2msbjr -->
**me** · [`examples/quickstart/main.go:132-136`](../../examples/quickstart/main.go#L132-L136)

```go
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Hello: u.Name}) // a client that hung up cannot be told
}
```
<!-- /ds:block hash=99bd31 -->

## Step 5 — Migrate and listen

`a.Migrate` creates the tables the wired plugins need and records each migration in `auth_migrations`; running it again is a no-op. For a single process, migrating at start-up is fine; with several instances, run `auth migrate` once from a deploy job instead ([production](production.md)).

<!-- ds:block id=main-7mrnbhrx -->
**main** · [`examples/quickstart/main.go:73-92`](../../examples/quickstart/main.go#L73-L92)

```go
func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}
```
<!-- /ds:block hash=219834 -->

```sh
go run .
```

```text
2026/09/29 13:40:16 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
2026/09/29 13:40:16 listening on http://localhost:8081
```

The warning is expected for one process; [production](production.md) covers several.

## Step 6 — Sign up

The session arrives as a cookie. The body never carries the token.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_sln4sw4ixsjemgutqsqskmah","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The log shows the verification mail. The link points at a page of your app (`/verify-email`), whose job is to `POST` the token to `/auth/email/verify`:

```text
2026/09/29 13:40:16 mail to=alice@example.com subject="Verify your email address"
Open this link to verify your email address:

http://localhost:8081/verify-email?token=IFMMt4zTNXfGjjZfLNMtYk64nv4KVy0SEwYJrFU_rGg

If you did not ask for this, ignore this email.
```

```sh
curl -s -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' -d '{"token":"IFMMt4zTNXfGjjZfLNMtYk64nv4KVy0SEwYJrFU_rGg"}'
```

Check: the answer is `{"email":"alice@example.com"}`, and `auth_user.email_verified_at` is set. Until the address is verified the user can still sign in here; add `email.RequireVerified()` to refuse that.

## Step 7 — Use the session

```sh
curl -s -b cookies.txt localhost:8081/me
curl -s -b cookies.txt localhost:8081/auth/session
```

```json
{"id":"usr_sln4sw4ixsjemgutqsqskmah","hello":"Alice"}
{"user":{"id":"usr_sln4sw4ixsjemgutqsqskmah","name":"Alice","image":""},"expiresAt":"2026-10-06T08:09:58.214072Z"}
```

A page on another site that tries to act with Alice's cookie is refused before anything runs:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

## Step 8 — Sign out and sign in again

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A wrong password gets the same answer, in the same time, whether or not the account exists:

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

The cookie is `Secure`: browsers and curl accept it on `http://localhost` for development, and everywhere else the app must be served over HTTPS.

## Step 9 — The same from Go

Every route is also a typed Go call through the same pipeline, with the same rate limits, checks and hooks. A service or a CLI signs a user in like this, with `pw` the `*password.Plugin` you passed to `auth.New` (or fetched with `auth.PluginOf[*password.Plugin](a)`):

```go
res, err := pw.SignIn(ctx, password.SignInRequest{Identifier: "alice@example.com", Password: "correct horse battery staple"})
```

`res.Token` is the raw session token for a Go caller; over HTTP it only ever travels as the cookie.

## What can go wrong

| Symptom | Fix |
|---|---|
| `{"error":{"code":"auth.origin_not_trusted",…}}` on every `POST` from a browser | The page's origin is not the base URL. Set `auth.WithBaseURL` to the URL the browser shows, or add the other origin with `auth.WithTrustedOrigins`. |
| `{"error":{"code":"auth.signed_out",…}}` right after a sign-in over plain `http://` on a host other than `localhost` | The `Secure` cookie was dropped. Serve HTTPS. |
| `{"error":{"code":"auth.rate_limited",…}}` while testing | [20](ds:block?id=signiniplimit-a4yqscxz) sign-ins a minute per IP and [5](ds:block?id=signinaccountlimit-yz756w5r) wrong passwords per account in 15 minutes is the password plugin's default. Wait, or use the Go API in tests. |
| `{"error":{"code":"password.too_short",…}}` | Passwords are at least [8](ds:block?id=defaultminlength-8nyr776x) characters by default (`password.MinLength`). |
| No mail arrives | The example prints mail; a real mailer goes in `logMailer`'s place. Delivery runs after the response, so a failure is in the log, not the response. |

## Next

- [Production](production.md): secrets, environment configuration, migrations in deploys, sweeping, several instances, real mail.
- [Ready-made pages](../integrations/ready-made-pages.md) if you would rather not write the forms, or the same app on [gin](../integrations/gin.md), [echo](../integrations/echo.md) or [fiber](../integrations/fiber.md).
- Add [two-factor](../plugins/twofactor.md), [passkeys](../plugins/passkey.md) or [social sign-in](../plugins/oauth.md).

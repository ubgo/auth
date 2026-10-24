# The quick start on fiber

The [quick start](../quickstart) app, email and password sign-in, served by [fiber v3](https://gofiber.io). Fiber runs on fasthttp, not `net/http`; `contrib/fiber` converts each request for the library's handlers and copies the session cookie back, so the plugins, the routes, the JSON and the cookies are the same as on `net/http`.

## Run it

```sh
cd examples
go run ./fiber
```

It creates `fiber.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./fiber`.

## Walkthrough

Sign up, then call the app's own fiber handler with the session cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_546mkdym77kwcvkww6omtidr","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_546mkdym77kwcvkww6omtidr","hello":"Alice"}
```

The origin check runs inside the operation, so it holds on fiber exactly as on `net/http`:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Sign out, and the fiber handler refuses the old cookie with the library's error JSON:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Routes are fiber routes, so a wrong method or an unknown path gets fiber's own plain-text answer, not the library's JSON:

```sh
curl -si localhost:8081/auth/password/sign-in
```

```text
HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain; charset=utf-8
Allow: POST

Method Not Allowed
```

## The code

`Mount` registers every operation of every plugin on a fiber group. In fiber v3 the handlers of a route run in the order given, so the middleware comes first:

```go
app := fiber.New(fiber.Config{ReadTimeout: readTimeout})
authfiber.Mount(app.Group(authPrefix), a)
app.Get("/me", authfiber.Middleware(a), authfiber.RequireUser(), me)
```

A handler reads the user from the fiber context. `Middleware` resolved the session once; this does not query the database:

```go
func me(c fiber.Ctx) error {
	u := authfiber.MustUser(c)
	return c.JSON(meResponse{ID: u.ID, Hello: u.Name})
}
```

Fiber is not an `http.Handler`, so `main_test.go` cannot put it behind `httptest`. Instead its client's transport hands each request to `app.Test`, fiber's in-memory round trip, and a normal `http.Client` with a cookie jar walks the same flow as the other examples: sign-up, the protected route, email verification from the recorded mail, sign-out, a wrong password, sign-in again and the refused cross-site POST. `app.Test`'s default one-second timeout is raised, because argon2id at the production cost can take longer on a busy machine.

## What this used

- [`contrib/fiber`](https://pkg.go.dev/github.com/ubgo/auth/contrib/fiber) (`authfiber`): `Mount`, `Middleware`, `RequireUser`, `MustUser`. A separate module, so fiber and fasthttp reach only apps that import it.
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- The same app on [net/http](../quickstart), [gin](../gin) and [echo](../echo); GraphQL is [contrib/gqlgen/example](../../contrib/gqlgen/example).

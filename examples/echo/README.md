# The quick start on echo

The [quick start](../quickstart) app, email and password sign-in, served by [echo](https://echo.labstack.com) instead of `net/http`. The plugins, the routes, the JSON and the cookies are identical: the adapter only registers each library operation as an echo route and resolves the session in an echo middleware.

## Run it

```sh
cd examples
go run ./echo
```

It creates `echo.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./echo`.

## Walkthrough

Sign up, then call the app's own echo handler with the session cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_kth5eiyr3jkofaervnpuiefo","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_kth5eiyr3jkofaervnpuiefo","hello":"Alice"}
```

The origin check runs inside the operation, so it holds on echo exactly as on `net/http`:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Sign out, and the echo handler refuses the old cookie with the library's error JSON:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Routes are echo routes, so a wrong method or an unknown path gets echo's own answer, not the library's JSON:

```sh
curl -si localhost:8081/auth/password/sign-in
curl -si localhost:8081/auth/nope
```

```text
HTTP/1.1 405 Method Not Allowed
Allow: OPTIONS, POST
Content-Type: application/json

{"message":"Method Not Allowed"}

HTTP/1.1 404 Not Found
Content-Type: application/json

{"message":"Not Found"}
```

## The code

`Mount` registers every operation of every plugin on an echo group; each route is `authhttp.OperationHandler`, the same one `authhttp.Handler` uses, so nothing is written twice. Echo's middleware arguments come after the handler:

```go
e := echo.New()
authecho.Mount(e.Group(authPrefix), a)
e.GET("/me", me, authecho.Middleware(a), authecho.RequireUser())
```

A handler reads the user from the echo context. `Middleware` resolved the session once; this does not query the database:

```go
func me(c echo.Context) error {
	u := authecho.MustUser(c)
	return c.JSON(http.StatusOK, meResponse{ID: u.ID, Hello: u.Name})
}
```

The server is a plain `http.Server` with the echo instance as its handler, so `e.Start` and its banner are not used.

`main_test.go` builds the same instance behind an `httptest` TLS server and walks sign-up, the protected route, email verification from the recorded mail, sign-out, a wrong password and sign-in again, plus the refused cross-site POST.

## What this used

- [`contrib/echo`](https://pkg.go.dev/github.com/ubgo/auth/contrib/echo) (`authecho`): `Mount`, `Middleware`, `RequireUser`, `MustUser`. A separate module, so echo reaches only apps that import it.
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- The same app on [net/http](../quickstart), [gin](../gin) and [fiber](../fiber); GraphQL is [contrib/gqlgen/example](../../contrib/gqlgen/example).

# The quick start on gin

The [quick start](../quickstart) app, email and password sign-in, served by [gin](https://github.com/gin-gonic/gin) instead of `net/http`. The plugins, the routes, the JSON and the cookies are identical: the adapter only registers each library operation as a gin route and resolves the session in a gin middleware.

## Run it

```sh
cd examples
go run ./gin
```

It creates `gin.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./gin`.

## Walkthrough

Sign up, then call the app's own gin handler with the session cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_i5q6ucdgzwza2ly5a4w3qiau","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_i5q6ucdgzwza2ly5a4w3qiau","hello":"Alice"}
```

The origin check runs inside the operation, so it holds on gin exactly as on `net/http`:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Sign out, and the gin handler refuses the old cookie with the library's error JSON:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Routes are gin routes, so a wrong method or an unknown path gets gin's answer, not the library's JSON. The example turns on `HandleMethodNotAllowed` so the wrong method is a 405 with an `Allow` header (gin's default is a 404):

```sh
curl -si localhost:8081/auth/password/sign-in
```

```text
HTTP/1.1 405 Method Not Allowed
Allow: POST
Content-Type: text/plain

405 method not allowed
```

## The code

`Mount` registers every operation of every plugin on a gin group; each route is `authhttp.OperationHandler`, the same one `authhttp.Handler` uses, so nothing is written twice:

```go
r := gin.New()
r.HandleMethodNotAllowed = true
r.Use(gin.Recovery())
authgin.Mount(r.Group(authPrefix), a)
r.GET("/me", authgin.Middleware(a), authgin.RequireUser(), me)
```

A handler reads the user from the gin context. `Middleware` resolved the session once; this does not query the database:

```go
func me(c *gin.Context) {
	u := authgin.MustUser(c)
	c.JSON(http.StatusOK, meResponse{ID: u.ID, Hello: u.Name})
}
```

`main_test.go` builds the same engine behind an `httptest` TLS server and walks sign-up, the protected route, email verification from the recorded mail, sign-out, a wrong password and sign-in again, plus the refused cross-site POST.

## What this used

- [`contrib/gin`](https://pkg.go.dev/github.com/ubgo/auth/contrib/gin) (`authgin`): `Mount`, `Middleware`, `RequireUser`, `MustUser`. A separate module, so gin reaches only apps that import it.
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- The same app on [net/http](../quickstart), [echo](../echo) and [fiber](../fiber); GraphQL is [contrib/gqlgen/example](../../contrib/gqlgen/example).

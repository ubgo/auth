# echo

You will have the library's routes served by an [echo](https://github.com/labstack/echo) instance, your own echo handlers behind its session middleware, and the signed-in user available from the echo context, with the same JSON, cookies and rules as on net/http.

## Before you start

- [Your first app](../start/first-app.md): the plugins, `auth.New` and the migration are the same on every framework; this guide changes only the router.
- The example is [`examples/echo`](../../examples/echo/main.go). `go run ./echo` in `examples/` serves it on `http://localhost:8081`; `go test ./echo` runs its tests.
- The adapter is its own module, `github.com/ubgo/auth/contrib/echo` (package `authecho`), so an app that does not use echo never downloads it: `go get github.com/ubgo/auth/contrib/echo`.

## Step 1 — Mount the routes on a group

`authecho.Mount` registers every operation of every plugin on an echo group: a Query as GET, a Mutation as POST. Each route is `authhttp.OperationHandler`, the same handler the net/http transport uses, so decoding, effects and the error JSON are exactly those of [net/http](net-http.md). Your own routes take `authecho.Middleware` as echo middleware, which attaches the request to the core and resolves the session once. Echo's middleware arguments come after the handler.

<!-- ds:block id=newhandler-4bd55d5d -->
**newHandler** · [`examples/echo/main.go:107-112`](../../examples/echo/main.go#L107-L112)

```go
func newHandler(a *auth.Auth) *echo.Echo {
	e := echo.New()
	authecho.Mount(e.Group(authPrefix), a)
	e.GET("/me", me, authecho.Middleware(a), authecho.RequireUser())
	return e
}
```
<!-- /ds:block hash=563c28 -->

Echo owns the router, so a wrong method or an unknown path under `/auth` gets echo's own JSON (`{"message":"Method Not Allowed"}` with an `Allow` header, `{"message":"Not Found"}`), not the library's error shape, which only the net/http `Handler` can give because it owns its own route table.

Check: start the app and sign up, then read the protected route with the cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_kth5eiyr3jkofaervnpuiefo","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_kth5eiyr3jkofaervnpuiefo","hello":"Alice"}
```

## Step 2 — Read the user in a handler

`authecho.RequireUser()` answers 401 `auth.signed_out` when there is no session, so a handler behind it can call `authecho.MustUser(c)`. `authecho.CurrentUser(c)` is the two-value form for a handler that serves both visitors and users. Neither queries the database: the middleware already resolved the session.

<!-- ds:block id=me-3dr3vbgf -->
**me** · [`examples/echo/main.go:123-126`](../../examples/echo/main.go#L123-L126)

```go
func me(c echo.Context) error {
	u := authecho.MustUser(c)
	return c.JSON(http.StatusOK, meResponse{ID: u.ID, Hello: u.Name})
}
```
<!-- /ds:block hash=9571c0 -->

Check: sign out, and the same route refuses the old cookie with the library's error JSON:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## Step 3 — Call an operation from a handler

An echo handler may call any operation through the Go API with `c.Request().Context()`, for example `pw.SignIn(c.Request().Context(), in)` from a form of your own. The cookie the operation issues reaches the response because the middleware wraps echo's response writer with `authhttp.WrapWriter`, which applies the request's effects just before the first header or byte; a handler that writes nothing gets them applied when it returns.

Check: the origin check runs inside the operation, so it holds on echo exactly as on net/http:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

## Options you may want

| Need | Do |
|---|---|
| Sessions shared across subdomains | Pass `authhttp.CookieDomain("example.com")` to both `Mount` and `Middleware`; see [net/http](net-http.md#cookiedomain). |
| Errors logged somewhere specific | Pass `authhttp.Logger(l)` the same way. |
| Error bodies in your own shape (RFC 9457 problem+json) | Pass `authhttp.EncodeErrors(enc)` the same way; the status and `Retry-After` stay the library's. See [net/http, Step 7](net-http.md#step-7--know-the-error-json). |
| Echo's `HTTPErrorHandler` to see the adapter's refusals | It does not: the 401 and 500 the adapter writes go straight to the response writer and the middleware returns `nil`. Errors your own handlers return still reach it. |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `{"error":{"code":"auth.internal",...}}` with status 500 from a route behind `Middleware` | The session lookup failed for a reason other than "signed out", such as a database that is down. The adapter refuses to run the handler as if nobody were signed in. | Read the log; the detail is there and never in the response. |
| `panic: authhttp: MustUser called on a request without a user; wrap the handler in RequireUser` | `MustUser` on a route without `RequireUser()`. | Add `authecho.RequireUser()` after the handler in the route's middleware list, or use `authecho.CurrentUser(c)`. |
| `auth.origin_not_trusted` on a POST from your own frontend | The request's `Origin` is not `auth.WithBaseURL`'s origin or one of `auth.WithTrustedOrigins`. | See [SPA frontends](spa-frontends.md). |
| A cookie set in a handler never arrives | The handler wrote the body before calling the operation. Effects recorded after the first byte cannot become headers. | Call the operation before writing anything. |

## Next

- [net/http](net-http.md) for everything the adapter reuses: cookies, bearer mode, `RequireScope`, the error JSON.
- [Mobile apps](mobile-apps.md) and [SPA frontends](spa-frontends.md) for the clients that call these routes.
- The adapter's [README](../../contrib/echo/README.md) is the reference for its API and tests.

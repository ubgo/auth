# gin

You will have the library's routes served by a [gin](https://github.com/gin-gonic/gin) engine, your own gin handlers behind its session middleware, and the signed-in user available from the gin context, with the same JSON, cookies and rules as on net/http.

## Before you start

- [Your first app](../start/first-app.md): the plugins, `auth.New` and the migration are the same on every framework; this guide changes only the router.
- The example is [`examples/gin`](../../examples/gin/main.go). `go run ./gin` in `examples/` serves it on `http://localhost:8081`; `go test ./gin` runs its tests.
- The adapter is its own module, `github.com/ubgo/auth/contrib/gin` (package `authgin`), so an app that does not use gin never downloads it: `go get github.com/ubgo/auth/contrib/gin`.

## Step 1 — Mount the routes on a group

`authgin.Mount` registers every operation of every plugin on a gin group: a Query as GET, a Mutation as POST. Each route is `authhttp.OperationHandler`, the same handler the net/http transport uses, so decoding, effects and the error JSON are exactly those of [net/http](net-http.md). Your own routes go in a group behind `authgin.Middleware`, which attaches the request to the core and resolves the session once.

<!-- ds:block id=newhandler-swjbzqm9 -->
**newHandler** · [`examples/gin/main.go:109-116`](../../examples/gin/main.go#L109-L116)

```go
func newHandler(a *auth.Auth) *gin.Engine {
	r := gin.New()
	r.HandleMethodNotAllowed = true // 405 with an Allow header, not gin's default 404
	r.Use(gin.Recovery())
	authgin.Mount(r.Group(authPrefix), a)
	r.GET("/me", authgin.Middleware(a), authgin.RequireUser(), me)
	return r
}
```
<!-- /ds:block hash=5e145c -->

`HandleMethodNotAllowed` is gin's, not the library's: gin owns the router, so a wrong method or an unknown path under `/auth` gets gin's answer. With the flag on, a wrong method is a 405 with an `Allow` header; gin's default is a 404 page. Neither is the library's JSON error, which only the net/http `Handler` can give, because it owns its own route table.

Check: start the app and sign up, then read the protected route with the cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_i5q6ucdgzwza2ly5a4w3qiau","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_i5q6ucdgzwza2ly5a4w3qiau","hello":"Alice"}
```

## Step 2 — Read the user in a handler

`authgin.RequireUser()` answers 401 `auth.signed_out` when there is no session, so a handler behind it can call `authgin.MustUser(c)`. `authgin.CurrentUser(c)` is the two-value form for a handler that serves both visitors and users. Neither queries the database: the middleware already resolved the session.

<!-- ds:block id=me-37fywwmb -->
**me** · [`examples/gin/main.go:127-130`](../../examples/gin/main.go#L127-L130)

```go
func me(c *gin.Context) {
	u := authgin.MustUser(c)
	c.JSON(http.StatusOK, meResponse{ID: u.ID, Hello: u.Name})
}
```
<!-- /ds:block hash=91453f -->

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

A gin handler may call any operation through the Go API with `c.Request.Context()`, for example `pw.SignIn(c.Request.Context(), in)` from a form of your own. The cookie the operation issues reaches the response because the middleware wraps gin's writer and applies the request's effects before the first header or byte, whichever of gin's write methods comes first (`WriteHeader`, `WriteHeaderNow`, `Write`, `WriteString`). The adapter's test `TestWriter_EveryWriteMethodAppliesEffectsFirst` pins that for each one.

Check: the origin check runs inside the operation, so it holds on gin exactly as on net/http:

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
| gin's own 404 and 405 for `/auth` paths | That is what you get; `r.HandleMethodNotAllowed = true` makes the 405 real. |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `{"error":{"code":"auth.internal",...}}` with status 500 from a route behind `Middleware` | The session lookup failed for a reason other than "signed out", such as a database that is down. The adapter refuses to run the handler as if nobody were signed in. | Read the log; the detail is there and never in the response. |
| `panic: authhttp: MustUser called on a request without a user; wrap the handler in RequireUser` | `MustUser` on a route without `RequireUser()` in front. | Add `authgin.RequireUser()` before the handler, or use `authgin.CurrentUser(c)`. |
| `auth.origin_not_trusted` on a POST from your own frontend | The request's `Origin` is not `auth.WithBaseURL`'s origin or one of `auth.WithTrustedOrigins`. | See [SPA frontends](spa-frontends.md). |
| A cookie set in a handler never arrives | The handler wrote the body before calling the operation. Effects recorded after the first byte cannot become headers. | Call the operation before writing anything. |

## Next

- [net/http](net-http.md) for everything the adapter reuses: cookies, bearer mode, `RequireScope`, the error JSON.
- [Mobile apps](mobile-apps.md) and [SPA frontends](spa-frontends.md) for the clients that call these routes.
- The adapter's [README](../../contrib/gin/README.md) is the reference for its API and tests.

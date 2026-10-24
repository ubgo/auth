# fiber

You will have the library's routes served by a [fiber v3](https://github.com/gofiber/fiber) app, your own fiber handlers behind its session middleware, and the signed-in user available from the fiber context, with the same JSON, cookies and rules as on net/http.

## Before you start

- [Your first app](../start/first-app.md): the plugins, `auth.New` and the migration are the same on every framework; this guide changes only the router.
- The example is [`examples/fiber`](../../examples/fiber/main.go). `go run ./fiber` in `examples/` serves it on `http://localhost:8081`; `go test ./fiber` runs its tests.
- The adapter is its own module, `github.com/ubgo/auth/contrib/fiber` (package `authfiber`): `go get github.com/ubgo/auth/contrib/fiber`.
- Fiber runs on fasthttp, not net/http. The adapter bridges the two for the library's handlers; the one place that shows is how effects reach the response (step 3).

## Step 1 — Mount the routes on a group

`authfiber.Mount` registers every operation of every plugin on a fiber router: a Query as GET, a Mutation as POST. Each route is `authhttp.OperationHandler` behind fiber's own net/http adaptor, so no operation is served differently here. Your own routes take `authfiber.Middleware` first; in fiber v3 the handlers of a route run in the order given.

<!-- ds:block id=newhandler-cdpjrvw5 -->
**newHandler** · [`examples/fiber/main.go:106-111`](../../examples/fiber/main.go#L106-L111)

```go
func newHandler(a *auth.Auth) *fiber.App {
	app := fiber.New(fiber.Config{ReadTimeout: readTimeout})
	authfiber.Mount(app.Group(authPrefix), a)
	app.Get("/me", authfiber.Middleware(a), authfiber.RequireUser(), me)
	return app
}
```
<!-- /ds:block hash=35b9a1 -->

Fiber owns the router, so a wrong method or an unknown path under `/auth` gets fiber's plain-text answer (`405 Method Not Allowed` with an `Allow` header), not the library's error JSON, which only the net/http `Handler` can give because it owns its own route table.

Check: start the app and sign up, then read the protected route with the cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_546mkdym77kwcvkww6omtidr","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_546mkdym77kwcvkww6omtidr","hello":"Alice"}
```

## Step 2 — Read the user in a handler

The middleware stores the resolved request context as fiber's context, so `c.Context()` carries the session. `authfiber.RequireUser()` answers 401 `auth.signed_out` when there is none, and a handler behind it can call `authfiber.MustUser(c)`; `authfiber.CurrentUser(c)` is the two-value form.

<!-- ds:block id=me-sgxnupxm -->
**me** · [`examples/fiber/main.go:122-125`](../../examples/fiber/main.go#L122-L125)

```go
func me(c fiber.Ctx) error {
	u := authfiber.MustUser(c)
	return c.JSON(meResponse{ID: u.ID, Hello: u.Name})
}
```
<!-- /ds:block hash=89e3ae -->

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

A fiber handler may call any operation through the Go API with `c.Context()`. Effects cannot be written through a wrapped `http.ResponseWriter` on fasthttp, so the middleware collects them as headers and copies them onto fiber's response after the handler returns. Fiber sends the response only when the handler chain ends, so a cookie issued inside a handler still lands. The one limit: a handler that streams its body with `SendStreamWriter` must not rely on effects recorded after streaming starts.

Check: the origin check runs inside the operation, so it holds on fiber exactly as on net/http:

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

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `{"error":{"code":"auth.internal",...}}` with status 500 from a route behind `Middleware` | The session lookup failed for a reason other than "signed out", such as a database that is down. | Read the log; the detail is there and never in the response. |
| `{"error":{"code":"auth.bad_request",...}}` with status 400 from `Middleware` | The request line could not be converted to a net/http request (an unparsable URI). | A real client never sends one; nothing to do. |
| `panic: authhttp: MustUser called on a request without a user; wrap the handler in RequireUser` | `MustUser` on a route without `RequireUser()` in front. | Add `authfiber.RequireUser()` before the handler, or use `authfiber.CurrentUser(c)`. |
| `auth.origin_not_trusted` on a POST from your own frontend | The request's `Origin` is not `auth.WithBaseURL`'s origin or one of `auth.WithTrustedOrigins`. | See [SPA frontends](spa-frontends.md). |

## Next

- [net/http](net-http.md) for everything the adapter reuses: cookies, bearer mode, `RequireScope`, the error JSON.
- [Mobile apps](mobile-apps.md) and [SPA frontends](spa-frontends.md) for the clients that call these routes.
- The adapter's [README](../../contrib/fiber/README.md) is the reference for its API and tests.

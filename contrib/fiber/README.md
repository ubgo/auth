# github.com/ubgo/auth/contrib/fiber

Mounts every auth route on a fiber v3 router and gives fiber handlers the signed-in user.

## Install

```sh
go get github.com/ubgo/auth/contrib/fiber
```

This is its own module, so an app that does not use fiber never downloads it. It brings `github.com/gofiber/fiber/v3`. The package name is `authfiber`.

## Wire it

From [examples/fiber](../../examples/fiber/main.go):

```go
import authfiber "github.com/ubgo/auth/contrib/fiber"

a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)

app := fiber.New()
authfiber.Mount(app.Group("/auth"), a)
app.Get("/me", authfiber.Middleware(a), authfiber.RequireUser(), func(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"id": authfiber.MustUser(c).ID})
})
```

## Options

Every function takes `authhttp` options (`authhttp.CookieDomain`, `authhttp.Logger`, `authhttp.EncodeErrors` for an error body in your own shape); pass the same ones to `Mount` and `Middleware`. `authhttp.Prefix` does not apply here, because the fiber group is the prefix.

## Handlers, middleware and helpers

| API | What it does |
|---|---|
| `Mount(r fiber.Router, a, opts...)` | Registers every operation at its route: a Query as GET, a Mutation as POST. Each route is `authhttp.OperationHandler` behind fiber's own net/http adaptor, so no operation is served differently here. |
| `Middleware(a, opts...)` | Converts the request, attaches it to the core, resolves the session once, and stores the result as fiber's context, where `CurrentUser` and every operation called from a handler find it. A request line net/http cannot parse answers 400 `auth.bad_request`; a session lookup that fails for any reason other than "signed out" answers 500 `auth.internal`. After the handler returns, the request's effects are copied onto fiber's response headers. |
| `RequireUser()` | Answers 401 `auth.signed_out` when there is no session. It must come after `Middleware`. |
| `CurrentUser(c)` | The signed-in user, and `false` when signed out or when the route is not behind `Middleware`. It never queries the database. |
| `MustUser(c)` | The signed-in user. It panics with `authhttp.ErrNoUser` when there is none, for handlers behind `RequireUser`. |

For the cookie names, bearer mode, the session cache cookie and headers, and the error JSON shape, see [authhttp](../../authhttp/README.md). Every effect the core records, a cached session copy included, reaches the response through the same path as the session cookie.

## Tables and columns

None.

## Errors

| Error | Code | Status | When |
|---|---|---|---|
| `auth.ErrBadRequest` | `auth.bad_request` | 400 | `Middleware` on a request URI net/http cannot parse. |
| `auth.ErrSignedOut` | `auth.signed_out` | 401 | `RequireUser` on a signed-out request. |
| `auth.ErrInternal` | `auth.internal` | 500 | `Middleware` when the session lookup fails. |
| `authhttp.ErrNoUser` | (panic value) | none | `MustUser` without a user. |

The JSON shape is the same as `authhttp`: `{"error":{"code":"...","message":"..."}}`.

## Security notes

| Property | Pinned by |
|---|---|
| A broken session lookup is a 500 and the handler does not run; it is never read as "signed out". | `TestMiddleware_ABrokenLookupIsA500NotASignOut` |
| A request the adaptor cannot convert is refused, never passed on half-built. | `TestMiddleware_AnUnreadableRequestURIIsABadRequest` |
| A cookie issued by an operation called inside a handler reaches the response. | `TestMiddleware_AppliesEffectsOfOperationsCalledInAHandler` |
| A cached session copy recorded by an operation reaches the client as the cache cookie. | `TestMount_SessionCacheCookiePassesThrough` |
| A signed-out request never reaches a handler behind `RequireUser`. | `TestRequireUser_RefusesASignedOutRequest`, `TestRequireUser_LetsASignedInRequestThrough` |

Limit: fiber runs on fasthttp, not net/http, so effects are copied as headers after the handler returns, not through a wrapped writer. Fiber sends the response only after the handler chain ends, so the headers still land. A handler that streams its body with `SendStreamWriter` must not rely on effects recorded after streaming starts.

## Example

- [examples/fiber](../../examples/fiber/): the quick-start app on fiber v3.
- https://pkg.go.dev/github.com/ubgo/auth/contrib/fiber

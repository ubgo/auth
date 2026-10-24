# github.com/ubgo/auth/contrib/echo

Mounts every auth route on an echo group and gives echo handlers the signed-in user.

## Install

```sh
go get github.com/ubgo/auth/contrib/echo
```

This is its own module, so an app that does not use echo never downloads it. It brings `github.com/labstack/echo/v4`. The package name is `authecho`.

## Wire it

From [examples/echo](../../examples/echo/main.go):

```go
import authecho "github.com/ubgo/auth/contrib/echo"

a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)

e := echo.New()
authecho.Mount(e.Group("/auth"), a)
e.GET("/me", func(c echo.Context) error {
	u := authecho.MustUser(c)
	return c.JSON(http.StatusOK, map[string]string{"id": u.ID})
}, authecho.Middleware(a), authecho.RequireUser())
```

## Options

Every function takes `authhttp` options (`authhttp.CookieDomain`, `authhttp.Logger`, `authhttp.EncodeErrors` for an error body in your own shape); pass the same ones to `Mount` and `Middleware`. `authhttp.Prefix` does not apply here, because the echo group is the prefix.

## Handlers, middleware and helpers

| API | What it does |
|---|---|
| `Mount(g *echo.Group, a, opts...)` | Registers every operation at its route: a Query as GET, a Mutation as POST. Each route is `authhttp.OperationHandler`, so decoding, effects and the error JSON are exactly those of `authhttp`. |
| `Middleware(a, opts...)` | Attaches the request to the core and resolves the session once. A lookup that fails for any reason other than "signed out" answers 500 `auth.internal`. It wraps echo's response writer with `authhttp.WrapWriter`, so effects recorded by operations called in the handler become headers before its first write. |
| `RequireUser()` | Answers 401 `auth.signed_out` when there is no session. It must come after `Middleware`. |
| `CurrentUser(c)` | The signed-in user, and `false` when signed out or when the route is not behind `Middleware`. It never queries the database. |
| `MustUser(c)` | The signed-in user. It panics with `authhttp.ErrNoUser` when there is none, for handlers behind `RequireUser`. |

For the cookie names, bearer mode, the session cache cookie and headers, and the error JSON shape, see [authhttp](../../authhttp/README.md). Every effect the core records, a cached session copy included, reaches the response through the same path as the session cookie.

## Tables and columns

None.

## Errors

| Error | Code | Status | When |
|---|---|---|---|
| `auth.ErrSignedOut` | `auth.signed_out` | 401 | `RequireUser` on a signed-out request. |
| `auth.ErrInternal` | `auth.internal` | 500 | `Middleware` when the session lookup fails. |
| `authhttp.ErrNoUser` | (panic value) | none | `MustUser` without a user. |

Routes answer every error of `authhttp`. The refusals above are written straight to the response writer and the middleware returns `nil`, so echo's `HTTPErrorHandler` does not see them.

## Security notes

| Property | Pinned by |
|---|---|
| A broken session lookup is a 500 and the handler does not run; it is never read as "signed out". | `TestMiddleware_ABrokenLookupIsA500NotASignOut` |
| A cookie issued by an operation called inside a handler reaches the response. | `TestMiddleware_AppliesEffectsOfOperationsCalledInAHandler` |
| A cached session copy recorded by an operation reaches the client as the cache cookie. | `TestMount_SessionCacheCookiePassesThrough` |
| A signed-out request never reaches a handler behind `RequireUser`. | `TestRequireUser_RefusesASignedOutRequest`, `TestRequireUser_LetsASignedInRequestThrough` |

## Example

- [examples/echo](../../examples/echo/): the quick-start app on echo.
- https://pkg.go.dev/github.com/ubgo/auth/contrib/echo

# github.com/ubgo/auth/contrib/gin

Mounts every auth route on a gin router and gives gin handlers the signed-in user.

## Install

```sh
go get github.com/ubgo/auth/contrib/gin
```

This is its own module, so an app that does not use gin never downloads it. It brings `github.com/gin-gonic/gin`. The package name is `authgin`.

## Wire it

From [examples/gin](../../examples/gin/main.go):

```go
import authgin "github.com/ubgo/auth/contrib/gin"

a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
	),
)

r := gin.New()
r.HandleMethodNotAllowed = true // 405 with an Allow header, not gin's default 404
authgin.Mount(r.Group("/auth"), a)
r.GET("/me", authgin.Middleware(a), authgin.RequireUser(), func(c *gin.Context) {
	u := authgin.MustUser(c)
	c.JSON(http.StatusOK, gin.H{"id": u.ID})
})
```

## Options

Every function takes `authhttp` options (`authhttp.CookieDomain`, `authhttp.Logger`, `authhttp.EncodeErrors` for an error body in your own shape); pass the same ones to `Mount` and `Middleware`. `authhttp.Prefix` does not apply here, because the gin group is the prefix.

## Handlers, middleware and helpers

| API | What it does |
|---|---|
| `Mount(r gin.IRoutes, a, opts...)` | Registers every operation at its route: a Query as GET, a Mutation as POST. Each route is `authhttp.OperationHandler`, so decoding, effects and the error JSON are exactly those of `authhttp`. gin answers unknown paths and methods itself. |
| `Middleware(a, opts...)` | Attaches the request to the core and resolves the session once. A lookup that fails for any reason other than "signed out" aborts with 500 `auth.internal`. Effects recorded by operations called in the handler (an issued session, say) become headers before gin's first write, whichever write method comes first (`WriteHeader`, `WriteHeaderNow`, `Write`, `WriteString`). |
| `RequireUser()` | Aborts with 401 `auth.signed_out` when there is no session. It must come after `Middleware`. |
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

Routes answer every error of `authhttp`.

## Security notes

| Property | Pinned by |
|---|---|
| A broken session lookup is a 500 and the handler does not run; it is never read as "signed out". | `TestMiddleware_ABrokenLookupIsA500NotASignOut` |
| A cookie issued by an operation called inside a handler reaches the response, whichever gin write method starts it. | `TestMiddleware_AppliesEffectsOfOperationsCalledInAHandler`, `TestWriter_EveryWriteMethodAppliesEffectsFirst` |
| A cached session copy recorded by an operation reaches the client as the cache cookie. | `TestMount_SessionCacheCookiePassesThrough` |
| A signed-out request never reaches a handler behind `RequireUser`. | `TestRequireUser_RefusesASignedOutRequest`, `TestRequireUser_LetsASignedInRequestThrough` |

## Example

- [examples/gin](../../examples/gin/): the quick-start app on gin.
- https://pkg.go.dev/github.com/ubgo/auth/contrib/gin

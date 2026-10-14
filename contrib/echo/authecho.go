// Package authecho mounts github.com/ubgo/auth on echo.
//
// A separate module so an app that does not use echo never downloads it. Like
// the gin adapter it re-implements nothing: every route is
// authhttp.OperationHandler, and the middleware is authhttp.Begin with
// authhttp.WrapWriter around echo's response writer.
package authecho

import (
	"github.com/labstack/echo/v4"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Mount registers every operation on g at its route: a Query as GET, a
// Mutation as POST.
func Mount(g *echo.Group, a *auth.Auth, opts ...authhttp.Option) {
	for _, op := range a.Operations() {
		g.Add(authhttp.MethodOf(op.Info().Kind), op.Route(), echo.WrapHandler(authhttp.OperationHandler(a, op, opts...)))
	}
}

// Middleware attaches the request to the core and resolves its session. A
// lookup that fails for a reason other than "signed out" answers 500. Effects
// recorded inside the handler become headers before its first write.
func Middleware(a *auth.Auth, opts ...authhttp.Option) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r, err := authhttp.Begin(a, c.Request(), opts...)
			if err != nil {
				authhttp.WriteErrorWith(c.Response().Writer, c.Request(), err, opts...)
				return nil
			}
			c.SetRequest(r)
			w, finish := authhttp.WrapWriter(c.Response().Writer, r, opts...)
			c.Response().Writer = w
			err = next(c)
			finish()
			return err
		}
	}
}

// RequireUser refuses a request without a session with the core's 401 JSON,
// or in the shape authhttp.EncodeErrors gave Middleware. It must come after
// Middleware.
func RequireUser() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, ok := auth.CurrentUser(c.Request().Context()); !ok {
				authhttp.WriteErrorWith(c.Response().Writer, c.Request(), auth.ErrSignedOut)
				return nil
			}
			return next(c)
		}
	}
}

// CurrentUser returns the signed-in user of c. It reports false both for a
// signed-out request and for a route that is not behind Middleware, and it
// never queries the database: Middleware resolved the session once.
func CurrentUser(c echo.Context) (auth.User, bool) { return auth.CurrentUser(c.Request().Context()) }

// MustUser returns the signed-in user and panics without one, for handlers
// behind RequireUser.
func MustUser(c echo.Context) auth.User {
	u, ok := CurrentUser(c)
	if !ok {
		panic(authhttp.ErrNoUser)
	}
	return u
}

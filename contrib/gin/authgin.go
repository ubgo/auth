// Package authgin mounts github.com/ubgo/auth on gin.
//
// It is a separate module so an app that does not use gin never downloads it.
// It re-implements nothing: every route is authhttp.OperationHandler, and the
// middleware is authhttp.Begin plus a writer that applies effects before
// gin's first write. What it adds is gin-shaped access — CurrentUser(c) rather
// than a detour through c.Request.Context().
package authgin

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Mount registers every operation on r at its route: a Query as GET, a
// Mutation as POST. gin then answers unknown paths and methods itself.
func Mount(r gin.IRoutes, a *auth.Auth, opts ...authhttp.Option) {
	for _, op := range a.Operations() {
		r.Handle(authhttp.MethodOf(op.Info().Kind), op.Route(), gin.WrapH(authhttp.OperationHandler(a, op, opts...)))
	}
}

// Middleware attaches the request to the core and resolves its session. A
// lookup that fails for a reason other than "signed out" answers 500 rather
// than letting the handler run as if nobody were signed in. Effects recorded
// by operations called inside the handler become headers before its first
// write.
func Middleware(a *auth.Auth, opts ...authhttp.Option) gin.HandlerFunc {
	return func(c *gin.Context) {
		r, err := authhttp.Begin(a, c.Request, opts...)
		if err != nil {
			c.Abort()
			authhttp.WriteErrorWith(c.Writer, c.Request, err, opts...)
			return
		}
		c.Request = r
		w := &writer{ResponseWriter: c.Writer, r: r, opts: opts}
		c.Writer = w
		c.Next()
		w.apply()
	}
}

// writer applies the request's effects once, before the first header or
// byte, whichever of gin's write methods comes first.
type writer struct {
	gin.ResponseWriter
	r    *http.Request
	opts []authhttp.Option
	once sync.Once
}

func (w *writer) apply() {
	w.once.Do(func() { authhttp.ApplyHeaderEffects(w.ResponseWriter, w.r, w.opts...) })
}

func (w *writer) WriteHeader(code int) { w.apply(); w.ResponseWriter.WriteHeader(code) }
func (w *writer) WriteHeaderNow()      { w.apply(); w.ResponseWriter.WriteHeaderNow() }
func (w *writer) Write(b []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(b)
}
func (w *writer) WriteString(s string) (int, error) {
	w.apply()
	return w.ResponseWriter.WriteString(s)
}

// RequireUser refuses a request without a session with the core's 401 JSON,
// or in the shape authhttp.EncodeErrors gave Middleware. It must come after
// Middleware.
func RequireUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := auth.CurrentUser(c.Request.Context()); !ok {
			c.Abort()
			authhttp.WriteErrorWith(c.Writer, c.Request, auth.ErrSignedOut)
			return
		}
		c.Next()
	}
}

// CurrentUser returns the signed-in user of c. It reports false both for a
// signed-out request and for a route that is not behind Middleware, and it
// never queries the database: Middleware resolved the session once.
func CurrentUser(c *gin.Context) (auth.User, bool) { return auth.CurrentUser(c.Request.Context()) }

// MustUser returns the signed-in user and panics without one, for handlers
// behind RequireUser, where a missing user is a wiring bug.
func MustUser(c *gin.Context) auth.User {
	u, ok := CurrentUser(c)
	if !ok {
		panic(authhttp.ErrNoUser)
	}
	return u
}

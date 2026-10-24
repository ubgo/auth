// Package authfiber mounts github.com/ubgo/auth on fiber v3.
//
// Fiber runs on fasthttp, not net/http, so this adapter differs from the gin
// and echo ones in one place only: effects cannot be written through a
// wrapped http.ResponseWriter, so the middleware collects them as headers and
// copies them onto fiber's response after the handler returns. Fiber sends
// the response only after the handler chain ends, so the headers still land;
// a handler that streams the body with SendStreamWriter must not rely on
// effects recorded after it starts streaming.
//
// Routes reuse authhttp.OperationHandler through fiber's own net/http
// adaptor, so no operation is served differently here.
package authfiber

import (
	"bytes"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Mount registers every operation on r at its route: a Query as GET, a
// Mutation as POST.
func Mount(r fiber.Router, a *auth.Auth, opts ...authhttp.Option) {
	for _, op := range a.Operations() {
		r.Add([]string{authhttp.MethodOf(op.Info().Kind)}, op.Route(), adaptor.HTTPHandler(authhttp.OperationHandler(a, op, opts...)))
	}
}

// Middleware attaches the request to the core, resolves its session, and
// stores the resulting context as fiber's context, where CurrentUser and
// every operation called from a handler find it. A lookup that fails for a
// reason other than "signed out" answers 500.
func Middleware(a *auth.Auth, opts ...authhttp.Option) fiber.Handler {
	return func(c fiber.Ctx) error {
		req, err := adaptor.ConvertRequest(c, false)
		if err != nil {
			return writeError(c, nil, auth.ErrBadRequest, opts)
		}
		req = req.WithContext(c.Context())
		begun, err := authhttp.Begin(a, req, opts...)
		if err != nil {
			return writeError(c, req, err, opts)
		}
		c.SetContext(begun.Context())
		next := c.Next()
		applyEffects(c, begun, opts)
		return next
	}
}

// headerSink is an http.ResponseWriter that only keeps headers, so
// authhttp.ApplyHeaderEffects can be reused unchanged.
type headerSink struct{ h http.Header }

func (s headerSink) Header() http.Header       { return s.h }
func (headerSink) Write(b []byte) (int, error) { return len(b), nil }
func (headerSink) WriteHeader(int)             {}

// applyEffects copies the request's effects onto fiber's response.
func applyEffects(c fiber.Ctx, r *http.Request, opts []authhttp.Option) {
	sink := headerSink{h: http.Header{}}
	authhttp.ApplyHeaderEffects(sink, r, opts...)
	for name, values := range sink.h {
		if name == authhttp.SetTokenHeader && len(c.Response().Header.Peek(name)) > 0 {
			// A route behind Middleware already answered a token (a sign-in
			// that replaced a dead one); the sink, which started empty,
			// cannot see it, and a second value would corrupt the first.
			continue
		}
		for _, v := range values {
			c.Response().Header.Add(name, v)
		}
	}
}

// errorBody is the JSON shape every transport answers errors with.
type errorBody struct {
	Error auth.ErrorInfo `json:"error"`
}

// writeError answers err as the library's JSON, or, when opts or the
// context Middleware stored set authhttp.EncodeErrors, as that encoder
// writes it: recorded through authhttp.WriteErrorWith, so the status and
// Retry-After stay authhttp's, then copied onto fiber's response. r is the
// converted request, or nil when there is none yet.
func writeError(c fiber.Ctx, r *http.Request, err error, opts []authhttp.Option) error {
	if authhttp.ErrorEncoderOf(c.Context(), opts...) == nil {
		info := auth.ErrorOf(err)
		return c.Status(info.Status).JSON(errorBody{Error: info})
	}
	if r == nil {
		r = (&http.Request{Method: c.Method(), Header: http.Header{}}).WithContext(c.Context())
	}
	rec := &recorder{h: http.Header{}}
	authhttp.WriteErrorWith(rec, r, err, opts...)
	for name, values := range rec.h {
		c.Response().Header.Del(name)
		for _, v := range values {
			c.Response().Header.Add(name, v)
		}
	}
	return c.Status(rec.status).Send(rec.body.Bytes())
}

// recorder is the http.ResponseWriter an error encoder writes into; fiber
// has none to hand out.
type recorder struct {
	h      http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.h }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(b)
}

// RequireUser refuses a request without a session with the core's 401 JSON,
// or in the shape authhttp.EncodeErrors gave Middleware. It must come after
// Middleware.
func RequireUser() fiber.Handler {
	return func(c fiber.Ctx) error {
		if _, ok := auth.CurrentUser(c.Context()); !ok {
			var r *http.Request
			if req, err := adaptor.ConvertRequest(c, false); err == nil {
				r = req.WithContext(c.Context())
			}
			return writeError(c, r, auth.ErrSignedOut, nil)
		}
		return c.Next()
	}
}

// CurrentUser returns the signed-in user of c. It reports false both for a
// signed-out request and for a route that is not behind Middleware, and it
// never queries the database: Middleware resolved the session once.
func CurrentUser(c fiber.Ctx) (auth.User, bool) { return auth.CurrentUser(c.Context()) }

// MustUser returns the signed-in user and panics without one, for handlers
// behind RequireUser.
func MustUser(c fiber.Ctx) auth.User {
	u, ok := CurrentUser(c)
	if !ok {
		panic(authhttp.ErrNoUser)
	}
	return u
}

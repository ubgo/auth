// Package example wires a generated gqlgen server to ubgo/auth.
package example

import (
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	authgql "github.com/ubgo/auth/contrib/gqlgen"
	"github.com/ubgo/auth/contrib/gqlgen/example/graph"
	"github.com/ubgo/auth/plugin/password"
)

// Handler is the GraphQL endpoint: gqlgen behind authhttp.Middleware, so the
// session is resolved once per request and a sign-in's cookie reaches the
// response. opts are the authhttp options (CookiePrefix, CookieDomain, ...)
// the rest of the app passes to its own authhttp handlers, so the GraphQL
// endpoint and the REST routes agree about which cookie holds the session.
//
//ds:def id=handler-u8q3vm8a
func Handler(a *auth.Auth, pw *password.Plugin, opts ...authhttp.Option) http.Handler {
	srv := handler.New(graph.NewExecutableSchema(graph.Config{
		Resolvers:  &graph.Resolver{Auth: a, Password: pw},
		Directives: graph.DirectiveRoot{SignedIn: authgql.SignedIn},
	}))
	srv.AddTransport(transport.POST{})
	srv.SetErrorPresenter(authgql.ErrorPresenter)
	return authhttp.Middleware(a, opts...)(srv)
}

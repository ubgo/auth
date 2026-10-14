// Package authgql connects github.com/ubgo/auth to a gqlgen server.
//
// Resolvers call the plugins' typed Go API — pw.SignIn(ctx, in) — so every
// rule of the pipeline runs exactly as it does over REST. This package adds
// the three GraphQL-shaped pieces: the error presenter that turns an
// auth.Error into a GraphQL error with its stable code, the @signedIn
// directive, and a schema file to copy.
//
// The GraphQL handler must sit behind authhttp.Middleware: it attaches the
// request, resolves the session once for every field, and turns effects such
// as an issued session into the response's Set-Cookie header.
package authgql

import (
	"context"
	_ "embed"

	"github.com/99designs/gqlgen/graphql"
	"github.com/ubgo/auth"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Schema is the GraphQL schema of the auth types and the @signedIn
// directive. Copy it into the app's schema directory; gqlgen generates code in
// the app's module, so the library cannot generate it for you.
//
//go:embed auth.graphqls
var Schema string

// CodeExtension is the key of the stable error code in a GraphQL error's
// extensions.
//
//ds:def id=codeextension-8av7hy4c owner=@khanakia stability=stable
const CodeExtension = "code"

// ErrorPresenter turns errors from resolvers into GraphQL errors. An auth
// error keeps its code and safe message; anything else becomes the core's
// internal error, so a SQL message never reaches a client. Pass it to
// srv.SetErrorPresenter; log the original error in your own presenter first
// if you wrap this one.
//
//ds:def id=errorpresenter-fcjseuga
func ErrorPresenter(ctx context.Context, err error) *gqlerror.Error {
	gqlErr := graphql.DefaultErrorPresenter(ctx, err)
	info := auth.ErrorOf(err)
	gqlErr.Message = info.Message
	if gqlErr.Extensions == nil {
		gqlErr.Extensions = map[string]any{}
	}
	gqlErr.Extensions[CodeExtension] = info.Code
	return gqlErr
}

// SignedIn is the @signedIn directive: the field resolves only for a request
// with a session.
//
// The obj parameter is any because that is gqlgen's directive signature;
// the directive does not read it.
//
//ds:def id=signedin-rfebjfkv
func SignedIn(ctx context.Context, _ any, next graphql.Resolver) (any, error) {
	if _, ok := auth.CurrentUser(ctx); !ok {
		return nil, auth.ErrSignedOut
	}
	return next(ctx)
}

// Code returns the stable code of a GraphQL error, for tests and clients
// written in Go.
func Code(err *gqlerror.Error) string {
	if err == nil {
		return ""
	}
	code, _ := err.Extensions[CodeExtension].(string)
	return code
}

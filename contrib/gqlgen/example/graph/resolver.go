// Package graph is a gqlgen server whose auth fields call the ubgo/auth
// plugins' Go API.
package graph

//go:generate go tool gqlgen generate

import (
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/contrib/gqlgen/example/graph/model"
	"github.com/ubgo/auth/plugin/password"
)

// Resolver holds what the resolvers call: the core and the password plugin.
type Resolver struct {
	Auth     *auth.Auth
	Password *password.Plugin
}

// Helpers live here, not in the generated resolver files, which gqlgen
// rewrites and would move them out of.

func passwordSignUp(identifier, pw string, name *string) password.SignUpRequest {
	in := password.SignUpRequest{Identifier: identifier, Password: password.Secret(pw)}
	if name != nil {
		in.Name = *name
	}
	return in
}

func passwordSignIn(identifier, pw string) password.SignInRequest {
	return password.SignInRequest{Identifier: identifier, Password: password.Secret(pw)}
}

func userOf(u auth.UserView) *model.AuthUser {
	return &model.AuthUser{ID: u.ID, Name: u.Name, Image: u.Image}
}

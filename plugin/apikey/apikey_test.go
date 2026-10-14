package apikey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
)

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

// other is a second token resolver, to prove overlapping prefixes are refused.
type other struct{ prefix string }

func (other) Name() string          { return "other" }
func (o other) TokenPrefix() string { return o.prefix }
func (other) ResolveToken(context.Context, auth.Token) (auth.Principal, error) {
	return auth.Principal{}, auth.ErrSignedOut
}

func TestValidate(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, apikey.New())); !errors.Is(err, apikey.ErrNoScopes) {
		t.Fatalf("no scopes: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.Scopes("orders:read"), apikey.Prefix("x")))); err == nil {
		t.Fatal("a one-character prefix must be refused")
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.Scopes("orders:read")))); err != nil {
		t.Fatal(err)
	}
	// Permissions alone are enough: an app that decides through a
	// permission model is not made to declare a scope it never checks.
	if _, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.WithPermissions(apikey.Vocabulary{"orders": {"read"}})))); err != nil {
		t.Fatalf("permissions only: %v", err)
	}
	// Turned off again, neither is declared, which still fails closed.
	if _, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.WithPermissions(apikey.Vocabulary{"orders": {"read"}}), apikey.WithPermissions(nil)))); !errors.Is(err, apikey.ErrNoScopes) {
		t.Fatalf("permissions turned off: %v", err)
	}
}

func TestNew_RefusesOverlappingTokenPrefixes(t *testing.T) {
	_, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.Scopes("s")), other{prefix: "ubk_live_"}))
	if !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("overlapping prefixes: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.Scopes("s")), other{prefix: "sk_"})); err != nil {
		t.Fatalf("distinct prefixes: %v", err)
	}
}

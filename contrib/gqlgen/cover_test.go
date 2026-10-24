package authgql

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
)

// signIn is the smallest plugin auth.New accepts: one declared way in.
type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

func TestSignedIn_ResolvesTheFieldForASession(t *testing.T) {
	a := sessionAuth(t, signIn{})
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: "session-token"})
	if err := a.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := SignedIn(ctx, nil, func(context.Context) (any, error) { return sessionUserID, nil })
	if err != nil || got != sessionUserID {
		t.Fatalf("SignedIn = %v %v, want the field's value", got, err)
	}
}

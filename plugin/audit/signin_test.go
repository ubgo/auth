package audit

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
)

// flaggedSignIn is a third-party sign-in method that declares no event
// types: its sign-in operation only carries auth.OpInfo.SignIn.
type flaggedSignIn struct{ ops []auth.Operation }

func newFlaggedSignIn() flaggedSignIn {
	noop := func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil }
	return flaggedSignIn{ops: []auth.Operation{
		auth.Define(auth.OpInfo{ID: "acme.verify", Kind: auth.Mutation, Require: auth.Public, Path: "/verify", SignIn: true}, noop),
		auth.Define(auth.OpInfo{ID: "acme.send", Kind: auth.Mutation, Require: auth.Public, Path: "/send"}, noop),
	}}
}

func (flaggedSignIn) Name() string                   { return "acme" }
func (flaggedSignIn) SignsIn() bool                  { return true }
func (f flaggedSignIn) Operations() []auth.Operation { return f.ops }

// TestTypes_SignInFlagIsUserSignedIn: an operation marked SignIn is
// user_signed_in with no mapping anywhere, an unmarked one keeps its id, and
// Types still wins over the flag.
func TestTypes_SignInFlagIsUserSignedIn(t *testing.T) {
	wire := func(opts ...Option) *Plugin {
		p := New(append([]Option{To(writeOnly{})}, opts...)...)
		if _, err := auth.New(auth.WithPlugins(newFlaggedSignIn(), p)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := wire()
	if got := p.TypeOf("acme.verify"); got != TypeUserSignedIn {
		t.Fatalf("flagged operation typed %q", got)
	}
	if got := p.TypeOf("acme.send"); got != "acme.send" {
		t.Fatalf("unflagged operation typed %q", got)
	}
	if got := TypeOf("acme.verify"); got != "acme.verify" {
		t.Fatalf("the package mapping knows no wiring, got %q", got)
	}
	o := wire(Types(map[auth.EndpointID]EventType{"acme.verify": "acme_verified"}))
	if got := o.TypeOf("acme.verify"); got != "acme_verified" {
		t.Fatalf("Types must win over the flag, got %q", got)
	}
}

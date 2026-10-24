package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// selfServedPlugin registers one self-served operation and keeps it, so the
// test can call it through Go the way a plugin's own handler does.
type selfServedPlugin struct {
	op *auth.Op[struct{}, auth.Done]
}

func newSelfServed(info auth.OpInfo) *selfServedPlugin {
	return &selfServedPlugin{op: auth.Define(info, func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil })}
}

func (*selfServedPlugin) Name() string                   { return "f" }
func (p *selfServedPlugin) Operations() []auth.Operation { return []auth.Operation{p.op} }

// A self-served operation is wired (Auth.Operation finds it, Go calls run
// the pipeline) but no transport sees it in Auth.Operations.
func TestSelfServed_WiredButNotListed(t *testing.T) {
	p := newSelfServed(auth.OpInfo{ID: "f.token", Kind: auth.Mutation, Require: auth.Public, Path: "/token", SelfServed: true})
	a, err := newAuth(auth.WithPlugins(signIn{on: true}, p))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range a.Operations() {
		if op.Info().ID == "f.token" {
			t.Fatal("a self-served operation is listed for the transports to mount")
		}
	}
	if _, ok := a.Operation("f.token"); !ok {
		t.Fatal("a self-served operation is not wired")
	}
	if res, err := p.op.Call(context.Background(), struct{}{}); err != nil || !res.OK {
		t.Fatalf("Go call: %v %v", res, err)
	}
}

// A self-served operation can still be switched off and hooked, like any
// other.
func TestSelfServed_DisabledAndHooked(t *testing.T) {
	p := newSelfServed(auth.OpInfo{ID: "f.token", Kind: auth.Mutation, Require: auth.Public, Path: "/token", SelfServed: true})
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, p), auth.WithDisabledOperations("f.token")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.op.Call(context.Background(), struct{}{}); !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("disabled self-served operation answered %v", err)
	}
	hooked := false
	q := newSelfServed(auth.OpInfo{ID: "f.token", Kind: auth.Mutation, Require: auth.Public, Path: "/token", SelfServed: true})
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, q), auth.WithOperationHooks(auth.OperationHook{
		Match:  []auth.EndpointID{"f.token"},
		Before: func(context.Context, *auth.Call) error { hooked = true; return nil },
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := q.op.Call(context.Background(), struct{}{}); err != nil || !hooked {
		t.Fatalf("hook did not run on a self-served operation: %v", err)
	}
}

// A self-served cross-site form is refused: nothing would vet the handler
// whose origin check it skips.
func TestSelfServed_NotACrossSiteForm(t *testing.T) {
	p := newSelfServed(auth.OpInfo{ID: "f.relay", Kind: auth.Mutation, Require: auth.Public, Path: "/relay", SelfServed: true, CrossSiteForm: true})
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, p)); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("got %v, want ErrBadOperation", err)
	}
}

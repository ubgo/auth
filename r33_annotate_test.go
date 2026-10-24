package auth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ubgo/auth"
)

// annotatePlugin's outer operation annotates, calls the inner one (which
// annotates the same key on its own Call), then fails when asked.
type annotatePlugin struct {
	outer *auth.Op[bool, auth.Done]
	inner *auth.Op[struct{}, auth.Done]
}

var errAnnotateFail = auth.NewError("f.fail", http.StatusBadRequest, "Failed.")

func newAnnotatePlugin() *annotatePlugin {
	p := &annotatePlugin{}
	p.inner = auth.Define(auth.OpInfo{ID: "f.inner", Kind: auth.Mutation, Require: auth.Public, Path: "/inner"}, func(_ context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
		c.Annotate(auth.AnnotationOrganization, "org_inner")
		return auth.Done{OK: true}, nil
	})
	p.outer = auth.Define(auth.OpInfo{ID: "f.outer", Kind: auth.Mutation, Require: auth.Public, Path: "/outer"}, func(ctx context.Context, c *auth.Call, fail bool) (auth.Done, error) {
		c.Annotate(auth.AnnotationOrganization, "org_first")
		c.Annotate(auth.AnnotationOrganization, "org_outer")
		if _, err := p.inner.Call(ctx, struct{}{}); err != nil {
			return auth.Done{}, err
		}
		if fail {
			return auth.Done{}, errAnnotateFail
		}
		return auth.Done{OK: true}, nil
	})
	return p
}

func (*annotatePlugin) Name() string                   { return "f" }
func (p *annotatePlugin) Operations() []auth.Operation { return []auth.Operation{p.outer, p.inner} }

// Annotations reach After and Finally hooks, survive a failure, keep the
// last write, and are per call: a nested operation does not overwrite them.
func TestCall_Annotations(t *testing.T) {
	p := newAnnotatePlugin()
	var after, finally, innerSeen string
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, p), auth.WithOperationHooks(
		auth.OperationHook{
			Match: []auth.EndpointID{"f.outer"},
			After: func(_ context.Context, c *auth.Call, _ any) error {
				after = c.Annotation(auth.AnnotationOrganization)
				return nil
			},
			Finally: func(_ context.Context, c *auth.Call, _ error) { finally = c.Annotation(auth.AnnotationOrganization) },
		},
		auth.OperationHook{
			Match:   []auth.EndpointID{"f.inner"},
			Finally: func(_ context.Context, c *auth.Call, _ error) { innerSeen = c.Annotation(auth.AnnotationOrganization) },
		},
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.outer.Call(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if after != "org_outer" || finally != "org_outer" || innerSeen != "org_inner" {
		t.Fatalf("after %q finally %q inner %q", after, finally, innerSeen)
	}
	finally = ""
	if _, err := p.outer.Call(context.Background(), true); !errors.Is(err, errAnnotateFail) {
		t.Fatalf("failing call: %v", err)
	}
	if finally != "org_outer" {
		t.Fatalf("Finally after a failure read %q", finally)
	}
	// A Call the pipeline did not build reads "" and can still be written.
	var c auth.Call
	if c.Annotation("missing") != "" {
		t.Fatal("an unset annotation is not empty")
	}
	c.Annotate("k", "v")
	if c.Annotation("k") != "v" {
		t.Fatal("a literal Call lost its annotation")
	}
}

package anonymous_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/email"
)

var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

// TestWiring: the plugin is a sign-in method by itself, adds its column, and
// registers the delete route unless KeepUsers.
func TestWiring(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(anonymous.New()))
	if err != nil {
		t.Fatalf("guests alone must be a complete app: %v", err)
	}
	for _, id := range []auth.EndpointID{anonymous.EndpointSignIn, anonymous.EndpointDelete} {
		if _, ok := a.Operation(id); !ok {
			t.Fatalf("%s not registered", id)
		}
	}
	kept, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(anonymous.New(anonymous.KeepUsers())))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kept.Operation(anonymous.EndpointDelete); ok {
		t.Fatal("KeepUsers must leave the delete route out")
	}
	cols := anonymous.New().Columns()
	if len(cols) != 1 || cols[0].Name != anonymous.ColIsAnonymous || cols[0].Type != auth.ColumnBool || cols[0].Nullable {
		t.Fatalf("columns = %+v", cols)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range ms {
		if m.Owner == anonymous.PluginName {
			found = true
		}
	}
	if !found {
		t.Fatal("the column migration must be owned by the plugin")
	}
}

// TestSignInLimitOption: WithSignInLimit replaces the one rate rule.
func TestSignInLimitOption(t *testing.T) {
	rules := anonymous.New(anonymous.WithSignInLimit(3, 2*time.Hour)).RateLimits()
	if len(rules) != 1 || rules[0].Match != anonymous.EndpointSignIn || rules[0].Key != auth.ByIP || rules[0].Limit != 3 || rules[0].Window != 2*time.Hour {
		t.Fatalf("rules = %+v", rules)
	}
	def := anonymous.New().RateLimits()
	if len(def) != 1 || def[0].Limit != 10 || def[0].Window != time.Hour {
		t.Fatalf("default rule = %+v", def)
	}
}

// TestUnwired: the Go methods of a plugin not passed to auth.New report it.
func TestUnwired(t *testing.T) {
	an := anonymous.New()
	if _, err := an.SignIn(context.Background()); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("SignIn unwired = %v", err)
	}
	if err := an.Delete(context.Background()); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Delete unwired = %v", err)
	}
	// Sweep without SweepStale deletes nothing and touches no database.
	if n, err := an.Sweep(context.Background(), time.Now()); n != 0 || err != nil {
		t.Fatalf("Sweep off = %d %v", n, err)
	}
	if !an.SignsIn() || an.Name() != anonymous.PluginName {
		t.Fatal("identity")
	}
	_ = noMail
}

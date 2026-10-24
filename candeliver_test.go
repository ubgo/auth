package auth_test

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
)

// cdSilentKind registers an identifier kind and delivers nothing.
type cdSilentKind struct{ kind auth.IdentifierKindName }

func (s cdSilentKind) Name() string { return "silent_" + string(s.kind) }
func (s cdSilentKind) Identifiers() []auth.IdentifierKind {
	return []auth.IdentifierKind{{Name: s.kind, Unique: true, Normalize: func(raw string) (string, error) { return raw, nil }}}
}

// cdDeliveringKind registers a kind and delivers to it.
type cdDeliveringKind struct{ cdSilentKind }

func (cdDeliveringKind) Deliver(context.Context, auth.Identity, auth.Message) error { return nil }

// cdConfigOf is the configuration a Validator would see.
type cdConfigOf struct{ got *auth.Config }

func (cdConfigOf) Name() string                      { return "cfg_of" }
func (c cdConfigOf) Validate(cfg *auth.Config) error { *c.got = *cfg; return nil }

// TestConfig_CanDeliver: true only for a registered kind whose plugin is a
// Deliverer, as Validate sees it; false for a silent kind and an unknown one.
func TestConfig_CanDeliver(t *testing.T) {
	var cfg auth.Config
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}, cdSilentKind{"handle"}, cdDeliveringKind{cdSilentKind{"pager"}}, cdConfigOf{&cfg})); err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[auth.IdentifierKindName]bool{"pager": true, "handle": false, "nope": false} {
		if got := cfg.CanDeliver(kind); got != want {
			t.Errorf("CanDeliver(%q) = %v, want %v", kind, got, want)
		}
	}
	if (auth.Config{}).CanDeliver("pager") {
		t.Fatal("a zero Config delivers nothing")
	}
}

package accessapikey_test

import (
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessapikey"
	"github.com/ubgo/auth/plugin/apikey"
)

// TestMatchesTheBuiltInVocabulary: for random held and wanted permissions,
// the adapter over an access control answers Check and Grants exactly as
// apikey's built-in Vocabulary over the same statements, so swapping one
// for the other changes no key's answer.
func TestMatchesTheBuiltInVocabulary(t *testing.T) {
	stmts := access.Statements{"orders": {"read", "write"}, "billing": {"read"}}
	adapter := accessapikey.New(access.MustNew(stmts))
	builtin := apikey.Vocabulary(stmts)
	resources := []string{"orders", "billing", "other"}
	actions := []string{"read", "write", "nope"}
	rng := rand.New(rand.NewPCG(3, 4))
	gen := func() apikey.Permissions {
		p := apikey.Permissions{}
		for range rng.IntN(3) {
			res := resources[rng.IntN(len(resources))]
			p[res] = append(p[res], actions[rng.IntN(len(actions))])
		}
		return p
	}
	for i := 0; i < 5000; i++ {
		held, want := gen(), gen()
		if (adapter.Check(held) == nil) != (builtin.Check(held) == nil) {
			t.Fatalf("Check(%v) differs", held)
		}
		if adapter.Check(held) != nil || len(want) == 0 {
			continue // the plugin never asks Grants about these
		}
		if adapter.Grants(held, want) != builtin.Grants(held, want) {
			t.Fatalf("Grants(%v, %v): adapter %v, built-in %v", held, want, adapter.Grants(held, want), builtin.Grants(held, want))
		}
	}
}

// TestNilAccessControl: an adapter without an access control refuses every
// permission and grants nothing.
func TestNilAccessControl(t *testing.T) {
	c := accessapikey.New(nil)
	if err := c.Check(apikey.Permissions{"orders": {"read"}}); !errors.Is(err, access.ErrEmptyStatements) {
		t.Fatalf("Check: %v", err)
	}
	if c.Grants(apikey.Permissions{"orders": {"read"}}, apikey.Permissions{"orders": {"read"}}) {
		t.Fatal("Grants without an access control")
	}
}

// TestGrantsFailsClosedOnInputThePluginNeverSends: the plugin never asks
// Grants about an empty want, and a checker asked anyway must deny, since
// asking for nothing proves nothing; the adapter and the built-in
// Vocabulary agree.
func TestGrantsFailsClosedOnInputThePluginNeverSends(t *testing.T) {
	stmts := access.Statements{"orders": {"read"}}
	adapter := accessapikey.New(access.MustNew(stmts))
	for name, c := range map[string]apikey.PermissionChecker{"adapter": adapter, "built-in": apikey.Vocabulary(stmts)} {
		if c.Grants(apikey.Permissions{"orders": {"read"}}, apikey.Permissions{}) {
			t.Errorf("%s: an empty want granted", name)
		}
	}
}

// TestShrunkVocabularyAgreesWithTheBuiltIn: keys made under a wider
// vocabulary are checked after a resource and an action were removed. Both
// checkers skip what is no longer declared, so a key keeps the permissions
// that still exist, and both deny the removed resource and action
// themselves: for random held and wanted permissions drawn from the old
// vocabulary, Grants answers identically.
func TestShrunkVocabularyAgreesWithTheBuiltIn(t *testing.T) {
	shrunk := access.Statements{"orders": {"read"}, "billing": {"read"}} // "reports" and orders:write removed
	adapter := accessapikey.New(access.MustNew(shrunk))
	builtin := apikey.Vocabulary(shrunk)
	stale := apikey.Permissions{"orders": {"read", "write"}, "billing": {"read"}, "reports": {"read"}}
	cases := []struct {
		name string
		want apikey.Permissions
		ok   bool
	}{
		{"a still-declared permission", apikey.Permissions{"orders": {"read"}}, true},
		{"two still-declared resources", apikey.Permissions{"orders": {"read"}, "billing": {"read"}}, true},
		{"the removed resource", apikey.Permissions{"reports": {"read"}}, false},
		{"the removed action", apikey.Permissions{"orders": {"write"}}, false},
		{"a declared and the removed resource", apikey.Permissions{"orders": {"read"}, "reports": {"read"}}, false},
	}
	for _, tc := range cases {
		for name, c := range map[string]apikey.PermissionChecker{"adapter": adapter, "built-in": builtin} {
			if got := c.Grants(stale, tc.want); got != tc.ok {
				t.Errorf("%s: %s: Grants = %v, want %v", name, tc.name, got, tc.ok)
			}
		}
	}

	resources := []string{"orders", "billing", "reports"}
	actions := []string{"read", "write"}
	rng := rand.New(rand.NewPCG(5, 6))
	gen := func() apikey.Permissions {
		p := apikey.Permissions{}
		for range 1 + rng.IntN(3) {
			res := resources[rng.IntN(len(resources))]
			p[res] = append(p[res], actions[rng.IntN(len(actions))])
		}
		return p
	}
	for i := 0; i < 5000; i++ {
		held, want := gen(), gen()
		if a, b := adapter.Grants(held, want), builtin.Grants(held, want); a != b {
			t.Fatalf("Grants(%v, %v): adapter %v, built-in %v", held, want, a, b)
		}
	}
}

package admin_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/ubgo/auth/plugin/admin"
)

// TestRoles_DecodeStringOrList: set-role's role decodes from "a,b" or
// ["a","b"] to the same list, as better-auth sends either; anything else is
// ErrBadRole.
func TestRoles_DecodeStringOrList(t *testing.T) {
	for _, body := range []string{`"support, admin"`, `["support","admin"]`, `["support,admin"]`} {
		var r admin.Roles
		if err := json.Unmarshal([]byte(body), &r); err != nil || !slices.Equal(r, admin.Roles{"support", "admin"}) {
			t.Errorf("%s = %v %v", body, r, err)
		}
	}
	var r admin.Roles
	if err := json.Unmarshal([]byte(`5`), &r); !errors.Is(err, admin.ErrBadRole) {
		t.Fatalf("a number: %v", err)
	}
}

package accessadmin_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessadmin"
	"github.com/ubgo/auth/plugin/admin"
)

// TestDefaultRolesMatchTheBuiltIn: for random requests over the admin
// vocabulary, accessadmin's default roles answer exactly as the admin
// plugin's built-in roles, so moving to the adapter changes nothing.
func TestDefaultRolesMatchTheBuiltIn(t *testing.T) {
	ctx := context.Background()
	built := admin.DefaultRoles()
	authz := accessadmin.MustNew(accessadmin.DefaultAccessControl, nil)
	resources := []string{admin.ResourceUser, admin.ResourceSession, "other"}
	actions := slices.Concat(admin.DefaultStatements[admin.ResourceUser], []string{admin.ActionRevoke, "nope"})
	connectors := []admin.Connector{"", admin.And, admin.Or}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5000; i++ {
		want := admin.Permissions{}
		for range rng.IntN(3) {
			res := resources[rng.IntN(len(resources))]
			for range rng.IntN(3) {
				want[res] = append(want[res], actions[rng.IntN(len(actions))])
			}
			if want[res] == nil {
				want[res] = []string{}
			}
		}
		conn := connectors[rng.IntN(len(connectors))]
		for _, role := range []string{admin.RoleAdmin, admin.RoleUser} {
			got, err := authz.Authorize(ctx, admin.AccessRequest{Roles: []string{role}, Permissions: want, Connector: conn})
			if err != nil {
				t.Fatal(err)
			}
			if exp := admin.Grants(built[role], want, conn); got != exp {
				t.Fatalf("%s %v %q: adapter %v, built-in %v", role, want, conn, got, exp)
			}
		}
	}
}

// TestNew: roles are added or replace a default, named statements must be
// declared, names must be single, and a nil access control is refused.
func TestNew(t *testing.T) {
	ctx := context.Background()
	ac := accessadmin.DefaultAccessControl
	support := ac.MustRole(access.Permissions{admin.ResourceUser: {admin.ActionGet, admin.ActionList}})
	authz, err := accessadmin.New(ac, map[string]access.Role{"support": support})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(roles []string, act string) bool {
		ok, err := authz.Authorize(ctx, admin.AccessRequest{Roles: roles, Permissions: admin.Permissions{admin.ResourceUser: {act}}})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !ask([]string{"support"}, admin.ActionGet) || ask([]string{"support"}, admin.ActionBan) || !ask([]string{admin.RoleAdmin}, admin.ActionBan) {
		t.Fatal("support role")
	}
	if !authz.DefinesRole("support") || !authz.DefinesRole(admin.RoleUser) || authz.DefinesRole("nope") {
		t.Fatal("DefinesRole")
	}
	other := access.MustNew(access.Statements{"x": {"y"}})
	for name, roles := range map[string]map[string]access.Role{
		"foreign role":  {"r": other.MustRole(access.Permissions{"x": {"y"}})},
		"comma in name": {"a,b": {}},
		"empty name":    {"": {}},
		"padded name":   {" a": {}},
	} {
		if _, err := accessadmin.New(ac, roles); err == nil {
			t.Fatalf("%s passed", name)
		}
	}
	if _, err := accessadmin.New(nil, nil); !errors.Is(err, accessadmin.ErrNoAccessControl) {
		t.Fatalf("nil access control: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustNew did not panic")
		}
	}()
	accessadmin.MustNew(nil, nil)
}

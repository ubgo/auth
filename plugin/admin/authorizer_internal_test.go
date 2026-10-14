package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestGrants pins better-auth's role.authorize semantics the built-in roles
// keep: a resource granted nothing fails whatever the connector, every
// listed action is needed, an empty request or an empty action list is
// denied, And needs every resource, Or one, and Or stops at the first
// resource in sorted order.
func TestGrants(t *testing.T) {
	granted := Permissions{"a": {"x", "y"}, "b": {"z"}, "c": {}}
	cases := []struct {
		name string
		want Permissions
		conn Connector
		ok   bool
	}{
		{"one action", Permissions{"a": {"x"}}, "", true},
		{"every action", Permissions{"a": {"x", "y"}}, And, true},
		{"one action missing", Permissions{"a": {"x", "q"}}, And, false},
		{"empty request", Permissions{}, And, false},
		{"empty action list", Permissions{"a": {}}, And, false},
		{"and needs both", Permissions{"a": {"x"}, "b": {"q"}}, And, false},
		{"and both pass", Permissions{"a": {"x"}, "b": {"z"}}, And, true},
		{"or needs one", Permissions{"a": {"q"}, "b": {"z"}}, Or, true},
		{"or none", Permissions{"a": {"q"}, "b": {"q"}}, Or, false},
		{"ungranted resource fails or", Permissions{"0": {"x"}, "a": {"x"}}, Or, false},
		{"or stops before an ungranted resource", Permissions{"a": {"x"}, "zz": {"x"}}, Or, true},
		{"granted nothing on c", Permissions{"c": {"x"}}, And, false},
	}
	for _, tc := range cases {
		if got := Grants(granted, tc.want, tc.conn); got != tc.ok {
			t.Errorf("%s: Grants = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

// TestDefaultAuthorizer: the built-in admin role may do every admin
// action but impersonate-admins, the user role nothing, an unknown role
// nothing, and several roles pass when one does.
func TestDefaultAuthorizer(t *testing.T) {
	d := newDefaultAuthorizer()
	ask := func(roles []string, res, act string) bool {
		ok, err := d.Authorize(context.Background(), AccessRequest{Roles: roles, Permissions: Permissions{res: {act}}})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for res, acts := range DefaultStatements {
		for _, act := range acts {
			if want := act != ActionImpersonateAdmins; ask([]string{RoleAdmin}, res, act) != want {
				t.Fatalf("admin %s:%s = %v", res, act, !want)
			}
			if ask([]string{RoleUser}, res, act) || ask([]string{"nope"}, res, act) {
				t.Fatalf("user or unknown role holds %s:%s", res, act)
			}
		}
	}
	if !ask([]string{"nope", RoleUser, RoleAdmin}, ResourceUser, ActionBan) {
		t.Fatal("one role of several should be enough")
	}
	if !d.DefinesRole(RoleAdmin) || !d.DefinesRole(RoleUser) || d.DefinesRole("support") {
		t.Fatal("DefinesRole")
	}
}

// catalogAuthz is an Authorizer that also defines its own role names.
type catalogAuthz struct{ AuthorizerFunc }

func (catalogAuthz) DefinesRole(name string) bool {
	return name == "support" || name == RoleAdmin || name == RoleUser
}

// TestAuthorizerSeam: WithAuthorizer replaces the decision, an error never
// allows (even with true), role names come from a RoleCatalog or default to
// the built-in pair, and a nil authorizer or an undefined DefaultRole is
// refused at start-up.
func TestAuthorizerSeam(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("policy engine down")
	errTrue := New(WithAuthorizer(AuthorizerFunc(func(context.Context, AccessRequest) (bool, error) { return true, boom })))
	if ok, err := errTrue.decide(ctx, AccessRequest{}); ok || !errors.Is(err, boom) {
		t.Fatalf("an error must refuse: %v %v", ok, err)
	}
	if errTrue.CheckRolePermission(ctx, RoleAdmin, Permissions{ResourceUser: {ActionGet}}) {
		t.Fatal("CheckRolePermission allowed on an authorizer error")
	}

	var seen AccessRequest
	custom := New(WithAuthorizer(AuthorizerFunc(func(_ context.Context, r AccessRequest) (bool, error) {
		seen = r
		return r.Permissions[ResourceUser][0] == ActionGet, nil
	})))
	if !custom.CheckRolePermission(ctx, "a, b", Permissions{ResourceUser: {ActionGet}}) || custom.CheckRolePermission(ctx, RoleAdmin, Permissions{ResourceUser: {ActionBan}}) {
		t.Fatal("the custom authorizer did not decide")
	}
	if len(seen.Roles) != 1 || seen.Roles[0] != RoleAdmin || seen.Connector != And || seen.UserID != "" || seen.Call != nil {
		t.Fatalf("request = %+v", seen)
	}
	if !custom.definesRole(RoleAdmin) || custom.definesRole("support") {
		t.Fatal("an authorizer without a catalog accepts the built-in names only")
	}
	if cat := New(WithAuthorizer(catalogAuthz{})); !cat.definesRole("support") || cat.definesRole("nope") {
		t.Fatal("a RoleCatalog names the roles")
	}
	if err := New(WithAuthorizer(nil)).OptionErr(); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("nil authorizer: %v", err)
	}
	if err := New(DefaultRole("support")).Validate(&auth.Config{}); err == nil {
		t.Fatal("an undefined DefaultRole passed")
	}
	if err := New(WithAuthorizer(catalogAuthz{}), DefaultRole("support")).Validate(&auth.Config{}); err != nil {
		t.Fatalf("a catalog role as DefaultRole: %v", err)
	}
	if err := New(AdminRoles("a,b")).Validate(&auth.Config{}); err == nil {
		t.Fatal("a comma in a role name passed")
	}
}

// TestTargetOf: the target is the input's TargetUserID, or "" without one.
func TestTargetOf(t *testing.T) {
	if got := targetOf(&auth.Call{Input: BanRequest{UserID: "u1"}}); got != "u1" {
		t.Fatalf("targetOf = %q", got)
	}
	if got := targetOf(&auth.Call{Input: PermissionRequest{UserID: "u1"}}); got != "" {
		t.Fatalf("targetOf without a target = %q", got)
	}
}

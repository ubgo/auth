package admin_test

import (
	"context"
	"fmt"
	"slices"

	"github.com/ubgo/auth/plugin/admin"
)

// policyAuthorizer decides from policy lines (subject,
// resource, action), the shape a policy engine's Enforce(sub, obj, act)
// answers; with a real engine, Authorize calls the engine instead of
// scanning the lines. Every action of every resource asked for must be
// granted to one of the user's roles; Or asks for one resource.
type policyAuthorizer struct{ lines [][3]string }

func (p policyAuthorizer) enforce(sub, obj, act string) bool {
	return slices.Contains(p.lines, [3]string{sub, obj, act})
}

// Authorize is the whole adapter: the plugin passes the user's roles and
// the permissions asked for.
//
//ds:def id=policyauthorizer-authorize-cad7rbjj owner=@khanakia stability=stable
func (p policyAuthorizer) Authorize(_ context.Context, req admin.AccessRequest) (bool, error) {
	if len(req.Permissions) == 0 {
		return false, nil // asking for nothing proves nothing
	}
	anyRes := false
	for res, acts := range req.Permissions {
		ok := len(acts) > 0 && slices.ContainsFunc(req.Roles, func(role string) bool {
			return !slices.ContainsFunc(acts, func(act string) bool { return !p.enforce(role, res, act) })
		})
		if !ok && req.Connector != admin.Or {
			return false, nil
		}
		anyRes = anyRes || ok
	}
	return anyRes, nil
}

// DefinesRole lets set-role store the roles the policy names.
func (p policyAuthorizer) DefinesRole(name string) bool {
	return slices.ContainsFunc(p.lines, func(l [3]string) bool { return l[0] == name }) || name == admin.RoleUser
}

// Example_policyAuthorizer plugs a policy table into the admin plugin:
// a support role that may read users but not ban them.
//
//ds:def id=example-policyauthorizer-27fwf8au owner=@khanakia stability=stable
func Example_policyAuthorizer() {
	authz := policyAuthorizer{lines: [][3]string{
		{"admin", admin.ResourceUser, admin.ActionBan},
		{"admin", admin.ResourceUser, admin.ActionGet},
		{"support", admin.ResourceUser, admin.ActionGet},
	}}
	p := admin.New(admin.WithAuthorizer(authz))

	ctx := context.Background()
	fmt.Println(p.CheckRolePermission(ctx, "support", admin.Permissions{admin.ResourceUser: {admin.ActionGet}}))
	fmt.Println(p.CheckRolePermission(ctx, "support", admin.Permissions{admin.ResourceUser: {admin.ActionBan}}))
	fmt.Println(p.CheckRolePermission(ctx, "support,admin", admin.Permissions{admin.ResourceUser: {admin.ActionBan}}))
	// Output:
	// true
	// false
	// true
}

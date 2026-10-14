package orgjwt_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/organization/orgjwt"
)

// fakeSource is a Source with one organization, org_1, in which usr_1 is
// an admin; err, when set, fails the method named by failing.
type fakeSource struct {
	active  string
	role    organization.Role
	perms   access.Permissions
	failing string
	err     error
}

func (f fakeSource) fail(method string) error {
	if f.failing == method {
		return f.err
	}
	return nil
}

func (f fakeSource) ActiveOrgID(context.Context) (string, bool, error) {
	return f.active, f.active != "", f.fail("active")
}

func (f fakeSource) GetFor(_ context.Context, id string) (organization.Org, error) {
	return organization.Org{ID: id, Slug: "acme"}, f.fail("get")
}

func (f fakeSource) RoleOf(_ context.Context, _, userID string) (organization.Role, error) {
	if f.role == "" {
		return "", organization.ErrNotMember
	}
	return f.role, f.fail("role")
}

func (f fakeSource) PermissionsOf(context.Context, string, organization.Role) (access.Permissions, error) {
	return f.perms, f.fail("perms")
}

func run(t *testing.T, src orgjwt.Source, opts ...orgjwt.Option) (map[string]any, error) {
	t.Helper()
	fn, err := orgjwt.Claims(src, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return fn(context.Background(), auth.User{ID: "usr_1"}, auth.Session{ID: "ses_1"})
}

func TestClaims_ActiveOrganization(t *testing.T) {
	src := fakeSource{active: "org_1", role: "admin,member", perms: access.Permissions{"member": {"update", "create", "create"}, "team": {}, "ac": {"read"}}}
	got, err := run(t, src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"org": map[string]any{"id": "org_1", "slug": "acme", "role": "admin,member", "permissions": []string{"ac:read", "member:create", "member:update"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claims = %v\nwant %v", got, want)
	}
	got, _ = run(t, src, orgjwt.ClaimName("o"), orgjwt.WithoutPermissions())
	if o, ok := got["o"].(map[string]any); !ok || o["permissions"] != nil || o["role"] != "admin,member" {
		t.Fatalf("renamed, no permissions = %v", got)
	}
	if got, _ = run(t, src, orgjwt.ClaimName("")); got["org"] == nil {
		t.Fatalf(`ClaimName("") = %v, want the default`, got)
	}
}

// TestClaims_NoOrganizationNoClaim: no active organization, or one the
// caller is no longer a member of, adds no claim and no error.
func TestClaims_NoOrganizationNoClaim(t *testing.T) {
	for name, src := range map[string]fakeSource{
		"none active": {},
		"not member":  {active: "org_1"},
	} {
		if got, err := run(t, src); err != nil || len(got) != 0 {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
}

// TestClaims_ReadFailuresFailTheToken: every failing read is returned, so
// the token call fails instead of minting a token without the claim.
func TestClaims_ReadFailuresFailTheToken(t *testing.T) {
	boom := errors.New("db down")
	for _, m := range []string{"active", "role", "get", "perms"} {
		src := fakeSource{active: "org_1", role: "admin", failing: m, err: boom}
		if _, err := run(t, src); !errors.Is(err, boom) {
			t.Errorf("%s failing: %v", m, err)
		}
	}
}

func TestFlatten_EmptyIsNotNil(t *testing.T) {
	if got := orgjwt.Flatten(nil); got == nil || len(got) != 0 {
		t.Fatalf("Flatten(nil) = %#v", got)
	}
}

// TestClaims_PermissionsFromTheAppsAuthorizer: Permissions replaces the
// role-derived list (an app on Casbin or OPA), sorted and deduplicated,
// receives the org, user and role, and its error fails the token.
func TestClaims_PermissionsFromTheAppsAuthorizer(t *testing.T) {
	src := fakeSource{active: "org_1", role: "admin", perms: access.Permissions{"member": {"create"}}}
	var seen string
	custom := func(_ context.Context, orgID, userID string, role organization.Role) ([]string, error) {
		seen = orgID + "/" + userID + "/" + string(role)
		return []string{"report:read", "billing:view", "report:read"}, nil
	}
	got, err := run(t, src, orgjwt.Permissions(custom))
	if err != nil {
		t.Fatal(err)
	}
	if p := got["org"].(map[string]any)["permissions"]; !reflect.DeepEqual(p, []string{"billing:view", "report:read"}) || seen != "org_1/usr_1/admin" {
		t.Fatalf("permissions = %v, seen %q", p, seen)
	}
	empty := func(context.Context, string, string, organization.Role) ([]string, error) { return nil, nil }
	got, _ = run(t, src, orgjwt.Permissions(empty))
	if p := got["org"].(map[string]any)["permissions"]; !reflect.DeepEqual(p, []string{}) {
		t.Fatalf("empty list = %#v, want []", p)
	}
	boom := errors.New("opa down")
	failing := func(context.Context, string, string, organization.Role) ([]string, error) { return nil, boom }
	if _, err := run(t, src, orgjwt.Permissions(failing)); !errors.Is(err, boom) {
		t.Fatalf("failing authorizer: %v", err)
	}
}

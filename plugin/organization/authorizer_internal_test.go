package organization

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
)

// TestAuthorizerSeam: the default is the static-role check, WithAuthorizer
// replaces it with the request it is given, an error never allows (even
// with true), and a nil authorizer is refused at start-up.
func TestAuthorizerSeam(t *testing.T) {
	ctx := context.Background()
	req := access.Request{ResourceMember: access.All(ActionDelete)}

	def := New()
	for role, want := range map[Role]bool{RoleOwner: true, RoleAdmin: true, RoleMember: false, "member,admin": true} {
		if ok, err := def.allows(ctx, nil, "org_1", "usr_1", role, req, access.And); err != nil || ok != want {
			t.Fatalf("default %s: %v %v", role, ok, err)
		}
	}

	boom := errors.New("policy engine down")
	errTrue := New(WithAuthorizer(AuthorizerFunc(func(context.Context, AccessRequest) (bool, error) { return true, boom })))
	if ok, err := errTrue.allows(ctx, nil, "org_1", "usr_1", RoleOwner, req, access.And); ok || !errors.Is(err, boom) {
		t.Fatalf("an error must refuse: %v %v", ok, err)
	}

	var seen AccessRequest
	deny := New(WithAuthorizer(AuthorizerFunc(func(_ context.Context, r AccessRequest) (bool, error) {
		seen = r
		return false, nil
	})))
	if ok, err := deny.allows(ctx, &auth.Call{Op: auth.OpInfo{ID: EndpointRemoveMember}}, "org_1", "usr_1", RoleOwner, req, access.Or); ok || err != nil {
		t.Fatalf("a denying authorizer allowed the owner: %v %v", ok, err)
	}
	if seen.OrgID != "org_1" || seen.UserID != "usr_1" || seen.Role != RoleOwner || seen.Connector != access.Or || seen.Operation != EndpointRemoveMember || seen.Call == nil {
		t.Fatalf("request = %+v", seen)
	}
	if err := deny.authorize(ctx, &auth.Call{User: &auth.User{ID: "usr_2"}}, "org_1", RoleOwner, req); !errors.Is(err, ErrForbidden) || seen.UserID != "usr_2" {
		t.Fatalf("authorize: %v, user %q", err, seen.UserID)
	}

	noMail := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"),
		auth.WithPlugins(signInStub{}, email.New(email.WithMailer(noMail)), New(WithAuthorizer(nil)))); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("nil authorizer: %v", err)
	}
}

// TestRoleAuthorizerComposes: an authorizer that adds a rule to the roles
// wraps RoleAuthorizer, so the role model stays reachable by name.
func TestRoleAuthorizerComposes(t *testing.T) {
	var p *Plugin
	p = New(WithAuthorizer(AuthorizerFunc(func(ctx context.Context, r AccessRequest) (bool, error) {
		if r.OrgID == "frozen" {
			return false, nil
		}
		return p.RoleAuthorizer().Authorize(ctx, r)
	})))
	req := access.Request{ResourceTeam: access.All(ActionCreate)}
	if ok, err := p.allows(context.Background(), nil, "org_1", "u", RoleAdmin, req, access.And); !ok || err != nil {
		t.Fatalf("role model: %v %v", ok, err)
	}
	if ok, _ := p.allows(context.Background(), nil, "frozen", "u", RoleOwner, req, access.And); ok {
		t.Fatal("the added rule did not refuse")
	}
}

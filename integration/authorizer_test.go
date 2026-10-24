package integration

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/organization"
)

// errPolicyDown is the failure a policy engine that is unreachable returns.
var errPolicyDown = errors.New("policy engine down")

// TestAuthorizer_AdminABAC plugs an attribute-based authorizer into the
// admin plugin: it reads the target user, not roles, so the built-in admin
// may read anyone but ban nobody named in a protected list, and the request
// it receives carries the caller, the resolved roles, the target and the
// operation. An authorizer error refuses the operation instead of allowing
// it, even when it also returns true.
func TestAuthorizer_AdminABAC(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var (
			mu        sync.Mutex
			seen      []admin.AccessRequest
			protected = map[string]bool{}
			down      bool
		)
		abac := admin.AuthorizerFunc(func(_ context.Context, r admin.AccessRequest) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, r)
			if down {
				return true, errPolicyDown
			}
			if !slices.Contains(r.Roles, admin.RoleAdmin) {
				return false, nil
			}
			return !(r.Permissions[admin.ResourceUser] != nil && slices.Contains(r.Permissions[admin.ResourceUser], admin.ActionBan) && protected[r.TargetUserID]), nil
		})
		w := newAdminWorld(t, e, []admin.Option{admin.WithAuthorizer(abac)})
		mu.Lock()
		protected[w.bob.User.ID] = true
		mu.Unlock()

		if _, err := w.ad.User(w.bossCtx(), w.bob.User.ID); err != nil {
			t.Fatalf("admin reads bob: %v", err)
		}
		if err := w.ad.Ban(w.bossCtx(), w.bob.User.ID, "x"); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("ban of a protected user: %v", err)
		}
		mu.Lock()
		last := seen[len(seen)-1]
		mu.Unlock()
		if last.UserID != w.boss.User.ID || last.TargetUserID != w.bob.User.ID || last.Operation != admin.EndpointBan || last.Call == nil || !slices.Contains(last.Roles, admin.RoleAdmin) {
			t.Fatalf("request = %+v", last)
		}
		if _, err := w.ad.User(request(w.a, w.bob.Token), w.boss.User.ID); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("a non-admin reads: %v", err)
		}
		if ok, err := w.ad.HasPermission(w.bossCtx(), admin.PermissionRequest{Permissions: admin.Permissions{admin.ResourceUser: {admin.ActionGet}}}); !ok || err != nil {
			t.Fatalf("has-permission: %v %v", ok, err)
		}

		mu.Lock()
		down = true
		mu.Unlock()
		if _, err := w.ad.User(w.bossCtx(), w.bob.User.ID); !errors.Is(err, errPolicyDown) {
			t.Fatalf("an authorizer error must refuse: %v", err)
		}
		if ok, err := w.ad.HasPermission(w.bossCtx(), admin.PermissionRequest{Permissions: admin.Permissions{admin.ResourceUser: {admin.ActionGet}}}); ok || err == nil {
			t.Fatalf("has-permission with the engine down: %v %v", ok, err)
		}
	})
}

// TestAuthorizer_OrganizationABAC plugs an authorizer into the
// organization plugin that keeps the roles (RoleAuthorizer) and adds one
// attribute rule: a frozen organization refuses every permission, even to
// its owner. Membership stays the plugin's, and an authorizer error refuses.
func TestAuthorizer_OrganizationABAC(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var (
			mu     sync.Mutex
			frozen = map[string]bool{}
			down   bool
			org    *organization.Plugin
		)
		abac := organization.AuthorizerFunc(func(ctx context.Context, r organization.AccessRequest) (bool, error) {
			mu.Lock()
			isFrozen, isDown := frozen[r.OrgID], down
			mu.Unlock()
			if isDown {
				return true, errPolicyDown
			}
			if isFrozen {
				return false, nil
			}
			return org.RoleAuthorizer().Authorize(ctx, r)
		})
		// The option records the plugin, so the rule can wrap its roles from
		// the first join on.
		w := r30Setup(t, e, func(p *organization.Plugin) {
			org = p
			organization.WithAuthorizer(abac)(p)
		})
		ctx := context.Background()
		del := access.Request{organization.ResourceMember: access.All(organization.ActionDelete)}

		if ok, err := w.org.Can(ctx, w.o.ID, w.owner.User.ID, del, access.And); !ok || err != nil {
			t.Fatalf("roles still decide: %v %v", ok, err)
		}
		if ok, err := w.org.Can(ctx, w.o.ID, w.carol.User.ID, del, access.And); ok || err != nil {
			t.Fatalf("a member deletes: %v %v", ok, err)
		}
		mu.Lock()
		frozen[w.o.ID] = true
		mu.Unlock()
		if err := w.org.RemoveMember(w.ownerCtx(), organization.MemberRequest{OrgID: w.o.ID, UserID: w.carol.User.ID}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("owner removes in a frozen org: %v", err)
		}
		if ok, err := w.org.HasPermission(w.ownerCtx(), organization.PermissionRequest{OrgID: w.o.ID, Permissions: access.Permissions{organization.ResourceMember: {organization.ActionDelete}}}); ok || err != nil {
			t.Fatalf("has-permission in a frozen org: %v %v", ok, err)
		}
		if _, allowed, err := w.org.APIKeyPermission(ctx, w.o.ID, w.owner.User.ID, "create"); allowed || err != nil {
			t.Fatalf("the creator's API-key shortcut survived a custom authorizer: allowed=%v %v", allowed, err)
		}
		if _, err := w.org.Can(ctx, w.o.ID, "usr_stranger", del, access.And); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("a stranger: %v", err)
		}

		mu.Lock()
		frozen[w.o.ID], down = false, true
		mu.Unlock()
		if err := w.org.RemoveMember(w.ownerCtx(), organization.MemberRequest{OrgID: w.o.ID, UserID: w.carol.User.ID}); !errors.Is(err, errPolicyDown) {
			t.Fatalf("an authorizer error must refuse: %v", err)
		}
		if _, err := w.org.RoleOf(ctx, w.o.ID, w.carol.User.ID); err != nil {
			t.Fatalf("carol was removed despite the refusal: %v", err)
		}
	})
}

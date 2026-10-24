package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/sqlb"
)

// The statements COVERAGE.md listed as reachable and untested on
// 2026-10-08 (apikey, audit, scim, organization), each driven through the
// public API. A row that disappears between a plugin's read and its write is
// produced through a hook the app owns, the one place a concurrent request
// can be stood in for without racing two goroutines.

// p3CoverOrgKeys is an apikey plugin with an organization-owned
// configuration whose membership check is check.
func p3CoverOrgKeys(check apikey.OrganizationsFunc, opts ...apikey.Option) *apikey.Plugin {
	return apikey.New(append([]apikey.Option{apikey.Scopes("read"), apikey.WithOrganizations(check),
		apikey.Configuration("org", apikey.Prefix("ubo_"), apikey.OrganizationOwned())}, opts...)...)
}

// allowAll is a membership check that admits everyone to everything.
func allowAll(context.Context, string, string, string) (bool, bool, error) { return true, true, nil }

// TestP3Cover_APIKeyRowGoneBetweenReadAndWrite: an organization key deleted
// while its revoke or update was being authorized (the membership check is
// the app's code, run between the plugin's read and its write) is
// ErrNotFound, not a silent success.
func TestP3Cover_APIKeyRowGoneBetweenReadAndWrite(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var a *auth.Auth
		var vanish string // the action whose check deletes the key
		ak := p3CoverOrgKeys(func(ctx context.Context, _, _, action string) (bool, bool, error) {
			if action == vanish {
				org := "org_1"
				if _, err := a.Exec(ctx, sqlb.NewDelete(a.Dialect()).From(apikey.TableKey).Where(sqlb.Eq(apikey.KeyOrganization, &org))); err != nil {
					return false, false, err
				}
			}
			return true, true, nil
		})
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a = e.newAuth(t, nil, em, pw, ak)
		ctx := request(a, signUpVerified(t, e, a, pw, em).Token)

		vanish = apikey.ActionDelete
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "org", OrganizationID: "org_1", Name: "k"}))
		if err := ak.Revoke(ctx, k.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("revoke of a key deleted mid-call: %v", err)
		}

		vanish = apikey.ActionUpdate
		k = must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "org", OrganizationID: "org_1", Name: "k"}))
		name := "renamed"
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: k.Key.ID, Name: &name}); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("update of a key deleted mid-call: %v", err)
		}
	})
}

// TestP3Cover_APIKeySetPermissionsRemovedConfiguration: SetPermissions on a
// key whose configuration was removed from the code is ErrUnknownConfig
// rather than checked against the default's vocabulary.
func TestP3Cover_APIKeySetPermissionsRemovedConfiguration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("read"), apikey.WithPermissions(r36Orders),
			apikey.Configuration("live", apikey.Prefix("sk_live_")))
		k := must[apikey.CreateResult](t)(ak.Create(request(a, up.Token), apikey.CreateRequest{Config: "live", Name: "k"}))
		ak2 := apikey.New(apikey.Scopes("read"), apikey.WithPermissions(r36Orders))
		e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ak2)
		if err := ak2.SetPermissions(context.Background(), k.Key.ID, apikey.Permissions{"orders": {"read"}}); !errors.Is(err, apikey.ErrUnknownConfig) {
			t.Fatalf("SetPermissions under a removed configuration: %v", err)
		}
	})
}

// TestP3Cover_APIKeyOrganizationCacheFailure: DeleteOrganizationKeys stops
// at a cache entry it cannot drop and deletes nothing, because a key left in
// the cache would keep working after its organization is gone.
func TestP3Cover_APIKeyOrganizationCacheFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		c := &r6FailingCache{inner: apikey.NewMemoryCacheAt(e.clock.Now)}
		ak := p3CoverOrgKeys(allowAll, apikey.WithCache(c, 0))
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, ak)
		ctx := request(a, signUpVerified(t, e, a, pw, em).Token)
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "org", OrganizationID: "org_1", Name: "k"}))
		c.del = true
		if n, err := ak.DeleteOrganizationKeys(context.Background(), "org_1"); !errors.Is(err, errCacheDown) || n != 0 {
			t.Fatalf("delete with a failing cache = %d, %v", n, err)
		}
		if !r6Exists(t, a, k.Key.ID) {
			t.Fatal("the key went although its cache entry stayed")
		}
	})
}

// TestP3Cover_APIKeyFaults: every database failure on the organization and
// permission paths reaches the caller.
func TestP3Cover_APIKeyFaults(t *testing.T) {
	orgKeyed := func(t *testing.T, e *faultEnv, opts ...apikey.Option) (*auth.Auth, *apikey.Plugin, apikey.CreateResult) {
		ak := p3CoverOrgKeys(allowAll, opts...)
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, ak)
		ctx := request(a, signUpVerified(t, e.env, a, pw, em).Token)
		return a, ak, must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "org", OrganizationID: "org_1", Name: "k"}))
	}
	t.Run("verify organization key", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			_, ak, k := orgKeyed(t, e)
			return func(ctx context.Context) error { _, err := ak.Verify(ctx, k.Secret); return err }
		}, 2) // the use stamp is logged, not returned
	})
	t.Run("delete organization keys with a cache", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			_, ak, _ := orgKeyed(t, e, apikey.WithCache(apikey.NewMemoryCache(), 0))
			return func(ctx context.Context) error { _, err := ak.DeleteOrganizationKeys(ctx, "org_1"); return err }
		})
	})
	t.Run("set permissions", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			ak := apikey.New(apikey.Scopes("read"), apikey.WithPermissions(r36Orders))
			a := e.newAuth(t, nil, em, pw, ak)
			k := must[apikey.CreateResult](t)(ak.Create(request(a, signUpVerified(t, e.env, a, pw, em).Token), apikey.CreateRequest{Name: "k"}))
			return func(ctx context.Context) error {
				return ak.SetPermissions(ctx, k.Key.ID, apikey.Permissions{"orders": {"write"}})
			}
		})
	})
	t.Run("authorize", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			ak := apikey.New(apikey.Scopes("read"), apikey.WithPermissions(r36Orders), apikey.DefaultPermissions(apikey.Permissions{"orders": {"read"}}))
			a := e.newAuth(t, nil, em, pw, ak)
			k := must[apikey.CreateResult](t)(ak.Create(request(a, signUpVerified(t, e.env, a, pw, em).Token), apikey.CreateRequest{Name: "k"}))
			keyCtx := tokensBearer(a, k.Secret)
			if err := a.Resolve(keyCtx); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return ak.Authorize(keyCtx, apikey.Permissions{"orders": {"read"}}) }
		})
	})
}

// TestP3Cover_AuditMyEventsFault: a database failure reading the caller's
// own history reaches the caller.
func TestP3Cover_AuditMyEventsFault(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		w := newAuditWorld(t, e.env)
		return func(context.Context) error {
			_, err := w.au.MyEvents(request(w.a, w.bob.Token), audit.MyQuery{})
			return err
		}
	})
}

// TestP3Cover_SCIMManagedTokenOfAVanishedConnection: a managed credential
// whose connection row is gone is refused (401), never re-created as an
// unmanaged connection the way a verifier's unknown connection is.
func TestP3Cover_SCIMManagedTokenOfAVanishedConnection(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e, scim.ManagedConnections(scim.CredentialHashSecret([]byte(proxySecret))))
		made, err := w.sp.CreateManagedConnection(context.Background(), scim.CreateManagedRequest{CreationRequestID: "req-0000000000002", ProvisioningDomainID: "tenant-1", ActorID: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		r6Raw(t, w.a, sqlb.NewDelete(w.a.Dialect()).From(scim.TableConnection).Where(sqlb.Eq(scim.ConnID, made.Connection.ID)))
		if code, _ := w.do(t, http.MethodGet, "/Users", made.Token.Reveal(), ""); code != http.StatusUnauthorized {
			t.Fatalf("managed token of a deleted connection = %d", code)
		}
		var n int64
		if err := w.a.One(context.Background(), w.a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(scim.TableConnection).Where(sqlb.Eq(scim.ConnID, made.Connection.ID))); err != nil || n != 0 {
			t.Fatalf("the connection was re-created: %d %v", n, err)
		}
	})
}

// TestP3Cover_OrganizationCancelLosesToAConcurrentClose: an invitation
// accepted while its cancel was in the BeforeCancelInvitation hook is not
// canceled after all: the status guard in the write matches no row, the
// cancel is ErrInviteInvalid, and nothing it did is kept (its transaction,
// which here also held the stand-in acceptance, rolls back).
func TestP3Cover_OrganizationCancelLosesToAConcurrentClose(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var w *r30World
		w = r30Setup(t, e, organization.WithHooks(organization.Hooks{
			BeforeCancelInvitation: func(ctx context.Context, inv organization.Invitation, _ auth.User) error {
				_, err := w.a.Exec(ctx, sqlb.NewUpdate(w.a.Dialect()).Table(organization.TableInvite).
					Set(sqlb.Set(organization.InviteStatusCol, organization.StatusAccepted)).Where(sqlb.Eq(organization.InviteID, inv.ID)))
				return err
			},
		}))
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		list := must[[]organization.Invitation](t)(w.org.ListInvitations(w.ownerCtx(), w.o.ID))
		var id string
		for _, inv := range list {
			if inv.Email == "dave@example.com" {
				id = inv.ID
			}
		}
		if err := w.org.Cancel(w.ownerCtx(), id); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("cancel of an invitation accepted meanwhile: %v", err)
		}
		for _, inv := range must[[]organization.Invitation](t)(w.org.ListInvitations(w.ownerCtx(), w.o.ID)) {
			if inv.ID == id && inv.Status == organization.StatusCanceled {
				t.Fatal("the losing cancel was written")
			}
		}
	})
}

// TestP3Cover_OrganizationAPIKeyPermissionFault: a database failure loading
// a member's dynamic role reaches the API-key permission check as an error,
// with the member still reported as a member.
func TestP3Cover_OrganizationAPIKeyPermissionFault(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		w := orgSetup(t, e.env, organization.DynamicRoles(organization.DynamicRolesConfig{}))
		must[organization.OrgRole](t)(w.org.CreateRole(request(w.a, w.owner.Token), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "ops", Permission: access.Permissions{}}))
		u, _ := secondUser(t, w.a, "ops@example.com")
		if err := w.org.AddMember(context.Background(), w.o.ID, u.ID, "ops"); err != nil {
			t.Fatal(err)
		}
		return func(ctx context.Context) error {
			_, _, err := w.org.APIKeyPermission(ctx, w.o.ID, u.ID, apikey.ActionRead)
			return err
		}
	})
}

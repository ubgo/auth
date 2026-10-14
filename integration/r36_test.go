package integration

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessapikey"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/sqlb"
)

// r36Orders is the vocabulary key permissions are checked against in these
// tests: an app's own resources, apart from the organization's.
var r36Orders = apikey.Vocabulary{"orders": {"read", "write"}}

// r36OrgAccess is an organization access control with the API-key
// statements merged in: the owner keeps only the organization's defaults
// (so its key rights come from the creator bypass alone), an admin gets
// every API-key action and a member "read", better-auth's docs example.
func r36OrgAccess() []organization.Option {
	st := access.Statements{}
	maps.Copy(st, organization.DefaultStatements)
	maps.Copy(st, apikey.Statements())
	ac := access.MustNew(st)
	return []organization.Option{organization.WithAccessControl(ac), organization.WithRoles(map[organization.Role]access.Role{
		organization.RoleOwner:  ac.MustRole(access.Permissions(organization.DefaultStatements).Clone()),
		organization.RoleAdmin:  ac.MustRole(access.Permissions{apikey.ResourceAPIKey: {apikey.ActionCreate, apikey.ActionRead, apikey.ActionUpdate, apikey.ActionDelete}}),
		organization.RoleMember: ac.MustRole(access.Permissions{apikey.ResourceAPIKey: {apikey.ActionRead}}),
	})}
}

// *organization.Plugin is apikey's Organizations as it is, so an app passes
// it to WithOrganizations without an adapter. Its apiKey resource is an
// unexported constant there; the role grants below are written with
// apikey.ResourceAPIKey, so TestR36_OrganizationKeys fails if the two
// spellings ever differ (an admin would lose every action).
var _ apikey.Organizations = (*organization.Plugin)(nil)

// r36World is an app with organizations and organization-owned keys: alice
// owns Acme, bob is its admin, carol a member, dave an outsider.
type r36World struct {
	a                      *auth.Auth
	ak                     *apikey.Plugin
	orgs                   *organization.Plugin
	org                    organization.Org
	alice, bob, carol, dav context.Context
	aliceID                string
}

func r36Setup(t *testing.T, e *env, opts ...apikey.Option) *r36World {
	t.Helper()
	em, pw := e.emailPlugin(), e.passwordPlugin()
	org := organization.New(r36OrgAccess()...)
	ak := apikey.New(append([]apikey.Option{apikey.Scopes("read"), apikey.WithOrganizations(org),
		apikey.Configuration("org", apikey.Prefix("ubo_"), apikey.OrganizationOwned(), apikey.MaxKeys(2))}, opts...)...)
	a := e.newAuth(t, nil, em, pw, org, ak)
	up := signUpVerified(t, e, a, pw, em)
	w := &r36World{a: a, ak: ak, orgs: org, alice: request(a, up.Token), aliceID: up.User.ID}
	w.org = must[organization.Org](t)(org.Create(w.alice, organization.CreateRequest{Name: "Acme", Slug: "acme"}))
	for _, m := range []struct {
		addr string
		role organization.Role
		ctx  *context.Context
	}{{"bob@example.com", organization.RoleAdmin, &w.bob}, {"carol@example.com", organization.RoleMember, &w.carol}, {"dave@example.com", "", &w.dav}} {
		u, tok := secondUser(t, a, m.addr)
		if m.role != "" {
			if err := org.AddMember(context.Background(), w.org.ID, u.ID, m.role); err != nil {
				t.Fatal(err)
			}
		}
		*m.ctx = request(a, tok)
	}
	return w
}

// TestR36_OrganizationKeys: a key owned by an organization is created,
// listed, read, changed and revoked by its members as their roles allow;
// the creator passes every check; an outsider gets 403 where they named the
// organization and 404 where they named only a key id.
func TestR36_OrganizationKeys(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r36Setup(t, e)
		orgID := w.org.ID
		mk := func(ctx context.Context, in apikey.CreateRequest) (apikey.CreateResult, error) {
			in.Config = "org"
			return w.ak.Create(ctx, in)
		}

		// Create: the creator (no apiKey grant of its own) passes; a member
		// with read only, an outsider, a missing organization and a user
		// configuration naming one are refused.
		made := must[apikey.CreateResult](t)(mk(w.alice, apikey.CreateRequest{Name: "ci", OrganizationID: orgID, Scopes: []string{"read"}}))
		if made.Key.OrganizationID != orgID || made.Secret[:4] != "ubo_" {
			t.Fatalf("made = %+v", made.Key)
		}
		for name, c := range map[string]struct {
			ctx  context.Context
			in   apikey.CreateRequest
			want error
		}{
			"member":      {w.carol, apikey.CreateRequest{Config: "org", OrganizationID: orgID}, apikey.ErrOrganizationPermission},
			"outsider":    {w.dav, apikey.CreateRequest{Config: "org", OrganizationID: orgID}, apikey.ErrNotOrganizationMember},
			"no org":      {w.bob, apikey.CreateRequest{Config: "org"}, apikey.ErrOrganizationIDRequired},
			"user config": {w.bob, apikey.CreateRequest{OrganizationID: orgID}, apikey.ErrNotOrganizationConfig},
			"unknown org": {w.bob, apikey.CreateRequest{Config: "org", OrganizationID: "org_nope"}, apikey.ErrNotOrganizationMember},
		} {
			if _, err := w.ak.Create(c.ctx, c.in); !errors.Is(err, c.want) {
				t.Errorf("create %s: %v, want %v", name, err, c.want)
			}
		}
		byBob := must[apikey.CreateResult](t)(mk(w.bob, apikey.CreateRequest{Name: "deploy", OrganizationID: orgID}))
		// MaxKeys counts the organization's keys, not the member's.
		if _, err := mk(w.bob, apikey.CreateRequest{OrganizationID: orgID}); !errors.Is(err, apikey.ErrTooMany) {
			t.Fatalf("third organization key: %v", err)
		}
		// A user's own key is unaffected by the organization's.
		mine := must[apikey.CreateResult](t)(w.ak.Create(w.alice, apikey.CreateRequest{Name: "mine"}))
		// ...and so is another organization's: bob's own organization has
		// room although Acme is full.
		beta := must[organization.Org](t)(w.orgs.Create(w.bob, organization.CreateRequest{Name: "Beta", Slug: "beta"}))
		must[apikey.CreateResult](t)(mk(w.bob, apikey.CreateRequest{Name: "beta", OrganizationID: beta.ID}))

		// List: by organization for any member; the caller's own list never
		// shows organization keys.
		l := must[apikey.ListResult](t)(w.ak.ListKeys(w.carol, apikey.ListRequest{OrganizationID: orgID}))
		if l.Total != 2 || l.Keys[1].OrganizationID != orgID || l.Keys[0].OrganizationID != orgID {
			t.Fatalf("carol's organization list = %+v", l)
		}
		own := must[apikey.ListResult](t)(w.ak.ListKeys(w.alice, apikey.ListRequest{}))
		if own.Total != 1 || own.Keys[0].ID != mine.Key.ID {
			t.Fatalf("alice's own list = %+v", own)
		}
		if _, err := w.ak.ListKeys(w.dav, apikey.ListRequest{OrganizationID: orgID}); !errors.Is(err, apikey.ErrNotOrganizationMember) {
			t.Fatalf("outsider list: %v", err)
		}

		// Get, update, revoke by id.
		if k := must[apikey.Key](t)(w.ak.Get(w.carol, made.Key.ID)); k.ID != made.Key.ID {
			t.Fatal(k)
		}
		if _, err := w.ak.Get(w.dav, made.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("outsider get: %v", err)
		}
		name := "renamed"
		if _, err := w.ak.Update(w.carol, apikey.UpdateRequest{ID: made.Key.ID, Name: &name}); !errors.Is(err, apikey.ErrOrganizationPermission) {
			t.Fatalf("member update: %v", err)
		}
		if k := must[apikey.Key](t)(w.ak.Update(w.bob, apikey.UpdateRequest{ID: made.Key.ID, Name: &name})); k.Name != name || k.OrganizationID != orgID {
			t.Fatalf("admin update = %+v", k)
		}
		if err := w.ak.Revoke(w.carol, byBob.Key.ID); !errors.Is(err, apikey.ErrOrganizationPermission) {
			t.Fatalf("member revoke: %v", err)
		}
		if err := w.ak.Revoke(w.dav, byBob.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("outsider revoke: %v", err)
		}
		if err := w.ak.Revoke(w.bob, byBob.Key.ID); err != nil {
			t.Fatal(err)
		}
		// Another user's own key stays out of reach of the organization path.
		if _, err := w.ak.Get(w.bob, mine.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("bob read alice's own key: %v", err)
		}

		// The key never signs anyone in; Verify reports its organization.
		bearer := tokensBearer(w.a, made.Secret)
		if err := w.a.Resolve(bearer); err != nil {
			t.Fatal(err)
		}
		if u, ok := auth.CurrentUser(bearer); ok {
			t.Fatalf("an organization key signed in %s", u.ID)
		}
		v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), made.Secret, "read"))
		if !v.Valid || v.OrganizationID != orgID || v.UserID != "" || v.Key.OrganizationID != orgID {
			t.Fatalf("verify = %+v", v)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), made.Secret, "write")); v.Valid || !errors.Is(v.Reason, apikey.ErrScopeMissing) {
			t.Fatalf("verify missing scope = %+v", v)
		}
		if v := must[apikey.Verification](t)(w.ak.VerifyFor(context.Background(), apikey.DefaultConfig, made.Secret)); v.Valid {
			t.Fatal("VerifyFor accepted a key of another configuration")
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), "ubo_unknown-key-of-enough-length-000000")); v.Valid || !errors.Is(v.Reason, auth.ErrSignedOut) {
			t.Fatalf("unknown organization key = %+v", v)
		}

		// A bearer attempt with an organization key is refused before its
		// quota moves: CreateFor gives one use, and Verify still has it.
		one := 1
		quota := must[apikey.CreateResult](t)(w.ak.CreateFor(context.Background(), w.aliceID, apikey.CreateRequest{Config: "org", OrganizationID: orgID}, apikey.Limits{Remaining: &one}))
		if _, err := w.ak.CreateFor(context.Background(), w.aliceID, apikey.CreateRequest{Config: "org"}, apikey.Limits{}); !errors.Is(err, apikey.ErrOrganizationIDRequired) {
			t.Fatalf("CreateFor without an organization: %v", err)
		}
		if err := w.a.Resolve(tokensBearer(w.a, quota.Secret)); err != nil {
			t.Fatal(err)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), quota.Secret)); !v.Valid {
			t.Fatalf("the bearer attempt spent the quota: %+v", v)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), quota.Secret)); !errors.Is(v.Reason, apikey.ErrUsageExceeded) {
			t.Fatalf("second use = %+v", v)
		}

		// A row under the organization prefix that is not an organization's
		// does not verify on the organization path.
		r6Raw(t, w.a, sqlb.NewUpdate(w.a.Dialect()).Table(apikey.TableKey).Set(sqlb.Set(apikey.KeyOrganization, (*string)(nil))).Where(sqlb.Eq(apikey.KeyID, quota.Key.ID)))
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), quota.Secret)); v.Valid || !errors.Is(v.Reason, auth.ErrSignedOut) {
			t.Fatalf("user row on the organization path = %+v", v)
		}
		r6DeleteRow(t, w.a, quota.Key.ID)

		// Deleting the creator's account leaves the organization's key; the
		// organization's deletion is what removes it.
		if err := w.a.DeleteUser(context.Background(), w.aliceID); err != nil {
			t.Fatal(err)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), made.Secret)); !v.Valid {
			t.Fatalf("organization key died with its creator: %+v", v)
		}
		if n := must[int64](t)(w.ak.DeleteOrganizationKeys(context.Background(), orgID)); n != 1 {
			t.Fatalf("deleted %d keys", n)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), made.Secret)); v.Valid {
			t.Fatal("a key of a deleted organization still verifies")
		}
	})
}

// TestR36_OrganizationKeyDistinct: under DistinctErrors an organization key
// presented as a bearer credential says why it was refused, and with a cache
// DeleteOrganizationKeys drops the cached entry too.
func TestR36_OrganizationKeyDistinct(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r36Setup(t, e, apikey.DistinctErrors(), apikey.WithCache(apikey.NewMemoryCache(), 0))
		made := must[apikey.CreateResult](t)(w.ak.Create(w.alice, apikey.CreateRequest{Config: "org", OrganizationID: w.org.ID}))
		if err := w.a.Resolve(tokensBearer(w.a, made.Secret)); !errors.Is(err, apikey.ErrOrganizationKey) {
			t.Fatalf("bearer organization key: %v", err)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), made.Secret)); !v.Valid {
			t.Fatalf("verify (now cached) = %+v", v)
		}
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), "ubo_unknown-key-of-enough-length-000000")); !errors.Is(v.Reason, apikey.ErrInvalidKey) {
			t.Fatalf("unknown organization key = %+v", v)
		}
		must[int64](t)(w.ak.DeleteOrganizationKeys(context.Background(), w.org.ID))
		if v := must[apikey.Verification](t)(w.ak.Verify(context.Background(), made.Secret)); v.Valid {
			t.Fatal("the cache kept a deleted organization's key alive")
		}
	})
}

// TestR36_KeyPermissions: permissions on a key, set from Go, checked with
// VerifyPermissions and Authorize, replaced with SetPermissions.
func TestR36_KeyPermissions(t *testing.T) {
	r36KeyPermissions(t, r36Orders)
}

// TestR36_KeyPermissionsWithAccess runs the same flow with the permission
// model behind apikey.PermissionChecker swapped for plugin/access's
// adapter over the same statements: every answer, error code included, is
// the built-in one's.
func TestR36_KeyPermissionsWithAccess(t *testing.T) {
	r36KeyPermissions(t, accessapikey.New(access.MustNew(access.Statements(r36Orders))))
}

func r36KeyPermissions(t *testing.T, checker apikey.PermissionChecker) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("read"), apikey.WithPermissions(checker),
			apikey.DefaultPermissions(apikey.Permissions{"orders": {"read"}}),
			apikey.Configuration("bare", apikey.Prefix("ubb_"), apikey.WithPermissions(nil), apikey.DefaultPermissions(nil)))
		ctx := request(a, up.Token)
		def := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "d"}))
		if len(def.Key.Permissions["orders"]) != 1 {
			t.Fatalf("default permissions = %v", def.Key.Permissions)
		}
		rw := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "rw", Permissions: apikey.Permissions{"orders": {"write", "read"}}}))
		if _, err := ak.Create(ctx, apikey.CreateRequest{Permissions: apikey.Permissions{"orders": {"delete"}}}); !errors.Is(err, apikey.ErrBadPermissions) {
			t.Fatalf("undeclared permission: %v", err)
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Config: "bare", Permissions: apikey.Permissions{"orders": {"read"}}}); !errors.Is(err, apikey.ErrPermissionsOff) {
			t.Fatalf("permissions without a vocabulary: %v", err)
		}
		bare := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Config: "bare"}))
		if bare.Key.Permissions != nil {
			t.Fatalf("bare key permissions = %v", bare.Key.Permissions)
		}
		// Read back as stored.
		if k := must[apikey.Key](t)(ak.Get(ctx, rw.Key.ID)); len(k.Permissions["orders"]) != 2 {
			t.Fatalf("stored = %v", k.Permissions)
		}

		write := apikey.Permissions{"orders": {"write"}}
		if v := must[apikey.Verification](t)(ak.VerifyPermissions(context.Background(), rw.Secret, write)); !v.Valid {
			t.Fatalf("rw write = %+v", v)
		}
		for name, secret := range map[string]string{"read-only": def.Secret, "none": bare.Secret} {
			if v := must[apikey.Verification](t)(ak.VerifyPermissions(context.Background(), secret, write)); v.Valid || !errors.Is(v.Reason, apikey.ErrPermissionDenied) {
				t.Errorf("%s write = %+v", name, v)
			}
		}
		if v := must[apikey.Verification](t)(ak.VerifyPermissions(context.Background(), "ubk_nope-nope-nope-nope-nope-nope", write)); v.Valid {
			t.Fatal("unknown key verified")
		}

		// Authorize on an app route: the request's key decides.
		keyCtx := tokensBearer(a, def.Secret)
		if err := a.Resolve(keyCtx); err != nil {
			t.Fatal(err)
		}
		if err := ak.Authorize(keyCtx, apikey.Permissions{"orders": {"read"}}); err != nil {
			t.Fatal(err)
		}
		if err := ak.Authorize(keyCtx, write); !errors.Is(err, apikey.ErrPermissionDenied) {
			t.Fatalf("authorize write: %v", err)
		}
		if err := a.Resolve(ctx); err != nil {
			t.Fatal(err)
		}
		if err := ak.Authorize(ctx, apikey.Permissions{"orders": {"read"}}); !errors.Is(err, apikey.ErrPermissionDenied) {
			t.Fatalf("a browser session passed a key permission: %v", err)
		}

		// SetPermissions widens, then clears.
		if err := ak.SetPermissions(context.Background(), def.Key.ID, write); err != nil {
			t.Fatal(err)
		}
		if err := ak.Authorize(keyCtx, write); err != nil {
			t.Fatalf("after SetPermissions: %v", err)
		}
		if err := ak.SetPermissions(context.Background(), def.Key.ID, nil); err != nil {
			t.Fatal(err)
		}
		if err := ak.Authorize(keyCtx, write); !errors.Is(err, apikey.ErrPermissionDenied) {
			t.Fatalf("after clearing: %v", err)
		}
		if err := ak.SetPermissions(context.Background(), "key_nope", write); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatal(err)
		}
		if err := ak.SetPermissions(context.Background(), bare.Key.ID, write); !errors.Is(err, apikey.ErrPermissionsOff) {
			t.Fatal(err)
		}
		// A key whose configuration left the code cannot be given permissions,
		// and a row marked as an organization's on an app without
		// organizations is nobody's to read.
		r6Raw(t, a, sqlb.NewUpdate(a.Dialect()).Table(apikey.TableKey).Set(sqlb.Set(apikey.KeyConfig, "gone")).Where(sqlb.Eq(apikey.KeyID, bare.Key.ID)))
		if err := ak.SetPermissions(context.Background(), bare.Key.ID, write); !errors.Is(err, apikey.ErrUnknownConfig) {
			t.Fatalf("configuration gone: %v", err)
		}
		org := "org_x"
		r6Raw(t, a, sqlb.NewUpdate(a.Dialect()).Table(apikey.TableKey).Set(sqlb.Set(apikey.KeyOrganization, &org)).Where(sqlb.Eq(apikey.KeyID, rw.Key.ID)))
		if _, err := ak.Get(ctx, rw.Key.ID); !errors.Is(err, apikey.ErrNotFound) {
			t.Fatalf("organization row without organizations: %v", err)
		}

		// A key revoked after the request resolved grants nothing.
		r6DeleteRow(t, a, def.Key.ID)
		if err := ak.Authorize(keyCtx, apikey.Permissions{"orders": {"read"}}); !errors.Is(err, apikey.ErrPermissionDenied) {
			t.Fatalf("deleted key: %v", err)
		}
	})
}

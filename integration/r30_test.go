package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessadmin"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
)

// The organization round (r30): fields, get/update/delete, the active
// organization, invitation states, permissions and custom roles, teams,
// dynamic roles and the lifecycle hooks.

// r30World is orgSetup plus bob (admin) and carol (member), both verified.
type r30World struct {
	*orgWorld
	bob, carol password.SignInResult
	env        *env
}

func r30Setup(t *testing.T, e *env, opts ...organization.Option) *r30World {
	t.Helper()
	w := &r30World{orgWorld: orgSetup(t, e, opts...), env: e}
	w.bob = w.orgUser(t, e, "bob@example.com")
	w.carol = w.orgUser(t, e, "carol@example.com")
	// The clock is frozen; a second between joins gives the joined-at order
	// the members list sorts by.
	e.clock.Advance(time.Second)
	w.orgJoin(t, w.bob, "bob@example.com", organization.RoleAdmin)
	e.clock.Advance(time.Second)
	w.orgJoin(t, w.carol, "carol@example.com", organization.RoleMember)
	return w
}

func (w *r30World) as(u password.SignInResult) context.Context { return request(w.a, u.Token) }
func (w *r30World) ownerCtx() context.Context                  { return request(w.a, w.owner.Token) }

func TestR30_FieldsGetUpdateDelete(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		logo := "https://cdn.example.com/acme.png"
		o, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "Beta", Slug: "beta", Logo: &logo, Metadata: auth.AppData(`{"plan":"pro"}`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "X", Slug: "x-1", Metadata: auth.AppData(`[1]`)}); !errors.Is(err, organization.ErrBadMetadata) {
			t.Fatalf("array metadata: %v", err)
		}
		big := auth.AppData(`{"k":"` + strings.Repeat("a", organization.MaxMetadataSize) + `"}`)
		if _, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "X", Slug: "x-2", Metadata: big}); !errors.Is(err, organization.ErrBadMetadata) {
			t.Fatalf("oversized metadata: %v", err)
		}

		got := must[organization.Org](t)(w.org.Get(w.ownerCtx(), organization.GetRequest{OrgSlug: "BETA"}))
		if got.ID != o.ID || got.Logo == nil || *got.Logo != logo || string(got.Metadata) != `{"plan":"pro"}` {
			t.Fatalf("get = %+v", got)
		}
		if _, err := w.org.Get(w.as(w.bob), organization.GetRequest{OrgID: o.ID}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger reads: %v", err)
		}
		if _, err := w.org.Get(w.ownerCtx(), organization.GetRequest{OrgID: "org_nope"}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("unknown id: %v", err)
		}

		// Update: the admin may, the member may not.
		name, slug, empty := "Acme Inc", "acme-inc", ""
		if _, err := w.org.Update(w.as(w.carol), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Name: &name}}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member updates: %v", err)
		}
		up := must[organization.Org](t)(w.org.Update(w.as(w.bob), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Name: &name, Slug: &slug, Logo: &logo, Metadata: auth.AppData(`{"a":1}`)}}))
		if up.Name != name || up.Slug != slug || up.Logo == nil {
			t.Fatalf("update = %+v", up)
		}
		up = must[organization.Org](t)(w.org.Update(w.as(w.bob), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Logo: &empty}}))
		if up.Logo != nil || string(up.Metadata) != `{"a":1}` {
			t.Fatalf("clearing the logo: %+v", up)
		}
		taken := "beta"
		if _, err := w.org.Update(w.as(w.bob), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Slug: &taken}}); !errors.Is(err, organization.ErrSlugTaken) {
			t.Fatalf("taken slug: %v", err)
		}
		bad := "-no"
		if _, err := w.org.Update(w.as(w.bob), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Slug: &bad}}); !errors.Is(err, organization.ErrBadSlug) {
			t.Fatalf("bad slug: %v", err)
		}
		if _, err := w.org.Update(w.as(w.bob), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Metadata: auth.AppData(`"s"`)}}); !errors.Is(err, organization.ErrBadMetadata) {
			t.Fatalf("bad metadata: %v", err)
		}
		list := must[[]organization.OrgWithRole](t)(w.org.List(w.ownerCtx()))
		if len(list) != 2 || list[0].Name != name || list[1].Logo == nil {
			t.Fatalf("list = %+v", list)
		}

		// Full read: members, pending invitations.
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dan@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		full := must[organization.FullOrg](t)(w.org.GetFull(w.as(w.carol), organization.GetRequest{OrgID: w.o.ID, MembersLimit: 2}))
		if len(full.Members) != 2 || len(full.Invitations) != 1 || full.Invitations[0].Status != organization.StatusPending || full.Teams != nil {
			t.Fatalf("full = %d members, %+v", len(full.Members), full.Invitations)
		}

		// Delete: only the owner, and every row of the organization goes.
		if err := w.org.Delete(w.as(w.bob), w.o.ID); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("admin deletes: %v", err)
		}
		if err := w.org.Delete(w.ownerCtx(), w.o.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := w.org.RoleOf(context.Background(), w.o.ID, w.bob.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("members survived: %v", err)
		}
		for table, want := range map[string]int{organization.TableNameOrg: 1, organization.TableNameMember: 1, organization.TableNameInvite: 0} {
			if got := count(t, e, table); got != want {
				t.Fatalf("%s rows = %d, want %d", table, got, want)
			}
		}
	})
}

func TestR30_ActiveOrganization(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		// Create made Acme active for the owner's session.
		act := must[organization.ActiveResult](t)(w.org.Active(w.ownerCtx()))
		if act.OrgID == nil || *act.OrgID != w.o.ID || act.Org == nil || act.Org.Slug != "acme" {
			t.Fatalf("active after create = %+v", act)
		}
		// An empty orgId now means the active organization.
		if got := must[[]organization.MemberView](t)(w.org.Members(w.ownerCtx(), "")); len(got) != 3 {
			t.Fatalf("members of the active org = %d", len(got))
		}
		// KeepActive leaves Acme active.
		beta := must[organization.Org](t)(w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "Beta", Slug: "beta", KeepActive: true}))
		if id, ok, err := w.org.ActiveOrgID(w.ownerCtx()); err != nil || !ok || id != w.o.ID {
			t.Fatalf("ActiveOrgID = %q %v %v", id, ok, err)
		}
		// Switch by slug; a stranger cannot select it.
		if r := must[organization.ActiveResult](t)(w.org.SetActive(w.ownerCtx(), organization.SetActiveRequest{OrgSlug: "beta"})); r.Org == nil || r.Org.ID != beta.ID {
			t.Fatalf("set by slug = %+v", r)
		}
		if _, err := w.org.SetActive(w.as(w.bob), organization.SetActiveRequest{OrgID: beta.ID}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger selects: %v", err)
		}
		if _, err := w.org.SetActive(w.as(w.bob), organization.SetActiveRequest{OrgSlug: "nope"}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("unknown slug: %v", err)
		}
		// Bob has none: an empty orgId is no_active.
		if _, err := w.org.Members(w.as(w.bob), ""); !errors.Is(err, organization.ErrNoActiveOrg) {
			t.Fatalf("no active: %v", err)
		}
		if id, ok, err := w.org.ActiveOrgID(w.as(w.bob)); err != nil || ok || id != "" {
			t.Fatalf("bob's ActiveOrgID = %q %v %v", id, ok, err)
		}
		if id, ok, _ := w.org.ActiveOrgID(context.Background()); ok || id != "" {
			t.Fatal("a context with no request has an active org")
		}
		must[organization.ActiveResult](t)(w.org.SetActive(w.as(w.bob), organization.SetActiveRequest{OrgID: w.o.ID}))
		// Clearing.
		must[organization.ActiveResult](t)(w.org.SetActive(w.ownerCtx(), organization.SetActiveRequest{}))
		if r := must[organization.ActiveResult](t)(w.org.Active(w.ownerCtx())); r.OrgID != nil || r.Org != nil {
			t.Fatalf("after clearing = %+v", r)
		}
		// Removing bob drops his selection; signing carol out drops hers.
		must[organization.ActiveResult](t)(w.org.SetActive(w.as(w.carol), organization.SetActiveRequest{OrgID: w.o.ID}))
		if got := count(t, e, organization.TableNameActive); got != 2 {
			t.Fatalf("active rows = %d, want 2", got)
		}
		if err := w.org.RemoveMember(w.ownerCtx(), organization.MemberRequest{OrgID: w.o.ID, UserID: w.bob.User.ID}); err != nil {
			t.Fatal(err)
		}
		if err := w.a.SignOut(w.as(w.carol)); err != nil {
			t.Fatal(err)
		}
		if got := count(t, e, organization.TableNameActive); got != 0 {
			t.Fatalf("active rows after removal and sign-out = %d", got)
		}
		// Sweep drops selections of sessions past their hard stop.
		must[organization.ActiveResult](t)(w.org.SetActive(w.ownerCtx(), organization.SetActiveRequest{OrgID: w.o.ID}))
		e.clock.Advance(400 * 24 * time.Hour)
		if _, err := w.org.Sweep(context.Background(), e.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if got := count(t, e, organization.TableNameActive); got != 0 {
			t.Fatalf("active rows after sweep = %d", got)
		}
	})
}

func TestR30_InvitationStates(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.InvitationLimit(3))
		dan := w.orgUser(t, e, "dan@example.com")
		invite := func(ctx context.Context, addr string, role organization.Role) error {
			return w.org.Invite(ctx, organization.InviteRequest{OrgID: w.o.ID, Email: addr, Role: role})
		}
		if err := invite(w.as(w.bob), "dan@example.com", organization.JoinRoles(organization.RoleAdmin, organization.RoleMember)); err != nil {
			t.Fatal(err)
		}
		inv := must[[]organization.Invite](t)(w.org.Invites(w.as(dan)))[0]
		if inv.Role != "admin,member" {
			t.Fatalf("multi-role invitation = %q", inv.Role)
		}
		// Only the addressee can reject.
		if err := w.org.Reject(w.as(w.carol), inv.ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("someone else rejects: %v", err)
		}
		if err := w.org.Reject(w.as(dan), inv.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := w.org.Accept(w.as(dan), inv.ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("accept after reject: %v", err)
		}
		// Cancel: the admin may, the member may not, a stranger learns nothing.
		if err := invite(w.ownerCtx(), "dan@example.com", organization.RoleMember); err != nil {
			t.Fatal(err)
		}
		inv = must[[]organization.Invite](t)(w.org.Invites(w.as(dan)))[0]
		if err := w.org.Cancel(w.as(w.carol), inv.ID); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member cancels: %v", err)
		}
		if err := w.org.Cancel(w.as(dan), inv.ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("stranger cancels: %v", err)
		}
		if err := w.org.Cancel(w.as(dan), "inv_nope"); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("unknown id: %v", err)
		}
		if err := w.org.Cancel(w.as(w.bob), inv.ID); err != nil {
			t.Fatal(err)
		}
		if err := w.org.Cancel(w.as(w.bob), inv.ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("cancel twice: %v", err)
		}
		if got := must[[]organization.Invite](t)(w.org.Invites(w.as(dan))); len(got) != 0 {
			t.Fatalf("canceled invitation still pending: %+v", got)
		}
		// The admin list shows every state.
		all := must[[]organization.Invitation](t)(w.org.ListInvitations(w.as(w.carol), w.o.ID))
		states := map[organization.InviteStatus]int{}
		for _, i := range all {
			states[i.Status]++
		}
		if states[organization.StatusAccepted] != 2 || states[organization.StatusRejected] != 1 || states[organization.StatusCanceled] != 1 {
			t.Fatalf("states = %v", states)
		}
		if _, err := w.org.ListInvitations(w.as(dan), w.o.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger lists: %v", err)
		}
		// InvitationLimit counts pending invitations of the organization.
		for _, addr := range []string{"x1@example.com", "x2@example.com", "x3@example.com"} {
			if err := invite(w.ownerCtx(), addr, organization.RoleMember); err != nil {
				t.Fatal(err)
			}
		}
		if err := invite(w.ownerCtx(), "x4@example.com", organization.RoleMember); !errors.Is(err, organization.ErrInvitationLimit) {
			t.Fatalf("over the limit: %v", err)
		}
	})
}

func TestR30_RejectExistingMembers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.RejectExistingMembers())
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "Bob@Example.com", Role: organization.RoleMember}); !errors.Is(err, organization.ErrAlreadyMember) {
			t.Fatalf("invite a member: %v", err)
		}
		if err := w.org.AddMember(context.Background(), w.o.ID, w.carol.User.ID, organization.RoleMember); !errors.Is(err, organization.ErrAlreadyMember) {
			t.Fatalf("add a member: %v", err)
		}
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "new@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatalf("invite a stranger: %v", err)
		}
	})
}

// r30Statements are the default statements plus an app resource.
var r30Statements = func() access.Statements {
	s := access.Statements{"project": {"create", "share"}}
	for k, v := range organization.DefaultStatements {
		s[k] = v
	}
	return s
}()

func TestR30_PermissionsAndCustomRoles(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ac := access.MustNew(r30Statements)
		billing := ac.MustRole(access.Permissions{"project": {"create"}, organization.ResourceInvitation: {organization.ActionCreate}})
		owner := ac.MustRole(access.Permissions(r30Statements))
		w := r30Setup(t, e, organization.WithAccessControl(ac), organization.WithRoles(map[organization.Role]access.Role{"billing": billing, organization.RoleOwner: owner}))
		ask := func(u password.SignInResult, perms access.Permissions, conn access.Connector) bool {
			t.Helper()
			ok, err := w.org.HasPermission(w.as(u), organization.PermissionRequest{OrgID: w.o.ID, Permissions: perms, Connector: conn})
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		if !ask(w.owner, access.Permissions{"project": {"share"}}, "") || ask(w.bob, access.Permissions{"project": {"create"}}, "") {
			t.Fatal("owner/admin project permissions are wrong")
		}
		if !ask(w.bob, access.Permissions{organization.ResourceMember: {organization.ActionDelete}}, "") || ask(w.carol, access.Permissions{organization.ResourceMember: {organization.ActionDelete}}, "") {
			t.Fatal("admin/member member:delete is wrong")
		}
		// The admin may now change roles, but not grant or touch the owner.
		if err := w.org.SetRole(w.as(w.bob), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: organization.JoinRoles(organization.RoleMember, "billing")}); err != nil {
			t.Fatalf("admin sets a custom role: %v", err)
		}
		if !ask(w.carol, access.Permissions{"project": {"create"}}, "") {
			t.Fatal("billing role grants nothing")
		}
		if !ask(w.carol, access.Permissions{"project": {"share", "create"}, organization.ResourceAC: {organization.ActionRead}}, access.Or) {
			t.Fatal("OR across resources failed")
		}
		if ask(w.carol, access.Permissions{"project": {"share", "create"}}, "") {
			t.Fatal("AND passed with one action missing")
		}
		if err := w.org.SetRole(w.as(w.bob), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: organization.RoleOwner}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("admin grants owner: %v", err)
		}
		if err := w.org.SetRole(w.as(w.bob), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.owner.User.ID, Role: organization.RoleMember}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("admin demotes the owner: %v", err)
		}
		if err := w.org.SetRole(w.as(w.carol), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.bob.User.ID, Role: organization.RoleMember}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member sets a role: %v", err)
		}
		if err := w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.owner.User.ID, Role: organization.RoleAdmin}); !errors.Is(err, organization.ErrLastOwner) {
			t.Fatalf("last owner demotes self: %v", err)
		}
		// A billing member may invite (invitation:create) but not as admin... any
		// non-owner role is allowed for them.
		if err := w.org.Invite(w.as(w.carol), organization.InviteRequest{OrgID: w.o.ID, Email: "z@example.com", Role: organization.RoleAdmin}); err != nil {
			t.Fatalf("billing invites: %v", err)
		}
		// Server-side Can, and a stranger.
		if ok, err := w.org.Can(context.Background(), w.o.ID, w.carol.User.ID, access.Request{"project": access.Any("share", "create")}, ""); err != nil || !ok {
			t.Fatalf("Can = %v %v", ok, err)
		}
		dan := w.orgUser(t, e, "dan@example.com")
		if _, err := w.org.HasPermission(w.as(dan), organization.PermissionRequest{OrgID: w.o.ID, Permissions: access.Permissions{"project": {"create"}}}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger asks: %v", err)
		}

		// RequirePermission guards an app route.
		mux := http.NewServeMux()
		mux.Handle("POST /orgs/{org}/projects", authhttp.Middleware(w.a)(w.org.RequirePermission(func(r *http.Request) string { return r.PathValue("org") },
			access.Request{"project": access.All("create")})(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusCreated) }))))
		for _, c := range []struct {
			who  auth.Token
			want int
		}{{w.carol.Token, http.StatusCreated}, {w.bob.Token, http.StatusForbidden}, {dan.Token, http.StatusNotFound}, {"", http.StatusUnauthorized}} {
			if got := r30Serve(mux, c.who, http.MethodPost, "/orgs/"+w.o.ID+"/projects", nil).Code; got != c.want {
				t.Errorf("token %.6q: status %d, want %d", c.who, got, c.want)
			}
		}
	})
}

// r30Serve runs one request through h as a browser on the app's page.
func r30Serve(h http.Handler, tok auth.Token, method, path string, body any) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Origin", testBaseURL)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-auth_session", Value: string(tok)})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestR30_HTTPRoutes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		h := authhttp.Handler(w.a, authhttp.Prefix("/auth"))
		// Roles as a JSON array, as a client may send them.
		res := r30Serve(h, w.owner.Token, http.MethodPost, "/auth/organization/set-role", map[string]any{"orgId": w.o.ID, "userId": w.carol.User.ID, "role": []string{"admin", "member"}})
		if res.Code != http.StatusOK {
			t.Fatalf("set-role with an array = %d %s", res.Code, res.Body)
		}
		if r, _ := w.orgRole(t, w.carol.User.ID); r != "admin,member" {
			t.Fatalf("stored role = %q", r)
		}
		res = r30Serve(h, w.owner.Token, http.MethodPost, "/auth/organization/set-role", map[string]any{"orgId": w.o.ID, "userId": w.carol.User.ID, "role": 7})
		if res.Code != http.StatusBadRequest {
			t.Fatalf("a number as role = %d %s", res.Code, res.Body)
		}
		res = r30Serve(h, w.carol.Token, http.MethodPost, "/auth/organization/has-permission", map[string]any{"orgId": w.o.ID, "permissions": map[string][]string{"member": {"delete"}}})
		var ans organization.PermissionResult
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &ans) != nil || !ans.Success {
			t.Fatalf("has-permission = %d %s", res.Code, res.Body)
		}
		res = r30Serve(h, w.carol.Token, http.MethodPost, "/auth/organization/set-active", map[string]any{"orgSlug": "acme"})
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"activeOrganizationId":"`+w.o.ID+`"`) {
			t.Fatalf("set-active = %d %s", res.Code, res.Body)
		}
		res = r30Serve(h, w.carol.Token, http.MethodGet, "/auth/organization/get-full-organization", nil)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"members":[`) {
			t.Fatalf("get-full of the active org = %d %s", res.Code, res.Body)
		}
		res = r30Serve(h, w.carol.Token, http.MethodGet, "/auth/organization/members?sortBy=name&sortDirection=sideways", nil)
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "organization.bad_query") {
			t.Fatalf("bad direction = %d %s", res.Code, res.Body)
		}
		// Team and role routes are not mounted without their options.
		if res = r30Serve(h, w.owner.Token, http.MethodPost, "/auth/organization/create-team", map[string]any{"name": "x"}); res.Code != http.StatusNotFound {
			t.Fatalf("create-team without Teams = %d", res.Code)
		}
	})
}

func TestR30_MembersSortAndFilter(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		ids := func(r organization.MembersResult) []string {
			var out []string
			for _, m := range r.Members {
				out = append(out, m.User.ID)
			}
			return out
		}
		list := func(in organization.OrgRequest) organization.MembersResult {
			t.Helper()
			in.OrgID = w.o.ID
			return must[organization.MembersResult](t)(w.org.ListMembers(w.ownerCtx(), in))
		}
		joined := ids(list(organization.OrgRequest{}))
		if len(joined) != 3 || joined[0] != w.owner.User.ID {
			t.Fatalf("default order = %v", joined)
		}
		desc := ids(list(organization.OrgRequest{SortBy: organization.SortCreatedAt, SortDirection: organization.Desc}))
		if desc[0] != joined[2] || desc[2] != joined[0] {
			t.Fatalf("desc = %v, asc = %v", desc, joined)
		}
		byID := ids(list(organization.OrgRequest{SortBy: organization.SortUserID}))
		if !(byID[0] < byID[1] && byID[1] < byID[2]) {
			t.Fatalf("by user id = %v", byID)
		}
		if got := list(organization.OrgRequest{SortBy: organization.SortName}); len(got.Members) != 3 {
			t.Fatal("by name")
		}
		if got := list(organization.OrgRequest{SortBy: organization.SortRole, SortDirection: organization.Desc}); got.Members[0].Role != organization.RoleOwner {
			t.Fatalf("by role desc = %v", got.Members[0].Role)
		}
		admins := list(organization.OrgRequest{FilterField: organization.FieldRole, FilterValue: "admin"})
		if admins.Total != 1 || admins.Members[0].User.ID != w.bob.User.ID {
			t.Fatalf("role eq admin = %+v", admins)
		}
		if got := list(organization.OrgRequest{FilterField: organization.FieldRole, FilterOperator: organization.OpNe, FilterValue: "admin"}); got.Total != 2 {
			t.Fatalf("role ne admin = %d", got.Total)
		}
		if got := list(organization.OrgRequest{FilterField: organization.FieldUserID, FilterOperator: organization.OpIn, FilterValue: w.bob.User.ID + ", " + w.carol.User.ID}); got.Total != 2 {
			t.Fatalf("user id in = %d", got.Total)
		}
		if got := list(organization.OrgRequest{FilterField: organization.FieldRole, FilterOperator: organization.OpContains, FilterValue: "dmi"}); got.Total != 1 {
			t.Fatalf("role contains = %d", got.Total)
		}
		if got := list(organization.OrgRequest{FilterField: organization.FieldName, FilterValue: "Alice"}); got.Total != 1 {
			t.Fatalf("name eq = %d", got.Total)
		}
		for _, bad := range []organization.OrgRequest{
			{SortBy: "email"}, {SortDirection: "up"}, {FilterField: "email", FilterValue: "x"},
			{FilterField: organization.FieldName, FilterOperator: organization.OpLte, FilterValue: "A"},
			{FilterField: organization.FieldRole, FilterOperator: "gt", FilterValue: "a"},
			{FilterField: organization.FieldRole, FilterOperator: organization.OpIn, FilterValue: " , "},
		} {
			bad.OrgID = w.o.ID
			if _, err := w.org.ListMembers(w.ownerCtx(), bad); !errors.Is(err, organization.ErrBadQuery) {
				t.Errorf("%+v: %v", bad, err)
			}
		}
	})
}

func TestR30_CreatorRole(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e, organization.CreatorRole(organization.RoleAdmin), organization.MaxOwned(1))
		if r, _ := w.orgRole(t, w.owner.User.ID); r != organization.RoleAdmin {
			t.Fatalf("creator role = %q", r)
		}
		if _, err := w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "B", Slug: "bbb"}); !errors.Is(err, organization.ErrLimitReached) {
			t.Fatalf("MaxOwned counts the creator role: %v", err)
		}
		// The last holder of the creator role cannot leave.
		if err := w.org.RemoveMember(request(w.a, w.owner.Token), organization.MemberRequest{OrgID: w.o.ID, UserID: w.owner.User.ID}); !errors.Is(err, organization.ErrLastOwner) {
			t.Fatalf("last creator-role holder leaves: %v", err)
		}
	})
}

func TestR30_Teams(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.Teams(organization.TeamsConfig{MaxTeams: 3, MaxMembersPerTeam: 2}))
		// The default team holds the creator.
		teams := must[[]organization.Team](t)(w.org.ListTeams(w.ownerCtx(), w.o.ID))
		if len(teams) != 1 || teams[0].Name != "Acme" || teams[0].MemberCount != 1 {
			t.Fatalf("default team = %+v", teams)
		}
		def := teams[0]
		if _, err := w.org.CreateTeam(w.as(w.carol), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Ops"}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member creates a team: %v", err)
		}
		eng := must[organization.Team](t)(w.org.CreateTeam(w.as(w.bob), organization.CreateTeamRequest{OrgID: w.o.ID, Name: " Engineering "}))
		if eng.Name != "Engineering" || eng.MemberCount != 0 {
			t.Fatalf("created = %+v", eng)
		}
		must[organization.Team](t)(w.org.CreateTeam(w.as(w.bob), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Sales"}))
		if _, err := w.org.CreateTeam(w.as(w.bob), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Four"}); !errors.Is(err, organization.ErrTeamsLimit) {
			t.Fatalf("MaxTeams: %v", err)
		}
		renamed := "Eng"
		if got := must[organization.Team](t)(w.org.UpdateTeam(w.as(w.bob), organization.UpdateTeamRequest{TeamID: eng.ID, Data: organization.TeamUpdate{Name: &renamed}})); got.Name != "Eng" {
			t.Fatalf("renamed = %+v", got)
		}
		if _, err := w.org.UpdateTeam(w.as(w.carol), organization.UpdateTeamRequest{TeamID: eng.ID, Data: organization.TeamUpdate{Name: &renamed}}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member renames: %v", err)
		}
		dan := w.orgUser(t, e, "dan@example.com")
		if _, err := w.org.ListTeams(w.as(dan), w.o.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger lists teams: %v", err)
		}
		if _, err := w.org.ListTeamMembers(w.as(dan), eng.ID); !errors.Is(err, organization.ErrTeamNotFound) {
			t.Fatalf("stranger lists a team: %v", err)
		}
		// Membership: org members only, capped.
		add := func(ctx context.Context, team, user string) error {
			return w.org.AddTeamMember(ctx, organization.TeamMemberRequest{TeamID: team, UserID: user})
		}
		if err := add(w.as(w.bob), eng.ID, dan.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("adding a non-member: %v", err)
		}
		if err := add(w.as(w.carol), eng.ID, w.carol.User.ID); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member adds: %v", err)
		}
		for _, u := range []string{w.bob.User.ID, w.carol.User.ID, w.carol.User.ID} {
			if err := add(w.as(w.bob), eng.ID, u); err != nil {
				t.Fatal(err)
			}
		}
		if err := add(w.as(w.bob), eng.ID, w.owner.User.ID); !errors.Is(err, organization.ErrTeamMembersLimit) {
			t.Fatalf("MaxMembersPerTeam: %v", err)
		}
		if got := must[[]organization.TeamMember](t)(w.org.ListTeamMembers(w.as(w.carol), eng.ID)); len(got) != 2 {
			t.Fatalf("team members = %d", len(got))
		}
		if got := must[[]organization.Team](t)(w.org.ListUserTeams(w.as(w.carol))); len(got) != 1 || got[0].ID != eng.ID || got[0].MemberCount != 2 {
			t.Fatalf("carol's teams = %+v", got)
		}
		// Active team: members of it only; it sets the organization too.
		if _, err := w.org.SetActiveTeam(w.as(w.carol), def.ID); !errors.Is(err, organization.ErrTeamNotFound) {
			t.Fatalf("activating a team one is not in: %v", err)
		}
		act := must[organization.ActiveResult](t)(w.org.SetActiveTeam(w.as(w.carol), eng.ID))
		if act.TeamID == nil || *act.TeamID != eng.ID || act.OrgID == nil || *act.OrgID != w.o.ID {
			t.Fatalf("active team = %+v", act)
		}
		// Leaving the team clears it from the session, keeping the org.
		if err := w.org.RemoveTeamMember(w.as(w.carol), organization.TeamMemberRequest{TeamID: eng.ID, UserID: w.carol.User.ID}); err != nil {
			t.Fatal(err)
		}
		if r := must[organization.ActiveResult](t)(w.org.Active(w.as(w.carol))); r.TeamID != nil || r.OrgID == nil {
			t.Fatalf("after leaving = %+v", r)
		}
		if err := w.org.RemoveTeamMember(w.as(w.carol), organization.TeamMemberRequest{TeamID: eng.ID, UserID: w.carol.User.ID}); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("leaving twice: %v", err)
		}
		if err := w.org.RemoveTeamMember(w.as(w.carol), organization.TeamMemberRequest{TeamID: eng.ID, UserID: w.bob.User.ID}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member removes another: %v", err)
		}
		// Clearing the active team keeps the organization.
		must[organization.ActiveResult](t)(w.org.SetActiveTeam(w.as(w.bob), eng.ID))
		if r := must[organization.ActiveResult](t)(w.org.SetActiveTeam(w.as(w.bob), "")); r.OrgID == nil || *r.OrgID != w.o.ID || r.TeamID != nil {
			t.Fatalf("cleared team = %+v", r)
		}

		// An invitation into a team joins it on acceptance.
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dan@example.com", Role: organization.RoleMember, TeamID: def.ID}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dan@example.com", Role: organization.RoleMember, TeamID: "team_nope"}); !errors.Is(err, organization.ErrTeamNotFound) {
			t.Fatalf("invite into an unknown team: %v", err)
		}
		inv := must[[]organization.Invite](t)(w.org.Invites(w.as(dan)))[0]
		must[organization.Org](t)(w.org.Accept(w.as(dan), inv.ID))
		if got := must[[]organization.Team](t)(w.org.ListUserTeams(w.as(dan))); len(got) != 1 || got[0].ID != def.ID {
			t.Fatalf("dan's teams = %+v", got)
		}
		full := must[organization.FullOrg](t)(w.org.GetFull(w.as(dan), organization.GetRequest{OrgID: w.o.ID}))
		if len(full.Teams) != 3 {
			t.Fatalf("full teams = %d", len(full.Teams))
		}
		// Leaving the organization leaves its teams; deleting a user too.
		if err := w.org.RemoveMember(w.as(dan), organization.MemberRequest{OrgID: w.o.ID, UserID: dan.User.ID}); err != nil {
			t.Fatal(err)
		}
		if got := must[[]organization.Team](t)(w.org.ListUserTeams(w.as(dan))); len(got) != 0 {
			t.Fatalf("teams after leaving = %+v", got)
		}
		if err := w.a.DeleteUser(context.Background(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if got := must[[]organization.TeamMember](t)(w.org.ListTeamMembers(w.ownerCtx(), eng.ID)); len(got) != 0 {
			t.Fatalf("deleted user still in team: %+v", got)
		}
		// Removal: the last team stays.
		for _, id := range []string{eng.ID} {
			if err := w.org.RemoveTeam(w.as(w.carol), id); !errors.Is(err, organization.ErrForbidden) {
				t.Fatalf("member removes a team: %v", err)
			}
			if err := w.org.RemoveTeam(w.ownerCtx(), id); err != nil {
				t.Fatal(err)
			}
		}
		left := must[[]organization.Team](t)(w.org.ListTeams(w.ownerCtx(), w.o.ID))
		if err := w.org.RemoveTeam(w.ownerCtx(), left[0].ID); err != nil {
			t.Fatal(err)
		}
		if err := w.org.RemoveTeam(w.ownerCtx(), left[1].ID); !errors.Is(err, organization.ErrLastTeam) {
			t.Fatalf("removing the last team: %v", err)
		}
		// Deleting the organization removes its teams.
		if err := w.org.Delete(w.ownerCtx(), w.o.ID); err != nil {
			t.Fatal(err)
		}
		if got := count(t, e, organization.TableNameTeam); got != 0 {
			t.Fatalf("teams after delete = %d", got)
		}
	})
}

func TestR30_TeamOptions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		named := func(_ context.Context, o organization.Org, u auth.User) (string, error) { return o.Name + " core", nil }
		w := orgSetup(t, e, organization.Teams(organization.TeamsConfig{DefaultTeamName: named, AllowRemovingAllTeams: true}))
		teams := must[[]organization.Team](t)(w.org.ListTeams(request(w.a, w.owner.Token), w.o.ID))
		if len(teams) != 1 || teams[0].Name != "Acme core" {
			t.Fatalf("named default team = %+v", teams)
		}
		if err := w.org.RemoveTeam(request(w.a, w.owner.Token), teams[0].ID); err != nil {
			t.Fatalf("AllowRemovingAllTeams: %v", err)
		}
	})
}

func TestR30_NoDefaultTeam(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e, organization.Teams(organization.TeamsConfig{NoDefaultTeam: true}))
		if got := must[[]organization.Team](t)(w.org.ListTeams(request(w.a, w.owner.Token), w.o.ID)); len(got) != 0 {
			t.Fatalf("NoDefaultTeam made %+v", got)
		}
	})
}

func TestR30_DynamicRoles(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: 2}))
		create := func(u password.SignInResult, name organization.Role, perm access.Permissions) (organization.OrgRole, error) {
			return w.org.CreateRole(w.as(u), organization.CreateRoleRequest{OrgID: w.o.ID, Role: name, Permission: perm})
		}
		if _, err := create(w.carol, "auditor", access.Permissions{organization.ResourceAC: {organization.ActionRead}}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member creates a role: %v", err)
		}
		if _, err := create(w.bob, "deleter", access.Permissions{organization.ResourceOrganization: {organization.ActionDelete}}); !errors.Is(err, organization.ErrBadPermission) {
			t.Fatalf("admin grants what they lack: %v", err)
		}
		if _, err := create(w.bob, "x", access.Permissions{"project": {"create"}}); !errors.Is(err, organization.ErrBadPermission) {
			t.Fatalf("undeclared statement: %v", err)
		}
		if _, err := create(w.bob, organization.RoleAdmin, access.Permissions{}); !errors.Is(err, organization.ErrRoleTaken) {
			t.Fatalf("static name: %v", err)
		}
		for _, bad := range []organization.Role{"", " a", "a,b"} {
			if _, err := create(w.bob, bad, access.Permissions{}); !errors.Is(err, organization.ErrBadRole) {
				t.Fatalf("name %q: %v", bad, err)
			}
		}
		inviter := must[organization.OrgRole](t)(create(w.bob, "inviter", access.Permissions{organization.ResourceInvitation: {organization.ActionCreate, organization.ActionCancel}}))
		if _, err := create(w.bob, "inviter", access.Permissions{}); !errors.Is(err, organization.ErrRoleTaken) {
			t.Fatalf("duplicate: %v", err)
		}
		must[organization.OrgRole](t)(create(w.owner, "remover", access.Permissions{organization.ResourceMember: {organization.ActionDelete}}))
		if _, err := create(w.owner, "third", access.Permissions{}); !errors.Is(err, organization.ErrRolesLimit) {
			t.Fatalf("MaxRoles: %v", err)
		}
		// Assigning it grants its permissions.
		if err := w.org.SetRole(w.as(w.bob), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: "inviter"}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.SetRole(w.as(w.bob), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: "ghost"}); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("unknown dynamic role: %v", err)
		}
		if err := w.org.Invite(w.as(w.carol), organization.InviteRequest{OrgID: w.o.ID, Email: "new@example.com", Role: "inviter"}); err != nil {
			t.Fatalf("inviter invites: %v", err)
		}
		// Reads need ac:read, which the inviter role lacks.
		if _, err := w.org.ListRoles(w.as(w.carol), w.o.ID); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("inviter lists roles: %v", err)
		}
		if got := must[[]organization.OrgRole](t)(w.org.ListRoles(w.as(w.bob), w.o.ID)); len(got) != 2 || got[0].Role != "inviter" {
			t.Fatalf("roles = %+v", got)
		}
		got := must[organization.OrgRole](t)(w.org.GetRole(w.as(w.bob), organization.RoleRequest{OrgID: w.o.ID, RoleName: "inviter"}))
		if got.ID != inviter.ID || len(got.Permission[organization.ResourceInvitation]) != 2 {
			t.Fatalf("get = %+v", got)
		}
		if _, err := w.org.GetRole(w.as(w.bob), organization.RoleRequest{OrgID: w.o.ID, RoleID: "role_nope"}); !errors.Is(err, organization.ErrRoleNotFound) {
			t.Fatalf("unknown id: %v", err)
		}
		// In use: no delete, no rename; permissions may change.
		if err := w.org.DeleteRole(w.as(w.bob), organization.RoleRequest{OrgID: w.o.ID, RoleID: inviter.ID}); !errors.Is(err, organization.ErrRoleInUse) {
			t.Fatalf("delete in use: %v", err)
		}
		newName := organization.Role("sender")
		if _, err := w.org.UpdateRole(w.as(w.bob), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleID: inviter.ID, Data: organization.RoleUpdate{RoleName: &newName}}); !errors.Is(err, organization.ErrRoleInUse) {
			t.Fatalf("rename in use: %v", err)
		}
		up := must[organization.OrgRole](t)(w.org.UpdateRole(w.as(w.bob), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleName: "inviter", Data: organization.RoleUpdate{Permission: access.Permissions{organization.ResourceInvitation: {organization.ActionCancel}}}}))
		if len(up.Permission[organization.ResourceInvitation]) != 1 {
			t.Fatalf("updated = %+v", up)
		}
		if err := w.org.Invite(w.as(w.carol), organization.InviteRequest{OrgID: w.o.ID, Email: "n2@example.com", Role: organization.RoleMember}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("permission removed, still invites: %v", err)
		}
		if _, err := w.org.UpdateRole(w.as(w.bob), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleName: "inviter", Data: organization.RoleUpdate{Permission: access.Permissions{"x": {"y"}}}}); !errors.Is(err, organization.ErrBadPermission) {
			t.Fatalf("update to undeclared: %v", err)
		}
		taken := organization.Role("remover")
		if _, err := w.org.UpdateRole(w.as(w.bob), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleName: "inviter", Data: organization.RoleUpdate{RoleName: &taken}}); !errors.Is(err, organization.ErrRoleTaken) {
			t.Fatalf("rename onto another: %v", err)
		}
		// Free it, then rename and delete.
		if err := w.org.SetRole(w.as(w.bob), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		if got := must[organization.OrgRole](t)(w.org.UpdateRole(w.as(w.bob), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleID: inviter.ID, Data: organization.RoleUpdate{RoleName: &newName}})); got.Role != newName {
			t.Fatalf("renamed = %+v", got)
		}
		if err := w.org.DeleteRole(w.as(w.bob), organization.RoleRequest{OrgID: w.o.ID, RoleName: newName}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.DeleteRole(w.as(w.carol), organization.RoleRequest{OrgID: w.o.ID, RoleName: "remover"}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatalf("member deletes: %v", err)
		}
		// Deleting the organization removes its roles.
		if err := w.org.Delete(w.ownerCtx(), w.o.ID); err != nil {
			t.Fatal(err)
		}
		if got := count(t, e, organization.TableNameRole); got != 0 {
			t.Fatalf("roles after delete = %d", got)
		}
	})
}

func TestR30_Hooks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var log []string
		veto := errors.New("vetoed")
		hooks := organization.Hooks{
			BeforeCreateOrg: func(_ context.Context, o *organization.Org, _ auth.User) error {
				if o.Name == "Forbidden" {
					return veto
				}
				o.Name += " (beta)"
				return nil
			},
			AfterCreateOrg: func(_ context.Context, o organization.Org, _ auth.User) error {
				log = append(log, "created "+o.Name)
				return nil
			},
			BeforeUpdateOrg: func(_ context.Context, old organization.Org, o *organization.Org) error {
				o.ID = "org_hijack" // restored by the plugin
				return nil
			},
			AfterUpdateOrg:  func(_ context.Context, o organization.Org) error { log = append(log, "updated "+o.ID); return nil },
			BeforeDeleteOrg: func(context.Context, organization.Org) error { return veto },
			BeforeAddMember: func(_ context.Context, m *organization.MemberChange) error {
				m.Role = organization.RoleMember // every join is a member
				return nil
			},
			AfterAddMember: func(_ context.Context, m organization.MemberChange) error {
				log = append(log, "joined "+string(m.Role))
				return nil
			},
			BeforeRemoveMember: func(context.Context, organization.MemberChange) error { return veto },
			BeforeUpdateMemberRole: func(_ context.Context, m *organization.MemberChange, old organization.Role) error {
				if m.Role == organization.RoleOwner {
					return veto
				}
				return nil
			},
			AfterUpdateMemberRole: func(_ context.Context, m organization.MemberChange, old organization.Role) error {
				log = append(log, "role "+string(old)+"->"+string(m.Role))
				return nil
			},
			BeforeCreateInvitation: func(_ context.Context, inv *organization.Invitation, _ auth.User) error {
				inv.ExpiresAt = inv.CreatedAt.Add(time.Hour)
				inv.Email = "hijack@example.com" // restored
				return nil
			},
			AfterCreateInvitation: func(_ context.Context, inv organization.Invitation, _ auth.User) error {
				log = append(log, "invited "+inv.Email)
				return nil
			},
			BeforeAcceptInvitation: func(context.Context, organization.Invitation, auth.User) error {
				log = append(log, "accepting")
				return nil
			},
			AfterAcceptInvitation: func(_ context.Context, inv organization.Invitation, _ auth.User) error {
				log = append(log, "accepted "+string(inv.Status))
				return nil
			},
			BeforeRejectInvitation: func(context.Context, organization.Invitation, auth.User) error { return veto },
			AfterCancelInvitation: func(_ context.Context, inv organization.Invitation, _ auth.User) error {
				log = append(log, "canceled")
				return nil
			},
		}
		w := orgSetup(t, e, organization.WithHooks(hooks))
		owner := request(w.a, w.owner.Token)
		if w.o.Name != "Acme (beta)" {
			t.Fatalf("hook did not rename: %q", w.o.Name)
		}
		if _, err := w.org.Create(owner, organization.CreateRequest{Name: "Forbidden", Slug: "forbidden"}); !errors.Is(err, veto) {
			t.Fatalf("veto: %v", err)
		}
		if got := count(t, e, organization.TableNameOrg); got != 1 {
			t.Fatalf("vetoed create left %d orgs", got)
		}
		name := "New"
		if got := must[organization.Org](t)(w.org.Update(owner, organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Name: &name}})); got.ID != w.o.ID {
			t.Fatalf("hook moved the update to %q", got.ID)
		}
		if err := w.org.Delete(owner, w.o.ID); !errors.Is(err, veto) {
			t.Fatalf("delete veto: %v", err)
		}
		bob := w.orgUser(t, e, "bob@example.com")
		if err := w.org.Invite(owner, organization.InviteRequest{OrgID: w.o.ID, Email: "bob@example.com", Role: organization.RoleAdmin}); err != nil {
			t.Fatal(err)
		}
		inv := must[[]organization.Invite](t)(w.org.Invites(request(w.a, bob.Token)))
		if len(inv) != 1 || !inv[0].ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) {
			t.Fatalf("hooked invitation = %+v", inv)
		}
		if err := w.org.Reject(request(w.a, bob.Token), inv[0].ID); !errors.Is(err, veto) {
			t.Fatalf("reject veto: %v", err)
		}
		must[organization.Org](t)(w.org.Accept(request(w.a, bob.Token), inv[0].ID))
		if r, _ := w.orgRole(t, bob.User.ID); r != organization.RoleMember {
			t.Fatalf("BeforeAddMember did not set the role: %q", r)
		}
		if err := w.org.SetRole(owner, organization.SetRoleRequest{OrgID: w.o.ID, UserID: bob.User.ID, Role: organization.RoleOwner}); !errors.Is(err, veto) {
			t.Fatalf("role veto: %v", err)
		}
		if err := w.org.SetRole(owner, organization.SetRoleRequest{OrgID: w.o.ID, UserID: bob.User.ID, Role: organization.RoleAdmin}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.RemoveMember(owner, organization.MemberRequest{OrgID: w.o.ID, UserID: bob.User.ID}); !errors.Is(err, veto) {
			t.Fatalf("remove veto: %v", err)
		}
		if err := w.org.Invite(owner, organization.InviteRequest{OrgID: w.o.ID, Email: "zed@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		var zed string
		for _, i := range must[[]organization.Invitation](t)(w.org.ListInvitations(owner, w.o.ID)) {
			if i.Status == organization.StatusPending {
				zed = i.ID
			}
		}
		if err := w.org.Cancel(owner, zed); err != nil {
			t.Fatal(err)
		}
		want := "created Acme (beta)|updated " + w.o.ID + "|invited bob@example.com|accepting|joined member|accepted accepted|role member->admin|invited zed@example.com|canceled"
		if got := strings.Join(log, "|"); got != want {
			t.Fatalf("hook log:\n got %s\nwant %s", got, want)
		}
	})
}

func TestR30_ValidateRefusesBadConfiguration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		other := access.MustNew(access.Statements{"x": {"y"}})
		for name, opts := range map[string][]organization.Option{
			"creator role unknown": {organization.CreatorRole("boss")},
			"creator role multi":   {organization.CreatorRole("owner,admin")},
			"role name comma":      {organization.WithRoles(map[organization.Role]access.Role{"a,b": {}})},
			"role from another ac": {organization.WithRoles(map[organization.Role]access.Role{"r": other.MustRole(access.Permissions{"x": {"y"}})})},
			"nil access control":   {organization.WithAccessControl(nil)},
			"negative invitations": {organization.InvitationLimit(-1)},
			"negative teams":       {organization.Teams(organization.TeamsConfig{MaxTeams: -1})},
			"negative roles":       {organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: -1})},
		} {
			_, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), organization.New(opts...)))
			if err == nil || !strings.Contains(err.Error(), "organization") {
				t.Errorf("%s: err = %v", name, err)
			}
		}
	})
}

// TestR30_FaultSweep fails every database step of every new operation in
// turn and requires the failure to surface, never an empty answer.
func TestR30_FaultSweep(t *testing.T) {
	all := []organization.Option{
		organization.Teams(organization.TeamsConfig{MaxTeams: 5, MaxMembersPerTeam: 5}),
		organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: 5}),
		organization.RejectExistingMembers(),
	}
	type world struct {
		*r30World
		team organization.Team
		role organization.OrgRole
	}
	call := func(fn func() error) func(context.Context) error { return func(context.Context) error { return fn() } }
	cases := map[string]func(t *testing.T, w *world) func(context.Context) error{
		"create": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "B", Slug: "bbb"})
				return err
			})
		},
		"get": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.Get(w.ownerCtx(), organization.GetRequest{}); return err })
		},
		"get-full": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.GetFull(w.ownerCtx(), organization.GetRequest{OrgID: w.o.ID})
				return err
			})
		},
		"update": func(_ *testing.T, w *world) func(context.Context) error {
			slug := "acme-2"
			return call(func() error {
				_, err := w.org.Update(w.ownerCtx(), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Slug: &slug}})
				return err
			})
		},
		"delete": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { return w.org.Delete(w.ownerCtx(), w.o.ID) })
		},
		"set-active": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.SetActive(w.as(w.bob), organization.SetActiveRequest{OrgSlug: "acme"})
				return err
			})
		},
		"active": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.Active(w.ownerCtx()); return err })
		},
		"active-org-id": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, _, err := w.org.ActiveOrgID(w.ownerCtx()); return err })
		},
		"reject": func(t *testing.T, w *world) func(context.Context) error {
			dan, inv := w.invited(t, "")
			return call(func() error { return w.org.Reject(w.as(dan), inv) })
		},
		"cancel": func(t *testing.T, w *world) func(context.Context) error {
			_, inv := w.invited(t, "")
			return call(func() error { return w.org.Cancel(w.as(w.bob), inv) })
		},
		"accept-into-team": func(t *testing.T, w *world) func(context.Context) error {
			dan, inv := w.invited(t, w.team.ID)
			return call(func() error { _, err := w.org.Accept(w.as(dan), inv); return err })
		},
		"invite-into-team": func(t *testing.T, w *world) func(context.Context) error {
			w.orgUser(t, w.env, "dan@example.com")
			return call(func() error {
				return w.org.Invite(w.ownerCtx(), organization.InviteRequest{Email: "dan@example.com", Role: "custom", TeamID: w.team.ID})
			})
		},
		"list-invitations": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.ListInvitations(w.ownerCtx(), ""); return err })
		},
		"has-permission": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.HasPermission(w.as(w.carol), organization.PermissionRequest{OrgID: w.o.ID, Permissions: access.Permissions{organization.ResourceMember: {organization.ActionCreate}}})
				return err
			})
		},
		"members-filtered": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.ListMembers(w.ownerCtx(), organization.OrgRequest{FilterField: organization.FieldRole, FilterValue: "custom"})
				return err
			})
		},
		"role": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.Role(w.ownerCtx(), ""); return err })
		},
		"remove-member": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				return w.org.RemoveMember(w.as(w.bob), organization.MemberRequest{UserID: w.carol.User.ID, OrgID: w.o.ID})
			})
		},
		"set-role": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				return w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.bob.User.ID, Role: "custom,member"})
			})
		},
		"create-team": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{Name: "T"})
				return err
			})
		},
		"list-teams": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.ListTeams(w.ownerCtx(), ""); return err })
		},
		"update-team": func(_ *testing.T, w *world) func(context.Context) error {
			n := "N"
			return call(func() error {
				_, err := w.org.UpdateTeam(w.ownerCtx(), organization.UpdateTeamRequest{TeamID: w.team.ID, Data: organization.TeamUpdate{Name: &n}})
				return err
			})
		},
		"remove-team": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { return w.org.RemoveTeam(w.ownerCtx(), w.team.ID) })
		},
		"set-active-team": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.SetActiveTeam(w.as(w.carol), w.team.ID); return err })
		},
		"clear-active-team": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.SetActiveTeam(w.ownerCtx(), ""); return err })
		},
		"list-user-teams": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.ListUserTeams(w.as(w.carol)); return err })
		},
		"list-team-members": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.ListTeamMembers(w.as(w.carol), w.team.ID); return err })
		},
		"add-team-member": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				return w.org.AddTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: w.team.ID, UserID: w.bob.User.ID})
			})
		},
		"remove-team-member": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				return w.org.RemoveTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: w.team.ID, UserID: w.carol.User.ID})
			})
		},
		"create-role": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{Role: "r2", Permission: access.Permissions{organization.ResourceTeam: {organization.ActionCreate}}})
				return err
			})
		},
		"update-role": func(_ *testing.T, w *world) func(context.Context) error {
			name := organization.Role("unused2")
			return call(func() error {
				_, err := w.org.UpdateRole(w.ownerCtx(), organization.UpdateRoleRequest{RoleName: "unused", Data: organization.RoleUpdate{RoleName: &name, Permission: access.Permissions{organization.ResourceAC: {organization.ActionRead}}}})
				return err
			})
		},
		"delete-role": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { return w.org.DeleteRole(w.ownerCtx(), organization.RoleRequest{RoleName: "unused"}) })
		},
		"get-role": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error {
				_, err := w.org.GetRole(w.ownerCtx(), organization.RoleRequest{RoleID: w.role.ID})
				return err
			})
		},
		"list-roles": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.ListRoles(w.ownerCtx(), ""); return err })
		},
		"sign-out-everywhere": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { return w.a.SignOutAll(w.ownerCtx()) })
		},
		"session-replaced": func(t *testing.T, w *world) func(context.Context) error {
			s := w.session(t, w.owner)
			return call(func() error {
				return w.org.SessionReplaced(context.Background(), s, auth.Session{ID: "ses_new", UserID: s.UserID, ExpiresAt: s.ExpiresAt})
			})
		},
		"sweep": func(_ *testing.T, w *world) func(context.Context) error {
			return call(func() error { _, err := w.org.Sweep(context.Background(), time.Now().Add(1000*time.Hour)); return err })
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				w := &world{r30World: r30Setup(t, e.env, all...)}
				w.role = must[organization.OrgRole](t)(w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{Role: "custom", Permission: access.Permissions{organization.ResourceMember: {organization.ActionCreate}}}))
				must[organization.OrgRole](t)(w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{Role: "unused", Permission: access.Permissions{}}))
				if err := w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: "member,custom"}); err != nil {
					t.Fatal(err)
				}
				w.team = must[organization.Team](t)(w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{Name: "Eng"}))
				for _, u := range []string{w.carol.User.ID, w.owner.User.ID} {
					if err := w.org.AddTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: w.team.ID, UserID: u}); err != nil {
						t.Fatal(err)
					}
				}
				must[organization.ActiveResult](t)(w.org.SetActiveTeam(w.ownerCtx(), w.team.ID))
				return op(t, w)
			})
		})
	}
}

// invited signs dan up and invites him, into team when it is set,
// returning his session and the invitation id.
func (w *r30World) invited(t *testing.T, team string) (password.SignInResult, string) {
	t.Helper()
	dan := w.orgUser(t, w.env, "dan@example.com")
	if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "dan@example.com", Role: organization.RoleMember, TeamID: team}); err != nil {
		t.Fatal(err)
	}
	return dan, must[[]organization.Invite](t)(w.org.Invites(w.as(dan)))[0].ID
}

// session resolves u's session.
func (w *r30World) session(t *testing.T, u password.SignInResult) auth.Session {
	t.Helper()
	s, _, _, err := w.a.ResolveSession(context.Background(), u.Token)
	if err != nil || s == nil {
		t.Fatalf("resolve: %v", err)
	}
	return *s
}

// TestR30_SessionReplacedMovesTheSelection: the selection made on a pending
// second-factor session belongs to the full session after promotion.
func TestR30_SessionReplacedMovesTheSelection(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		old := w.session(t, w.owner)
		next := auth.Session{ID: "ses_promoted", UserID: old.UserID, ExpiresAt: old.ExpiresAt}
		if err := w.org.SessionReplaced(context.Background(), old, next); err != nil {
			t.Fatal(err)
		}
		var sid, org string
		if err := e.db.QueryRow("SELECT "+organization.ColActiveSessionID+", "+organization.ColActiveOrgID+" FROM "+tbl(organization.TableNameActive)).Scan(&sid, &org); err != nil {
			t.Fatal(err)
		}
		if sid != next.ID || org != w.o.ID {
			t.Fatalf("selection = %s %s", sid, org)
		}
		// Nothing selected: nothing to move.
		if err := w.org.SessionReplaced(context.Background(), w.session(t, w.bob), auth.Session{ID: "x", UserID: w.bob.User.ID}); err != nil {
			t.Fatal(err)
		}
		// Sign-out everywhere drops every selection of the user.
		if err := w.a.SignOutAll(w.ownerCtx()); err != nil {
			t.Fatal(err)
		}
		if got := count(t, e, organization.TableNameActive); got != 0 {
			t.Fatalf("rows after sign-out everywhere = %d", got)
		}
	})
}

func TestR30_TeamHooks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var log []string
		veto := errors.New("vetoed")
		hooks := organization.Hooks{
			BeforeCreateTeam: func(_ context.Context, tm *organization.Team) error {
				if tm.Name == "No" {
					return veto
				}
				tm.Name = strings.ToUpper(tm.Name)
				return nil
			},
			AfterCreateTeam: func(_ context.Context, tm organization.Team) error { log = append(log, "team "+tm.Name); return nil },
			BeforeUpdateTeam: func(_ context.Context, old organization.Team, tm *organization.Team) error {
				tm.OrgID = "org_other" // restored
				return nil
			},
			AfterUpdateTeam: func(_ context.Context, tm organization.Team) error { log = append(log, "renamed "+tm.Name); return nil },
			BeforeDeleteTeam: func(_ context.Context, tm organization.Team) error {
				log = append(log, "deleting "+tm.Name)
				return nil
			},
			AfterDeleteTeam: func(_ context.Context, tm organization.Team) error { log = append(log, "deleted"); return nil },
			BeforeAddTeamMember: func(_ context.Context, m organization.TeamMemberChange) error {
				log = append(log, "adding")
				return nil
			},
			AfterAddTeamMember: func(_ context.Context, m organization.TeamMemberChange) error { log = append(log, "added"); return nil },
			BeforeRemoveTeamMember: func(_ context.Context, m organization.TeamMemberChange) error {
				log = append(log, "removing")
				return nil
			},
			AfterRemoveTeamMember: func(_ context.Context, m organization.TeamMemberChange) error { return veto },
		}
		w := orgSetup(t, e, organization.WithHooks(hooks), organization.Teams(organization.TeamsConfig{NoDefaultTeam: true, AllowRemovingAllTeams: true}))
		owner := request(w.a, w.owner.Token)
		if _, err := w.org.CreateTeam(owner, organization.CreateTeamRequest{OrgID: w.o.ID, Name: "No"}); !errors.Is(err, veto) {
			t.Fatalf("veto: %v", err)
		}
		tm := must[organization.Team](t)(w.org.CreateTeam(owner, organization.CreateTeamRequest{OrgID: w.o.ID, Name: "eng"}))
		n := "ops"
		if got := must[organization.Team](t)(w.org.UpdateTeam(owner, organization.UpdateTeamRequest{TeamID: tm.ID, Data: organization.TeamUpdate{Name: &n}})); got.OrgID != w.o.ID {
			t.Fatalf("hook moved the team to %q", got.OrgID)
		}
		if err := w.org.AddTeamMember(owner, organization.TeamMemberRequest{TeamID: tm.ID, UserID: w.owner.User.ID}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.RemoveTeamMember(owner, organization.TeamMemberRequest{TeamID: tm.ID, UserID: w.owner.User.ID}); !errors.Is(err, veto) {
			t.Fatalf("after-hook error: %v", err)
		}
		if got := must[[]organization.TeamMember](t)(w.org.ListTeamMembers(owner, tm.ID)); len(got) != 1 {
			t.Fatalf("a failed after hook did not roll back: %d members", len(got))
		}
		if err := w.org.RemoveTeam(owner, tm.ID); err != nil {
			t.Fatal(err)
		}
		want := "team ENG|renamed ops|adding|added|removing|deleting ops|deleted"
		if got := strings.Join(log, "|"); got != want {
			t.Fatalf("hook log:\n got %s\nwant %s", got, want)
		}
	})
}

// TestR30_EveryHookCanFail arms every Before hook, then every After hook,
// and requires each operation to fail with the hook's error and leave
// nothing behind.
func TestR30_EveryHookCanFail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		veto := errors.New("vetoed")
		var before, after bool
		b := func() error {
			if before {
				return veto
			}
			return nil
		}
		a := func() error {
			if after {
				return veto
			}
			return nil
		}
		hooks := organization.Hooks{
			BeforeCreateOrg:        func(context.Context, *organization.Org, auth.User) error { return b() },
			AfterCreateOrg:         func(context.Context, organization.Org, auth.User) error { return a() },
			BeforeUpdateOrg:        func(context.Context, organization.Org, *organization.Org) error { return b() },
			AfterUpdateOrg:         func(context.Context, organization.Org) error { return a() },
			BeforeDeleteOrg:        func(context.Context, organization.Org) error { return b() },
			AfterDeleteOrg:         func(context.Context, organization.Org) error { return a() },
			BeforeAddMember:        func(context.Context, *organization.MemberChange) error { return b() },
			AfterAddMember:         func(context.Context, organization.MemberChange) error { return a() },
			BeforeRemoveMember:     func(context.Context, organization.MemberChange) error { return b() },
			AfterRemoveMember:      func(context.Context, organization.MemberChange) error { return a() },
			BeforeUpdateMemberRole: func(context.Context, *organization.MemberChange, organization.Role) error { return b() },
			AfterUpdateMemberRole:  func(context.Context, organization.MemberChange, organization.Role) error { return a() },
			BeforeCreateInvitation: func(context.Context, *organization.Invitation, auth.User) error { return b() },
			AfterCreateInvitation:  func(context.Context, organization.Invitation, auth.User) error { return a() },
			BeforeAcceptInvitation: func(context.Context, organization.Invitation, auth.User) error { return b() },
			AfterAcceptInvitation:  func(context.Context, organization.Invitation, auth.User) error { return a() },
			BeforeRejectInvitation: func(context.Context, organization.Invitation, auth.User) error { return b() },
			AfterRejectInvitation:  func(context.Context, organization.Invitation, auth.User) error { return a() },
			BeforeCancelInvitation: func(context.Context, organization.Invitation, auth.User) error { return b() },
			AfterCancelInvitation:  func(context.Context, organization.Invitation, auth.User) error { return a() },
			BeforeCreateTeam:       func(context.Context, *organization.Team) error { return b() },
			AfterCreateTeam:        func(context.Context, organization.Team) error { return a() },
			BeforeUpdateTeam:       func(context.Context, organization.Team, *organization.Team) error { return b() },
			AfterUpdateTeam:        func(context.Context, organization.Team) error { return a() },
			BeforeDeleteTeam:       func(context.Context, organization.Team) error { return b() },
			AfterDeleteTeam:        func(context.Context, organization.Team) error { return a() },
			BeforeAddTeamMember:    func(context.Context, organization.TeamMemberChange) error { return b() },
			AfterAddTeamMember:     func(context.Context, organization.TeamMemberChange) error { return a() },
			BeforeRemoveTeamMember: func(context.Context, organization.TeamMemberChange) error { return b() },
			AfterRemoveTeamMember:  func(context.Context, organization.TeamMemberChange) error { return a() },
		}
		w := r30Setup(t, e, organization.WithHooks(hooks), organization.Teams(organization.TeamsConfig{}))
		team := must[organization.Team](t)(w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Eng"}))
		if err := w.org.AddTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: team.ID, UserID: w.carol.User.ID}); err != nil {
			t.Fatal(err)
		}
		dan, invID := w.invited(t, "")
		name := "N"
		ops := map[string]func() error{
			"create": func() error {
				_, err := w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: "B", Slug: "bbb"})
				return err
			},
			"update": func() error {
				_, err := w.org.Update(w.ownerCtx(), organization.UpdateRequest{OrgID: w.o.ID, Data: organization.OrgUpdate{Name: &name}})
				return err
			},
			"delete": func() error { return w.org.Delete(w.ownerCtx(), w.o.ID) },
			"add-member": func() error {
				return w.org.AddMember(context.Background(), w.o.ID, dan.User.ID, organization.RoleMember)
			},
			"remove-member": func() error {
				return w.org.RemoveMember(w.ownerCtx(), organization.MemberRequest{OrgID: w.o.ID, UserID: w.carol.User.ID})
			},
			"set-role": func() error {
				return w.org.SetRole(w.ownerCtx(), organization.SetRoleRequest{OrgID: w.o.ID, UserID: w.carol.User.ID, Role: organization.RoleAdmin})
			},
			"invite": func() error {
				return w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "x@example.com", Role: organization.RoleMember})
			},
			"accept": func() error { _, err := w.org.Accept(w.as(dan), invID); return err },
			"reject": func() error { return w.org.Reject(w.as(dan), invID) },
			"cancel": func() error { return w.org.Cancel(w.ownerCtx(), invID) },
			"create-team": func() error {
				_, err := w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "T"})
				return err
			},
			"update-team": func() error {
				_, err := w.org.UpdateTeam(w.ownerCtx(), organization.UpdateTeamRequest{TeamID: team.ID, Data: organization.TeamUpdate{Name: &name}})
				return err
			},
			"remove-team": func() error { return w.org.RemoveTeam(w.ownerCtx(), team.ID) },
			"add-team-member": func() error {
				return w.org.AddTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: team.ID, UserID: w.bob.User.ID})
			},
			"remove-team-member": func() error {
				return w.org.RemoveTeamMember(w.ownerCtx(), organization.TeamMemberRequest{TeamID: team.ID, UserID: w.carol.User.ID})
			},
		}
		tables := []string{organization.TableNameOrg, organization.TableNameMember, organization.TableNameInvite, organization.TableNameTeam, organization.TableNameTeamMember}
		snapshot := func() string {
			var parts []string
			for _, tb := range tables {
				parts = append(parts, tb+"="+strings.Repeat("|", count(t, e, tb)))
			}
			return strings.Join(parts, " ")
		}
		start := snapshot()
		for _, stage := range []string{"before", "after"} {
			before, after = stage == "before", stage == "after"
			for name, op := range ops {
				if err := op(); !errors.Is(err, veto) {
					t.Errorf("%s hook of %s: %v", stage, name, err)
				}
			}
		}
		before, after = false, false
		if got := snapshot(); got != start {
			t.Fatalf("a failed hook left rows behind:\n got %s\nwant %s", got, start)
		}
	})
}

// r30Fields declares extra columns on every table.
var r30Fields = organization.FieldsConfig{
	Org: []organization.Field{
		{Name: "plan", Type: auth.ColumnText, Nullable: true, ServerOnly: true},
		{Name: "seats", Type: auth.ColumnInt, Default: "5"},
		{Name: "trial", Type: auth.ColumnBool, Default: "false"},
		{Name: "renews_at", Type: auth.ColumnTimestamp, Nullable: true},
	},
	Member:     []organization.Field{{Name: "title", Type: auth.ColumnText, Nullable: true}},
	Invitation: []organization.Field{{Name: "note", Type: auth.ColumnText, Nullable: true}},
	Team:       []organization.Field{{Name: "color", Type: auth.ColumnText, Default: "'grey'", Required: true}},
	Role:       []organization.Field{{Name: "level", Type: auth.ColumnInt, Nullable: true}},
}

func raw(v string) json.RawMessage { return json.RawMessage(v) }

func TestR30_AdditionalFields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var plan string
		hooks := organization.Hooks{BeforeCreateOrg: func(_ context.Context, o *organization.Org, _ auth.User) error {
			if plan != "" {
				o.Fields = mergeR30(o.Fields, auth.Fields{"plan": raw(plan)})
			}
			return nil
		}}
		opts := []organization.Option{organization.WithFields(r30Fields), organization.Teams(organization.TeamsConfig{}),
			organization.DynamicRoles(organization.DynamicRolesConfig{}), organization.WithHooks(hooks)}
		w := r30Setup(t, e, opts...)
		// The org of the setup was created with only defaults.
		got := must[organization.Org](t)(w.org.Get(w.ownerCtx(), organization.GetRequest{OrgID: w.o.ID}))
		if string(got.Fields["seats"]) != "5" || string(got.Fields["trial"]) != "false" || string(got.Fields["plan"]) != "null" || string(got.Fields["renews_at"]) != "null" {
			t.Fatalf("defaults = %s", fieldsString(got.Fields))
		}
		create := func(slug string, f auth.Fields) (organization.Org, error) {
			return w.org.Create(w.ownerCtx(), organization.CreateRequest{Name: slug, Slug: slug, Fields: f})
		}
		for name, f := range map[string]auth.Fields{
			"unknown":          {"color": raw(`"x"`)},
			"server-only":      {"seats": raw("3"), "plan": raw(`"pro"`)},
			"wrong type":       {"seats": raw(`"3"`)},
			"null in not null": {"seats": raw("null")},
			"trailing data":    {"seats": raw("3 4")},
		} {
			if _, err := create("x-"+strings.ReplaceAll(name, " ", "-"), f); !errors.Is(err, auth.ErrFieldInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		at := "2027-01-02T03:04:05Z"
		o := must[organization.Org](t)(create("beta", auth.Fields{"seats": raw("12"), "trial": raw("true"), "renews_at": raw(`"` + at + `"`)}))
		if string(o.Fields["seats"]) != "12" || string(o.Fields["trial"]) != "true" || !strings.Contains(string(o.Fields["renews_at"]), "2027-01-02T03:04:05") {
			t.Fatalf("created = %s", fieldsString(o.Fields))
		}
		// A server-only field from a hook.
		plan = `"pro"`
		o2 := must[organization.Org](t)(create("gamma", auth.Fields{"seats": raw("1")}))
		if string(o2.Fields["plan"]) != `"pro"` {
			t.Fatalf("hook-set plan = %s", fieldsString(o2.Fields))
		}
		plan = ""
		// Update merges; a client cannot set a server-only field.
		up := must[organization.Org](t)(w.org.Update(w.ownerCtx(), organization.UpdateRequest{OrgID: o.ID, Data: organization.OrgUpdate{Fields: auth.Fields{"seats": raw("20")}}}))
		if string(up.Fields["seats"]) != "20" || string(up.Fields["trial"]) != "true" {
			t.Fatalf("updated = %s", fieldsString(up.Fields))
		}
		if _, err := w.org.Update(w.ownerCtx(), organization.UpdateRequest{OrgID: o.ID, Data: organization.OrgUpdate{Fields: auth.Fields{"plan": raw(`"x"`)}}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("client sets plan: %v", err)
		}
		list := must[[]organization.OrgWithRole](t)(w.org.List(w.ownerCtx()))
		if len(list) != 3 || list[0].Fields == nil {
			t.Fatalf("list fields = %+v", list)
		}
		// Members: from Go with fields; the list carries them.
		dan := w.orgUser(t, e, "dan@example.com")
		if err := w.org.AddMemberWith(context.Background(), organization.AddMemberRequest{OrgID: w.o.ID, UserID: dan.User.ID, Role: organization.RoleMember, Fields: auth.Fields{"title": raw(`"CTO"`)}}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.AddMemberWith(context.Background(), organization.AddMemberRequest{OrgID: o.ID, UserID: dan.User.ID, Role: organization.RoleMember, Fields: auth.Fields{"title": raw("1")}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("bad member field: %v", err)
		}
		members := must[organization.MembersResult](t)(w.org.ListMembers(w.ownerCtx(), organization.OrgRequest{OrgID: w.o.ID, FilterField: organization.FieldUserID, FilterValue: dan.User.ID}))
		if len(members.Members) != 1 || string(members.Members[0].Fields["title"]) != `"CTO"` {
			t.Fatalf("member fields = %+v", members.Members)
		}
		full := must[organization.FullOrg](t)(w.org.GetFull(w.ownerCtx(), organization.GetRequest{OrgID: w.o.ID}))
		if string(full.Members[0].Fields["title"]) != "null" {
			t.Fatalf("full members fields = %+v", full.Members[0])
		}
		// Invitations.
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "x@example.com", Role: organization.RoleMember, Fields: auth.Fields{"note": raw(`"welcome"`)}}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: "y@example.com", Role: organization.RoleMember, Fields: auth.Fields{"nope": raw("1")}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("bad invitation field: %v", err)
		}
		var note string
		for _, i := range must[[]organization.Invitation](t)(w.org.ListInvitations(w.ownerCtx(), w.o.ID)) {
			if i.Email == "x@example.com" {
				note = string(i.Fields["note"])
			}
		}
		if note != `"welcome"` {
			t.Fatalf("invitation note = %q", note)
		}
		// Teams: the default team takes the default; a create may set it.
		teams := must[[]organization.Team](t)(w.org.ListTeams(w.ownerCtx(), w.o.ID))
		if string(teams[0].Fields["color"]) != `"grey"` {
			t.Fatalf("default team fields = %s", fieldsString(teams[0].Fields))
		}
		if _, err := w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Ops"}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("team without required color: %v", err)
		}
		tm := must[organization.Team](t)(w.org.CreateTeam(w.ownerCtx(), organization.CreateTeamRequest{OrgID: w.o.ID, Name: "Ops", Fields: auth.Fields{"color": raw(`"red"`)}}))
		if string(tm.Fields["color"]) != `"red"` {
			t.Fatalf("team fields = %s", fieldsString(tm.Fields))
		}
		tm = must[organization.Team](t)(w.org.UpdateTeam(w.ownerCtx(), organization.UpdateTeamRequest{TeamID: tm.ID, Data: organization.TeamUpdate{Fields: auth.Fields{"color": raw(`"blue"`)}}}))
		if string(tm.Fields["color"]) != `"blue"` {
			t.Fatalf("team update = %s", fieldsString(tm.Fields))
		}
		if _, err := w.org.UpdateTeam(w.ownerCtx(), organization.UpdateTeamRequest{TeamID: tm.ID, Data: organization.TeamUpdate{Fields: auth.Fields{"color": raw("null")}}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("null color: %v", err)
		}
		// Roles.
		r := must[organization.OrgRole](t)(w.org.CreateRole(w.ownerCtx(), organization.CreateRoleRequest{OrgID: w.o.ID, Role: "ops", Permission: access.Permissions{}, Fields: auth.Fields{"level": raw("3")}}))
		if string(r.Fields["level"]) != "3" {
			t.Fatalf("role fields = %s", fieldsString(r.Fields))
		}
		r = must[organization.OrgRole](t)(w.org.UpdateRole(w.ownerCtx(), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleID: r.ID, Data: organization.RoleUpdate{Fields: auth.Fields{"level": raw("null")}}}))
		if string(r.Fields["level"]) != "null" {
			t.Fatalf("role update = %s", fieldsString(r.Fields))
		}
		if _, err := w.org.UpdateRole(w.ownerCtx(), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleID: r.ID, Data: organization.RoleUpdate{Fields: auth.Fields{"level": raw("true")}}}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("bad role field: %v", err)
		}
		// Over HTTP the fields are a "fields" object.
		h := authhttp.Handler(w.a, authhttp.Prefix("/auth"))
		res := r30Serve(h, w.owner.Token, http.MethodGet, "/auth/organization/get-organization?orgId="+o.ID, nil)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"fields":{`) || !strings.Contains(res.Body.String(), `"seats":20`) {
			t.Fatalf("http fields = %d %s", res.Code, res.Body)
		}
		// Top-level keys, on every request kind.
		post := func(path string, body map[string]any) *httptest.ResponseRecorder {
			return r30Serve(h, w.owner.Token, http.MethodPost, "/auth/organization/"+path, body)
		}
		res = post("create", map[string]any{"name": "Delta", "slug": "delta", "seats": 7})
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"seats":7`) {
			t.Fatalf("top-level create = %d %s", res.Code, res.Body)
		}
		for name, c := range map[string]struct {
			path string
			body map[string]any
			code string
		}{
			"both ways":       {"create", map[string]any{"name": "E", "slug": "eps", "seats": 1, "fields": map[string]any{"seats": 2}}, "auth.field_invalid"},
			"unknown key":     {"create", map[string]any{"name": "E", "slug": "eps", "colour": "x"}, "auth.bad_request"},
			"server-only top": {"create", map[string]any{"name": "E", "slug": "eps", "plan": "pro"}, "auth.field_invalid"},
			"update both":     {"update", map[string]any{"orgId": o.ID, "data": map[string]any{"seats": 1, "fields": map[string]any{"seats": 2}}}, "auth.field_invalid"},
		} {
			if res := post(c.path, c.body); !strings.Contains(res.Body.String(), c.code) {
				t.Errorf("%s = %d %s", name, res.Code, res.Body)
			}
		}
		for path, body := range map[string]map[string]any{
			"update":      {"orgId": o.ID, "data": map[string]any{"seats": 9}},
			"invite":      {"orgId": w.o.ID, "email": "top@example.com", "role": "member", "note": "hi"},
			"create-team": {"orgId": w.o.ID, "name": "Top", "color": "green"},
			"update-team": {"teamId": tm.ID, "data": map[string]any{"color": "teal"}},
			"create-role": {"orgId": w.o.ID, "role": "toprole", "permission": map[string]any{}, "level": 2},
			"update-role": {"orgId": w.o.ID, "roleId": r.ID, "data": map[string]any{"level": 4}},
		} {
			if res := post(path, body); res.Code != http.StatusOK {
				t.Errorf("top-level %s = %d %s", path, res.Code, res.Body)
			}
		}
		if got := must[organization.Org](t)(w.org.Get(w.ownerCtx(), organization.GetRequest{OrgID: o.ID})); string(got.Fields["seats"]) != "9" {
			t.Fatalf("top-level update stored %s", fieldsString(got.Fields))
		}
	})
}

func mergeR30(a, b auth.Fields) auth.Fields {
	out := auth.Fields{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func fieldsString(f auth.Fields) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func TestR30_FieldsValidate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for name, cfg := range map[string]struct {
			f    organization.FieldsConfig
			opts []organization.Option
		}{
			"bad name":           {f: organization.FieldsConfig{Org: []organization.Field{{Name: "Bad-Name", Type: auth.ColumnText, Nullable: true}}}},
			"shadows a column":   {f: organization.FieldsConfig{Org: []organization.Field{{Name: "slug", Type: auth.ColumnText, Nullable: true}}}},
			"twice":              {f: organization.FieldsConfig{Org: []organization.Field{{Name: "a", Type: auth.ColumnText, Nullable: true}, {Name: "a", Type: auth.ColumnText, Nullable: true}}}},
			"unknown type":       {f: organization.FieldsConfig{Org: []organization.Field{{Name: "a", Type: "json", Nullable: true}}}},
			"sql default":        {f: organization.FieldsConfig{Org: []organization.Field{{Name: "a", Type: auth.ColumnText, Default: "now()"}}}},
			"not null no def":    {f: organization.FieldsConfig{Org: []organization.Field{{Name: "a", Type: auth.ColumnText}}}},
			"required member":    {f: organization.FieldsConfig{Member: []organization.Field{{Name: "a", Type: auth.ColumnText, Default: "''", Required: true}}}},
			"team without teams": {f: organization.FieldsConfig{Team: []organization.Field{{Name: "a", Type: auth.ColumnText, Nullable: true}}}},
			"role without roles": {f: organization.FieldsConfig{Role: []organization.Field{{Name: "a", Type: auth.ColumnText, Nullable: true}}}},
		} {
			_, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), organization.New(append(cfg.opts, organization.WithFields(cfg.f))...)))
			if err == nil || !strings.Contains(err.Error(), "organization") {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

// TestR30_AuditLog records organization and session events with their
// organization and type, queries them by both, and serves a user's own
// history without the other party's details.
func TestR30_AuditLog(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		au := audit.New()
		w := &orgWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), org: organization.New(organization.Teams(organization.TeamsConfig{}))}
		w.a = e.newAuth(t, nil, w.em, w.pw, w.org, au)
		w.owner = signUpVerified(t, e, w.a, w.pw, w.em)
		w.o = must[organization.Org](t)(w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		bob := w.orgUser(t, e, "bob@example.com")
		w.orgJoin(t, bob, "bob@example.com", organization.RoleMember)
		owner := request(w.a, w.owner.Token)
		if err := w.org.SetRole(owner, organization.SetRoleRequest{OrgID: w.o.ID, UserID: bob.User.ID, Role: organization.RoleAdmin}); err != nil {
			t.Fatal(err)
		}
		if err := w.org.RemoveMember(owner, organization.MemberRequest{OrgID: w.o.ID, UserID: bob.User.ID}); err != nil {
			t.Fatal(err)
		}
		// Operations that found the organization themselves: the active one
		// (an invite with no orgId), a team's, an invitation's.
		if err := w.org.Invite(owner, organization.InviteRequest{Email: "carol@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		team := must[organization.Team](t)(w.org.CreateTeam(owner, organization.CreateTeamRequest{Name: "Eng"}))
		must[organization.Team](t)(w.org.UpdateTeam(owner, organization.UpdateTeamRequest{TeamID: team.ID}))
		stranger := w.orgUser(t, e, "eve@example.com")
		var carolInv string
		for _, i := range must[[]organization.Invitation](t)(w.org.ListInvitations(owner, w.o.ID)) {
			if i.Email == "carol@example.com" {
				carolInv = i.ID
			}
		}
		if err := w.org.Cancel(request(w.a, stranger.Token), carolInv); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("stranger cancels: %v", err)
		}
		// By organization: every operation that acted in it.
		page := must[audit.Page](t)(au.Events(context.Background(), audit.Query{OrgID: w.o.ID}))
		types := map[audit.EventType]int{}
		for _, ev := range page.Events {
			types[ev.Type]++
			if ev.OrgID != w.o.ID {
				t.Fatalf("event of another org: %+v", ev)
			}
		}
		for want, n := range map[audit.EventType]int{audit.TypeOrganizationCreated: 1, audit.TypeInvitationCreated: 2, audit.TypeInvitationAccepted: 1,
			audit.TypeMemberRoleUpdated: 1, audit.TypeMemberRemoved: 1, audit.TypeTeamCreated: 1, audit.TypeTeamUpdated: 1} {
			if types[want] != n {
				t.Fatalf("types = %v, want %d of %s", types, n, want)
			}
		}
		// A stranger's refused cancel is recorded, but not tied to the
		// organization it guessed at.
		refused := must[audit.Page](t)(au.Events(context.Background(), audit.Query{UserID: stranger.User.ID, Type: audit.TypeInvitationCanceled}))
		if refused.Total != 1 || refused.Events[0].OrgID != "" || refused.Events[0].OK {
			t.Fatalf("stranger's cancel = %+v", refused.Events)
		}
		// By type, across operations: the sign-ups and sign-ins.
		ins := must[audit.Page](t)(au.Events(context.Background(), audit.Query{Type: audit.TypeUserSignedUp}))
		if ins.Total != 3 || ins.Events[0].Type != audit.TypeUserSignedUp {
			t.Fatalf("signed-up events = %d %+v", ins.Total, ins.Events)
		}
		// Bob's own history: the removal is there, without the owner's details.
		mine := must[audit.Page](t)(au.MyEvents(request(w.a, bob.Token), audit.MyQuery{Type: audit.TypeMemberRemoved}))
		if mine.Total != 1 {
			t.Fatalf("bob's removals = %d", mine.Total)
		}
		ev := mine.Events[0]
		if ev.SubjectID != bob.User.ID || ev.ActorID != "" || ev.IP != "" || ev.UserAgent != "" || ev.SessionID != "" {
			t.Fatalf("someone else's details leaked: %+v", ev)
		}
		own := must[audit.Page](t)(au.MyEvents(request(w.a, bob.Token), audit.MyQuery{Type: audit.TypeInvitationAccepted}))
		if own.Total != 1 || own.Events[0].ActorID != bob.User.ID || own.Events[0].IP == "" {
			t.Fatalf("bob's own event = %+v", own.Events)
		}
		if _, err := au.MyEvents(anon(w.a), audit.MyQuery{}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed out: %v", err)
		}
		// Over HTTP.
		h := authhttp.Handler(w.a, authhttp.Prefix("/auth"))
		res := r30Serve(h, bob.Token, http.MethodGet, "/auth/audit/my-events?type=organization_member_removed", nil)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"type":"organization_member_removed"`) {
			t.Fatalf("my-events = %d %s", res.Code, res.Body)
		}
	})
}

// r30AdminUser signs up and verifies addr in an admin world.
func r30AdminUser(t *testing.T, e *env, w *adminWorld, addr string) password.SignInResult {
	t.Helper()
	res := must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: addr, Password: secret}))
	if _, err := w.em.Verify(anon(w.a), e.mail.LastToken(t, w.a, addr)); err != nil {
		t.Fatal(err)
	}
	return res
}

// TestR30_AdminRoles: the admin plugin's operations check permissions from
// plugin/access; the staff flag still makes an admin; set-role stores roles
// and keeps the flag in step.
func TestR30_AdminRoles(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ac := accessadmin.DefaultAccessControl
		support := ac.MustRole(access.Permissions{admin.ResourceUser: {admin.ActionList, admin.ActionGet}, admin.ResourceSession: {admin.ActionList}})
		super := ac.MustRole(access.Permissions(admin.DefaultStatements.Clone()))
		authz := accessadmin.MustNew(ac, map[string]access.Role{"support": support, "super": super})
		w := newAdminWorld(t, e, []admin.Option{admin.WithAuthorizer(authz), admin.AdminRoles(admin.RoleAdmin, "super")})
		boss, bob := w.bossCtx, func() context.Context { return request(w.a, w.bob.Token) }
		roles := func(id string) string {
			t.Helper()
			r := must[[]string](t)(w.ad.RolesOf(context.Background(), id))
			return strings.Join(r, ",")
		}
		// The flag is the admin role; everyone else holds the default role.
		if roles(w.boss.User.ID) != admin.RoleAdmin || roles(w.bob.User.ID) != admin.RoleUser {
			t.Fatalf("roles = %s / %s", roles(w.boss.User.ID), roles(w.bob.User.ID))
		}
		if _, err := w.ad.Users(bob(), admin.UsersRequest{}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("user lists: %v", err)
		}
		// support may list and read, not ban.
		if err := w.ad.SetRole(boss(), admin.SetRoleRequest{UserID: w.bob.User.ID, Role: admin.Roles{"support"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.ad.Users(bob(), admin.UsersRequest{}); err != nil {
			t.Fatalf("support lists: %v", err)
		}
		if err := w.ad.Ban(bob(), w.boss.User.ID, ""); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("support bans: %v", err)
		}
		if err := w.ad.SetRole(bob(), admin.SetRoleRequest{UserID: w.bob.User.ID, Role: admin.Roles{"super"}}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("support promotes self: %v", err)
		}
		has := func(ctx context.Context, user string, perms admin.Permissions) bool {
			t.Helper()
			ok, err := w.ad.HasPermission(ctx, admin.PermissionRequest{UserID: user, Permissions: perms})
			if err != nil {
				t.Fatal(err)
			}
			return ok
		}
		if !has(bob(), "", admin.Permissions{admin.ResourceUser: {admin.ActionList}}) || has(bob(), "", admin.Permissions{admin.ResourceUser: {admin.ActionBan}}) {
			t.Fatal("support's own permissions")
		}
		if !has(bob(), w.boss.User.ID, admin.Permissions{admin.ResourceUser: {admin.ActionBan}}) {
			t.Fatal("support reads the admin's permissions")
		}
		get := admin.Permissions{admin.ResourceUser: {admin.ActionGet}}
		if !w.ad.CheckRolePermission(context.Background(), "support", get) || w.ad.CheckRolePermission(context.Background(), "nope", get) {
			t.Fatal("CheckRolePermission")
		}
		if err := w.ad.SetRole(boss(), admin.SetRoleRequest{UserID: w.bob.User.ID, Role: admin.Roles{"ghost"}}); !errors.Is(err, admin.ErrBadRole) {
			t.Fatalf("unknown role: %v", err)
		}
		if err := w.ad.SetRole(boss(), admin.SetRoleRequest{UserID: w.bob.User.ID}); !errors.Is(err, admin.ErrBadRole) {
			t.Fatalf("no role: %v", err)
		}
		// A role in AdminRoles makes an admin: protected, flagged, listed.
		carol := r30AdminUser(t, e, w, "carol@example.com")
		if err := w.ad.SetRole(boss(), admin.SetRoleRequest{UserID: carol.User.ID, Role: admin.Roles{"super"}}); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.Ban(boss(), carol.User.ID, ""); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("ban a super: %v", err)
		}
		admins := must[admin.UsersResult](t)(w.ad.Users(boss(), admin.UsersRequest{Admin: admin.FlagTrue}))
		if admins.Total != 2 {
			t.Fatalf("admins listed = %d", admins.Total)
		}
		// Over HTTP, a role array.
		h := authhttp.Handler(w.a, authhttp.Prefix("/auth"))
		res := r30Serve(h, carol.Token, http.MethodPost, "/auth/admin/set-role", map[string]any{"userId": w.bob.User.ID, "role": []string{"support", "user"}})
		if res.Code != http.StatusOK || roles(w.bob.User.ID) != "support,user" {
			t.Fatalf("http set-role = %d %s, roles %s", res.Code, res.Body, roles(w.bob.User.ID))
		}
		res = r30Serve(h, w.bob.Token, http.MethodPost, "/auth/admin/has-permission", map[string]any{"permissions": map[string][]string{"session": {"list"}}})
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"success":true`) {
			t.Fatalf("http has-permission = %d %s", res.Code, res.Body)
		}
		// impersonate-admins: super has it, admin does not.
		if _, err := w.ad.Impersonate(boss(), admin.ImpersonateRequest{UserID: carol.User.ID}); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("admin impersonates a super: %v", err)
		}
		if _, err := w.ad.Impersonate(request(w.a, carol.Token), admin.ImpersonateRequest{UserID: w.boss.User.ID}); err != nil {
			t.Fatalf("super impersonates an admin: %v", err)
		}
		// set-admin and set-role move the flag together; the last admin stays.
		if err := w.ad.SetAdmin(boss(), carol.User.ID, false); err != nil {
			t.Fatal(err)
		}
		if roles(carol.User.ID) != admin.RoleUser {
			t.Fatalf("revoked admin roles = %s", roles(carol.User.ID))
		}
		if err := w.ad.SetAdmin(boss(), carol.User.ID, true); err != nil {
			t.Fatal(err)
		}
		if roles(carol.User.ID) != "user,admin" {
			t.Fatalf("granted roles = %s", roles(carol.User.ID))
		}
		if err := w.ad.SetRoleFor(context.Background(), w.boss.User.ID, admin.RoleUser); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.SetRoleFor(context.Background(), carol.User.ID, "support"); !errors.Is(err, admin.ErrLastAdmin) {
			t.Fatalf("last admin demoted: %v", err)
		}
	})
}

func TestR30_AdminRolesValidate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for name, opts := range map[string][]admin.Option{
			"unknown default": {admin.DefaultRole("ghost")},
			"unknown admin":   {admin.AdminRoles("ghost")},
			"no admin roles":  {admin.AdminRoles()},
			"comma in name":   {admin.AdminRoles("a,b")},
			"nil authorizer":  {admin.WithAuthorizer(nil)},
		} {
			_, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), admin.New(opts...)))
			if err == nil || !strings.Contains(err.Error(), "admin") {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

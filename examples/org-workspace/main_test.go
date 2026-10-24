package main

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/organization/orgtest"
)

// app is the example wired on the test harness: SQLite in memory, recorded
// mail, the example's own plugin list, hooks and routes, and the
// organization fixtures.
type app struct {
	env  *authtest.Env
	orgs *organization.Plugin
	f    *orgtest.Factory
	h    http.Handler
}

// newApp builds the app the way main does, on the harness instead of a file.
func newApp(t *testing.T) *app {
	t.Helper()
	env := authtest.New(t, authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		return plugins(e.Mail)
	}))
	if _, err := env.DB.ExecContext(context.Background(), appSchema); err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(env.Auth)
	if err != nil {
		t.Fatal(err)
	}
	orgs, err := auth.PluginOf[*organization.Plugin](env.Auth)
	if err != nil {
		t.Fatal(err)
	}
	return &app{env: env, orgs: orgs, f: orgtest.New(env), h: h}
}

// projectNames lists an organization's project names straight from the table.
func (a *app) projectNames(t *testing.T, orgID string) []string {
	t.Helper()
	ps, err := listProjects(context.Background(), a.env.Auth, orgID)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Name)
	}
	return names
}

// TestOrgWorkspace_CreateOverHTTPStartsWithAProject: an organization created
// through the library's own route gets the app's default project from the
// hook, in the same transaction, and an admin adds more.
func TestOrgWorkspace_CreateOverHTTPStartsWithAProject(t *testing.T) {
	a := newApp(t)
	alice := a.env.CreateUser("Alice", authtest.Identity{Kind: email.KindEmail, Value: "alice@example.com"})
	b := a.env.Browser(a.h)
	b.SetSession(a.env.SignIn(alice.ID))

	var org organization.Org
	b.Post("/auth/organization/create", map[string]string{"name": "Acme", "slug": "acme"}).Expect(http.StatusOK).Decode(&org)

	var list listResponse
	b.Get("/orgs/" + org.ID + "/projects").Expect(http.StatusOK).Decode(&list)
	if len(list.Projects) != 1 || list.Projects[0].Name != defaultProject {
		t.Fatalf("a new organization's projects = %+v, want only %q", list.Projects, defaultProject)
	}

	b.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "Roadmap"}).Expect(http.StatusCreated)
	if code := b.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "Roadmap"}).Expect(http.StatusConflict).ErrorCode(); code != errProjectTaken.Code {
		t.Fatalf("a duplicate project: %q", code)
	}
	if code := b.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "  "}).Expect(http.StatusBadRequest).ErrorCode(); code != errProjectName.Code {
		t.Fatalf("a blank name: %q", code)
	}
	if got := a.projectNames(t, org.ID); !slices.Equal(got, []string{defaultProject, "Roadmap"}) {
		t.Fatalf("projects = %v", got)
	}
}

// TestOrgWorkspace_CrossSitePostIsRefused: the app's own POST route checks
// the origin, because the session cookie would be sent from any site.
func TestOrgWorkspace_CrossSitePostIsRefused(t *testing.T) {
	a := newApp(t)
	owner := a.env.CreateUser("Alice")
	org := a.f.SaveOrganization(a.f.NewOrganization(owner.ID, "Acme"))
	b := a.env.Browser(a.h)
	b.SetSession(a.env.SignIn(owner.ID))

	req, err := http.NewRequest(http.MethodPost, b.URL()+"/orgs/"+org.ID+"/projects", strings.NewReader(`{"name":"Evil"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	if code := b.Do(req).Expect(http.StatusForbidden).ErrorCode(); code != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("a cross-site POST: %q", code)
	}
	if got := a.projectNames(t, org.ID); !slices.Equal(got, []string{defaultProject}) {
		t.Fatalf("projects after a refused POST = %v", got)
	}
}

// TestOrgWorkspace_RolesGuardTheData builds the organization with orgtest
// instead of the HTTP flow (the fixtures run CreateFor and AddMember, so the
// hook still adds the default project): a member reads but cannot create,
// and a stranger cannot tell the organization exists.
//
//ds:def id=orgworkspace-fixtures-3m9xw5kd
func TestOrgWorkspace_RolesGuardTheData(t *testing.T) {
	a := newApp(t)
	alice, bob, eve := a.env.CreateUser("Alice"), a.env.CreateUser("Bob"), a.env.CreateUser("Eve")
	fix := a.f.NewOrganization(alice.ID, "Acme")
	fix.Members = []orgtest.Member{{UserID: bob.ID, Role: organization.RoleMember}}
	org := a.f.SaveOrganization(fix)

	asBob := a.env.Browser(a.h)
	asBob.SetSession(a.env.SignIn(bob.ID))
	var list listResponse
	asBob.Get("/orgs/" + org.ID + "/projects").Expect(http.StatusOK).Decode(&list)
	if len(list.Projects) != 1 || list.Projects[0].Name != defaultProject {
		t.Fatalf("a fixture organization's projects = %+v", list.Projects)
	}
	if code := asBob.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "Roadmap"}).Expect(http.StatusForbidden).ErrorCode(); code != organization.ErrForbidden.Code {
		t.Fatalf("a member creating: %q", code)
	}

	asEve := a.env.Browser(a.h)
	asEve.SetSession(a.env.SignIn(eve.ID))
	if code := asEve.Get("/orgs/" + org.ID + "/projects").Expect(http.StatusNotFound).ErrorCode(); code != organization.ErrNotMember.Code {
		t.Fatalf("a stranger reading: %q", code)
	}

	// Adding Eve as an admin with the fixture lets her create.
	a.f.AddMember(org.ID, eve.ID, organization.RoleAdmin)
	asEve.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "Roadmap"}).Expect(http.StatusCreated)
}

// TestOrgWorkspace_DeleteTakesTheProjects: deleting the organization over
// HTTP removes its projects in the same transaction, and leaves another
// organization's alone.
func TestOrgWorkspace_DeleteTakesTheProjects(t *testing.T) {
	a := newApp(t)
	alice := a.env.CreateUser("Alice")
	gone := a.f.SaveOrganization(a.f.NewOrganization(alice.ID, "Gone"))
	kept := a.f.SaveOrganization(a.f.NewOrganization(alice.ID, "Kept"))

	b := a.env.Browser(a.h)
	b.SetSession(a.env.SignIn(alice.ID))
	b.Post("/auth/organization/delete", map[string]string{"orgId": gone.ID}).Expect(http.StatusOK)

	if got := a.projectNames(t, gone.ID); len(got) != 0 {
		t.Fatalf("a deleted organization still has projects %v", got)
	}
	if got := a.projectNames(t, kept.ID); !slices.Equal(got, []string{defaultProject}) {
		t.Fatalf("the other organization's projects = %v", got)
	}
}

// TestOrgWorkspace_ImportIsAllOrNothing: an import whose projects can all be
// written creates the organization with them; one whose project collides
// with the default leaves neither the organization nor any project.
func TestOrgWorkspace_ImportIsAllOrNothing(t *testing.T) {
	a := newApp(t)
	ctx := context.Background()
	alice := a.env.CreateUser("Alice")

	org, err := importWorkspace(ctx, a.env.Auth, a.orgs, ImportRequest{OwnerID: alice.ID, Name: "Acme", Slug: "acme", Projects: []string{"Roadmap", "Docs"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.projectNames(t, org.ID); !slices.Equal(got, []string{"Docs", defaultProject, "Roadmap"}) {
		t.Fatalf("imported projects = %v", got)
	}

	_, err = importWorkspace(ctx, a.env.Auth, a.orgs, ImportRequest{OwnerID: alice.ID, Name: "Globex", Slug: "globex", Projects: []string{defaultProject}})
	if !errors.Is(err, errProjectTaken) {
		t.Fatalf("a colliding import: %v, want %v", err, errProjectTaken)
	}
	all, err := a.orgs.ListAll(ctx, organization.AllOrgsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 1 || all.Orgs[0].Slug != "acme" {
		t.Fatalf("organizations after a failed import = %+v, want acme only", all.Orgs)
	}
	var orphans int
	if err := a.env.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM project WHERE org_id <> ?`, org.ID).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Fatalf("%d projects survived the rolled-back import", orphans)
	}
}

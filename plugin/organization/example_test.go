package organization_test

import (
	"fmt"
	"net/http"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/organization"
)

// ExampleWithRoles adds an app resource and a role of its own beside the
// built-in ones.
// ds:def id=examplewithroles-unstje3r owner=@khanakia stability=stable
func ExampleWithRoles() {
	s := access.Statements{"project": {"create", "share"}}
	for k, v := range organization.DefaultStatements {
		s[k] = v
	}
	ac := access.MustNew(s)
	billing := ac.MustRole(access.Permissions{"project": {"create"}, organization.ResourceInvitation: {organization.ActionCreate}})
	org := organization.New(organization.WithAccessControl(ac), organization.WithRoles(map[organization.Role]access.Role{"billing": billing}))
	fmt.Println(org.Name(), billing.Allows(access.Request{"project": access.All("create")}))
	// Output: organization true
}

// ExamplePlugin_RequirePermission guards an app route by permission rather
// than by role.
// ds:def id=exampleplugin-requirepermission-ph8srha8 owner=@khanakia stability=stable
func ExamplePlugin_RequirePermission() {
	orgs := organization.New()
	orgInPath := func(r *http.Request) string { return r.PathValue("org") }
	createProject := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	mux := http.NewServeMux()
	// Inside authhttp.Middleware in a real app.
	mux.Handle("POST /orgs/{org}/projects", orgs.RequirePermission(orgInPath, access.Request{"project": access.All("create")})(createProject))
	fmt.Println("mounted")
	// Output: mounted
}

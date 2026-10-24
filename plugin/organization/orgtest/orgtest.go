// Package orgtest is the organization counterpart of authtest's user
// factory: build an organization in memory, then save it through the
// plugin's real Go API so every rule and hook runs.
//
// It lives in the organization module, not in authtest, because the core
// module cannot import the organization plugin. Like authtest it imports no
// database driver: the test that uses it imports its own.
package orgtest

import (
	"context"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/organization"
)

// DefaultOrgName is the name NewOrganization gives when the test passes
// none.
const DefaultOrgName = "Test Organization"

// slugPrefix starts every generated slug; the rest is random, so two
// organizations built in one test never share a slug.
const slugPrefix = "test-org-"

// slugRandom is how many characters of a generated id the slug keeps: enough
// that two slugs in one test do not collide, short enough for SlugPattern's
// 48 characters.
const slugRandom = 12

// Factory builds and saves organizations for one authtest.Env.
type Factory struct {
	env    *authtest.Env
	plugin *organization.Plugin
}

// New returns the factory for env, whose Auth must have the organization
// plugin wired; a missing plugin fails the test.
func New(env *authtest.Env) *Factory {
	env.T.Helper()
	p, err := auth.PluginOf[*organization.Plugin](env.Auth)
	if err != nil {
		env.T.Fatalf("orgtest: %v", err)
	}
	return &Factory{env: env, plugin: p}
}

// Member is one membership an OrgFixture is saved with.
type Member struct {
	UserID string
	Role   organization.Role
}

// OrgFixture is an organization not yet saved. OwnerID is the user who
// creates it and becomes its creator-role member; Members are added after,
// each with its role.
type OrgFixture struct {
	Name     string
	Slug     string
	OwnerID  string
	Logo     *string
	Metadata auth.AppData
	Members  []Member
}

// NewOrganization builds an OrgFixture without touching the database:
// DefaultOrgName unless the test passes a name, a random slug that fits
// organization.SlugPattern, and ownerID as its creator. The organization's id
// is given by the plugin at SaveOrganization, as for any organization.
func (f *Factory) NewOrganization(ownerID, name string) OrgFixture {
	f.env.T.Helper()
	if name == "" {
		name = DefaultOrgName
	}
	id, err := f.env.Auth.NewID("")
	if err != nil {
		f.env.T.Fatalf("orgtest: slug: %v", err)
	}
	id = strings.ToLower(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, id))
	return OrgFixture{Name: name, Slug: slugPrefix + id[max(0, len(id)-slugRandom):], OwnerID: ownerID}
}

// SaveOrganization creates f through the plugin (CreateFor, then AddMember
// for each member), so slug, role and limit rules and every hook run, and
// returns the stored organization. Any refusal fails the test.
func (f *Factory) SaveOrganization(o OrgFixture) organization.Org {
	f.env.T.Helper()
	ctx := context.Background()
	org, err := f.plugin.CreateFor(ctx, o.OwnerID, organization.CreateRequest{Name: o.Name, Slug: o.Slug, Logo: o.Logo, Metadata: o.Metadata})
	if err != nil {
		f.env.T.Fatalf("orgtest: save organization %q: %v", o.Slug, err)
	}
	for _, m := range o.Members {
		f.AddMember(org.ID, m.UserID, m.Role)
	}
	return org
}

// AddMember adds userID to orgID with role through the plugin's AddMember;
// a refusal fails the test.
func (f *Factory) AddMember(orgID, userID string, role organization.Role) {
	f.env.T.Helper()
	if err := f.plugin.AddMember(context.Background(), orgID, userID, role); err != nil {
		f.env.T.Fatalf("orgtest: add %s to %s as %s: %v", userID, orgID, role, err)
	}
}

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/organization"
)

// world is a migrated database holding the users import-users would have
// brought in, with their source ids.
type world struct {
	a   *auth.Auth
	org *organization.Plugin
	ad  *admin.Plugin
}

func newWorld(t *testing.T, userIDs ...string) *world {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), dbFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	w := &world{}
	if w.a, w.org, w.ad, err = newAuth(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.a.Close() })
	ctx := context.Background()
	if _, err := w.a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	users := make([]auth.ImportUser, 0, len(userIDs))
	for _, id := range userIDs {
		users = append(users, auth.ImportUser{ID: id, Name: id})
	}
	res, err := w.a.ImportUsers(ctx, users)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	return w
}

func (w *world) role(t *testing.T, orgID, userID string) organization.Role {
	t.Helper()
	r, err := w.org.RoleOf(context.Background(), orgID, userID)
	if err != nil {
		t.Fatalf("role of %s in %s: %v", userID, orgID, err)
	}
	return r
}

// TestImportOrgs_Auth0 imports the Auth0 fixture: acme lands with its Owner,
// Admin and an unmapped role noted as member; globex names a member who was
// never imported, so it fails whole and leaves no organization behind; the
// tenant role "Admin" becomes the admin plugin's admin role, "Support" does
// not. A second run changes nothing.
func TestImportOrgs_Auth0(t *testing.T) {
	w := newWorld(t, "auth0|5f1a2b3c4d5e6f7a8b9c0d1e", "github|8675309", "auth0|blocked0001")
	ctx := context.Background()
	orgs := mustRead(t, "testdata/auth0-orgs.json", func(f *os.File) ([]org, error) { return readOrgs(sourceAuth0, f) })

	res := importOrgs(ctx, w.a, w.org, sourceAuth0, orgs)
	acme, globex := res[0], res[1]
	if acme.Err != nil {
		t.Fatalf("acme: %v", acme.Err)
	}
	for user, want := range map[string]organization.Role{"auth0|5f1a2b3c4d5e6f7a8b9c0d1e": organization.RoleOwner, "github|8675309": organization.RoleAdmin, "auth0|blocked0001": organization.RoleMember} {
		if got := w.role(t, acme.ID, user); got != want {
			t.Fatalf("%s in acme is %s, want %s", user, got, want)
		}
	}
	if len(acme.Notes) != 1 {
		t.Fatalf("acme notes = %v, want the unmapped Billing Viewer role", acme.Notes)
	}
	if globex.Err == nil || globex.ID == "" {
		t.Fatalf("globex with a member who was not imported: id %q, err %v", globex.ID, globex.Err)
	}
	if _, err := w.org.RoleOf(ctx, globex.ID, "github|8675309"); !errors.Is(err, organization.ErrNotMember) {
		t.Fatalf("the failed organization left a membership behind: %v", err)
	}

	grants := mustRead(t, "testdata/auth0-roles.json", func(f *os.File) (map[string][]string, error) { return readAuth0Roles(f, []string{"admin"}) })
	if errs := importAdminRoles(ctx, w.ad, grants); len(errs) != 0 {
		t.Fatal(errs)
	}
	for user, want := range map[string]bool{"auth0|5f1a2b3c4d5e6f7a8b9c0d1e": true, "github|8675309": false} {
		roles, err := w.ad.RolesOf(ctx, user)
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(roles, admin.RoleAdmin); got != want {
			t.Fatalf("%s admin = %v (roles %v), want %v", user, got, roles, want)
		}
	}

	for _, r := range importOrgs(ctx, w.a, w.org, sourceAuth0, orgs[:1]) {
		if !errors.Is(r.Err, organization.ErrSlugTaken) {
			t.Fatalf("second run of %s: %v, want the slug taken", r.Org.Slug, r.Err)
		}
	}
}

// TestImportOrgs_Clerk: Clerk has no owner role, so the creator becomes the
// owner (with a note), and a custom role is a member with a note.
func TestImportOrgs_Clerk(t *testing.T) {
	w := newWorld(t, "user_2abc", "user_2def")
	orgs := mustRead(t, "testdata/clerk-orgs.json", func(f *os.File) ([]org, error) { return readOrgs(sourceClerk, f) })
	res := importOrgs(context.Background(), w.a, w.org, sourceClerk, orgs)
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	for user, want := range map[string]organization.Role{"user_2def": organization.RoleOwner, "user_2abc": organization.RoleMember} {
		if got := w.role(t, res[0].ID, user); got != want {
			t.Fatalf("%s is %s, want %s", user, got, want)
		}
	}
	if len(res[0].Notes) != 2 {
		t.Fatalf("notes = %v, want the creator's promotion and the custom role", res[0].Notes)
	}
}

func mustRead[T any](t *testing.T, path string, read func(*os.File) (T, error)) T {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v, err := read(f)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

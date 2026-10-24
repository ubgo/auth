// Command import-orgs loads organizations, their members and their roles
// from an Auth0 or Clerk export into plugin/organization, and Auth0's tenant
// roles into plugin/admin, after import-users has brought the users in with
// their ids kept. Each organization is one transaction: one that fails
// (a slug already taken, a member who was not imported) leaves nothing
// behind and is listed; the rest land.
//
//	go run ./import-orgs -source auth0 -file orgs.json -roles roles.json -admin-role Admin -db app.db
//	go run ./import-orgs -source clerk -file orgs.json -db app.db -dry-run
//
// The program wires the plugins the import needs; in your app, call
// importOrgs and importAdminRoles with your own auth.New so your hooks apply.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// baseURL is the app's public URL; nothing is served here, but auth.New
	// wants one for the links the email plugin would build.
	baseURL = "http://localhost:8081"
	// dbFile is the SQLite database the import writes; -db changes it.
	dbFile = "import.db"
)

// The sources this program reads.
const (
	sourceAuth0 = "auth0"
	sourceClerk = "clerk"
)

// org is one organization in the shape every source is read into.
type org struct {
	// SourceID is the other system's id, kept in the organization's
	// metadata, since the organization plugin makes its own ids.
	SourceID string
	Name     string
	Slug     string
	// CreatorID is the user who becomes the owner; empty picks the
	// highest-ranked member.
	CreatorID string
	Members   []member
}

// member is one membership with its role already mapped.
type member struct {
	UserID string
	Role   organization.Role
	// Note says why the role is not the source's, for the summary.
	Note string
}

// importedFrom is what each organization's metadata records.
type importedFrom struct {
	Source   string `json:"importedFrom"`
	SourceID string `json:"sourceId"`
}

// orgResult is the outcome for one organization.
type orgResult struct {
	Org   org
	ID    string
	Err   error
	Notes []string
}

func main() {
	source := flag.String("source", "", "auth0 or clerk")
	file := flag.String("file", "", "the organizations file (see the README for its shape)")
	rolesFile := flag.String("roles", "", "auth0 only: the tenant roles file, each role with its users")
	adminRoles := flag.String("admin-role", "", "auth0 only: comma-separated tenant role names that become the admin role")
	dbPath := flag.String("db", dbFile, "the SQLite database to write")
	dryRun := flag.Bool("dry-run", false, "read and map everything, print the plan, write nothing")
	flag.Parse()

	orgs, err := readFile(*file, func(r io.Reader) ([]org, error) { return readOrgs(*source, r) })
	if err != nil {
		log.Fatal(err)
	}
	var grants map[string][]string
	if *rolesFile != "" {
		if grants, err = readFile(*rolesFile, func(r io.Reader) (map[string][]string, error) { return readAuth0Roles(r, splitList(*adminRoles)) }); err != nil {
			log.Fatal(err)
		}
	}
	if *dryRun {
		printPlan(os.Stdout, orgs, grants)
		return
	}

	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: *dbPath}).EscapedPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	a, op, ad, err := newAuth(db)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	results := importOrgs(ctx, a, op, *source, orgs)
	failed := printSummary(os.Stdout, results)
	if len(grants) > 0 {
		errs := importAdminRoles(ctx, ad, grants)
		fmt.Fprintf(os.Stdout, "set the admin role on %d user(s), %d failed\n", len(grants)-len(errs), len(errs))
		for _, e := range errs {
			failed++
			fmt.Fprintf(os.Stdout, "  FAILED admin role: %v\n", e)
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// newAuth wires the plugins the import writes through: email (the
// organization plugin requires it), organization and admin, and password,
// since auth.New refuses a configuration nobody could sign in with.
func newAuth(db *sql.DB) (*auth.Auth, *organization.Plugin, *admin.Plugin, error) {
	orgs, ad := organization.New(), admin.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(noMail{})), password.New(), orgs, ad),
	)
	return a, orgs, ad, err
}

// importOrgs creates each organization for its creator, who becomes the
// owner, and adds every other member with their mapped role, in one
// transaction per organization: CreateFor and AddMember join it, so a member
// who does not exist, or a slug already taken, rolls back that whole
// organization and nothing else. Running it twice fails every organization
// already imported on its slug and changes nothing.
//
//ds:def id=importorgs-6v2kq9wd
func importOrgs(ctx context.Context, a *auth.Auth, orgs *organization.Plugin, source string, in []org) []orgResult {
	out := make([]orgResult, 0, len(in))
	for _, o := range in {
		res := orgResult{Org: o}
		creator := pickCreator(o)
		meta, _ := json.Marshal(importedFrom{Source: source, SourceID: o.SourceID}) // two strings always encode
		res.Err = a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			created, err := orgs.CreateFor(ctx, creator, organization.CreateRequest{Name: o.Name, Slug: o.Slug, Metadata: meta})
			if err != nil {
				return fmt.Errorf("create: %w", err)
			}
			res.ID = created.ID
			for _, m := range o.Members {
				if m.UserID == creator {
					continue
				}
				if err := orgs.AddMember(ctx, created.ID, m.UserID, m.Role); err != nil {
					return fmt.Errorf("member %s: %w", m.UserID, err)
				}
			}
			return nil
		})
		for _, m := range o.Members {
			switch {
			case m.UserID == creator && m.Role != organization.RoleOwner:
				res.Notes = append(res.Notes, fmt.Sprintf("%s is the owner (was %s): an organization starts with its creator as owner", m.UserID, m.Role))
			case m.Note != "":
				res.Notes = append(res.Notes, m.UserID+": "+m.Note)
			}
		}
		out = append(out, res)
	}
	return out
}

// pickCreator is the source's creator when they are a member, else the
// first member of the highest rank.
func pickCreator(o org) string {
	best, rank := "", -1
	for _, m := range o.Members {
		if m.UserID == o.CreatorID {
			return m.UserID
		}
		if r := m.Role.Rank(); r > rank {
			best, rank = m.UserID, r
		}
	}
	return best
}

// importAdminRoles gives each user the admin plugin's admin role when one of
// their tenant roles maps to it. A role an app defines itself (admin.WithAuthorizer)
// is mapped the same way: pass its name instead of admin.RoleAdmin.
//
//ds:def id=importadminroles-3h8nw5tc
func importAdminRoles(ctx context.Context, ad *admin.Plugin, grants map[string][]string) []error {
	var errs []error
	for userID, roles := range grants {
		if err := ad.SetRoleFor(ctx, userID, roles...); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", userID, err))
		}
	}
	return errs
}

// readOrgs reads the organizations file of source.
func readOrgs(source string, r io.Reader) ([]org, error) {
	switch source {
	case sourceAuth0:
		return readAuth0(r)
	case sourceClerk:
		return readClerk(r)
	default:
		return nil, fmt.Errorf("-source %q: want %s or %s", source, sourceAuth0, sourceClerk)
	}
}

// readFile opens path and hands it to read.
func readFile[T any](path string, read func(io.Reader) (T, error)) (T, error) {
	var zero T
	if path == "" {
		return zero, errors.New("-file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	return read(f)
}

// splitList splits a comma-separated flag, dropping empty entries.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// printPlan prints what an import would do.
func printPlan(w io.Writer, orgs []org, grants map[string][]string) {
	fmt.Fprintf(w, "would import %d organization(s)\n", len(orgs))
	for _, o := range orgs {
		fmt.Fprintf(w, "  %s (%s): owner %s, %d member(s)\n", o.Slug, o.SourceID, pickCreator(o), len(o.Members))
		for _, m := range o.Members {
			if m.Note != "" {
				fmt.Fprintf(w, "    note %s: %s\n", m.UserID, m.Note)
			}
		}
	}
	if len(grants) > 0 {
		fmt.Fprintf(w, "would set the admin role on %d user(s)\n", len(grants))
	}
}

// printSummary prints the outcome and returns how many failed.
func printSummary(w io.Writer, results []orgResult) int {
	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
		}
	}
	fmt.Fprintf(w, "imported %d organization(s), %d failed\n", len(results)-failed, failed)
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(w, "  FAILED %s: %v\n", r.Org.Slug, r.Err)
			continue
		}
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note   %s: %s\n", r.Org.Slug, n)
		}
	}
	return failed
}

// noMail is the email plugin's mailer during an import: nothing here sends
// mail, and an attempt is an error rather than a message to a real user.
type noMail struct{}

// Send refuses.
func (noMail) Send(context.Context, email.Mail) error {
	return errors.New("import-orgs sends no mail")
}

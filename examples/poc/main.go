// Command poc wires the auth core with every plugin and prints what the
// composition produces: the routes, the migrations for each engine and the
// composite user query.
//
// It touches no database. The point is to show that the plugin set, the
// routes, the schema, the column list and the scan targets are all decided at
// compile time and start-up, and can be inspected before a single row exists.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// AppUser is the application's composite user.
//
// This declaration is the price Go charges for a user shape that depends on the
// enabled plugin set: the language cannot compute a struct type from a runtime
// list, so the application states the composition once. In exchange the
// compiler verifies every column and every scan target, and one statement
// fetches all of it.
//
// # Flat or nested follows the schema, not the cardinality
//
// auth.User is embedded because its fields ARE columns of auth_user: they
// survive with no join at all, so they belong to the user directly. Every
// plugin's contribution is a named field because it comes from a different
// table, whether the core owns that table (auth_identity) or the plugin does
// (auth_org_member). One join, one nested struct.
//
// This is the rule an ORM already applies and the reason it is worth copying:
// the Go shape then tells you what the SQL does. Flattening a joined table into
// the user would hide which fields cost a join, which can be null because a
// LEFT join missed, and which a schema change would have to touch.
//
// Cardinality is a separate axis. Everything here is one-to-one because each
// join is filtered to a single row — the PRIMARY phone, the role in ONE named
// organization. A genuine one-to-many, such as every identity a user owns, can
// only be a slice filled by its own query; step 2b below shows one.
type AppUser struct {
	// Embedded: these are COLUMNS ON auth_user, so they are flat fields of the
	// user exactly as the schema has them: u.ID, u.Name from the core, and
	// u.PrimaryEmail from the column the email plugin adds to auth_user.
	auth.User
	email.EmailColumns

	// Nested: each of these is a SEPARATE TABLE reached by a join, so it gets
	// its own struct rather than being flattened into the user. Same rule an
	// ORM applies — a column is a field, another table is an edge.
	//
	//  Phone, Username -> auth_identity  (a table the core owns)
	//  Membership      -> auth_org_member (a table the plugin owns)
	//
	// Read as u.Phone.Number, u.Username.Handle, u.Membership.Role. The extra
	// selector is what tells a reader which fields cost a join and which ones
	// can be absent because that join missed.
	Phone      phone.Data
	Username   username.Data
	Membership organization.UserMembership

	// orgID parameterises the membership join. A membership only exists
	// relative to an organization, so unlike phone or username this plugin's
	// join needs an argument, and the destination is where it lives.
	orgID string
}

// Joins returns the plugin joins this destination needs. The core user table is
// the driving table and never appears here.
func (u *AppUser) Joins() []sqlb.Join {
	return []sqlb.Join{
		phone.UserJoin(),               // borrows a core table under alias "phi"
		username.UserJoin(),            // borrows the same core table under "uni"
		organization.UserJoin(u.orgID), // joins a table the plugin owns
	}
}

// Bindings returns every column bound to a field of this destination.
//
// Order is the SELECT order and therefore the scan order. It cannot desync from
// the column list because both are derived from this one slice.
func (u *AppUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(
		auth.UserBindings(&u.User),
		email.Bindings(&u.EmailColumns),
		phone.UserBindings(&u.Phone),
		username.UserBindings(&u.Username),
		organization.UserBindings(&u.Membership),
	)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// plugins is the one list that answers "what can sign a user in".
func plugins() []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(mailStub{})),
		phone.New(phone.Login(), phone.SignInWithCode(), phone.WithSMS(smsStub{})),
		username.New(username.Login(), username.Reserved("khanakia", "ubgo")),
		password.New(),
		oauth.New(oauth.WithProviders(oauth.Google("client-id", "client-secret"), oauth.GitHub("client-id", "client-secret"))),
		organization.New(),
	}
}

func run() error {
	a, err := auth.New(
		auth.WithDialect(sqlb.PostgresDialect{}),
		auth.WithBaseURL("https://app.example.com"),
		auth.WithPlugins(plugins()...),
	)
	if err != nil {
		return err
	}

	names := make([]string, 0, len(a.Plugins()))
	for _, p := range a.Plugins() {
		names = append(names, p.Name())
	}
	fmt.Printf("wired plugins: %s\n", strings.Join(names, ", "))

	fmt.Println("\n=== routes, from the operation list (mounted under /auth) ===")
	for _, op := range a.Operations() {
		method := "POST"
		if op.Info().Kind == auth.Query {
			method = "GET "
		}
		fmt.Printf("  %s /auth%-32s %-26s %s\n", method, op.Route(), op.Info().ID, op.Info().Require)
	}

	for _, d := range []sqlb.Dialect{sqlb.PostgresDialect{}, sqlb.MySQLDialect{}, sqlb.SQLiteDialect{}} {
		e, err := auth.New(auth.WithDialect(d), auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(plugins()...))
		if err != nil {
			return err
		}
		ms, err := e.Migrations()
		if err != nil {
			return err
		}
		fmt.Printf("\n=== migrations on %s: %d ===\n", e.Engine(), len(ms))
		for _, m := range ms {
			fmt.Printf("  %-14s %s\n", m.Owner, m.Name)
		}
	}
	script, err := a.MigrationSQL()
	if err != nil {
		return err
	}
	fmt.Println("\n=== the identity indexes on Postgres ===")
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "UNIQUE INDEX") {
			fmt.Println("  " + line)
		}
	}

	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

	appUser := AppUser{orgID: "org_42"}
	q := a.Select().Columns(appUser.Bindings()...).From(auth.TableUser).Join(appUser.Joins()...)
	built, err := q.Where(sqlb.Eq(auth.UserID, "usr_123")).Limit(1).Build()
	if err != nil {
		return err
	}
	show("1. composite user: core + plugin columns + 3 plugin joins, ONE statement", built)
	fmt.Println("  shape follows the schema, like an ORM:")
	fmt.Println("    u.ID, u.PrimaryEmail       flat   - columns ON auth_user")
	fmt.Println("    u.Phone.Number             nested - joined from auth_identity")
	fmt.Println("    u.Username.Handle          nested - joined from auth_identity")
	fmt.Println("    u.Membership.Role          nested - joined from auth_org_member")

	var member organization.Member
	built, err = organization.MembersQuery(a, "org_42", &member)
	if err != nil {
		return err
	}
	show("2. plugin joins BACK into core: org members", built)

	var invite organization.Invite
	built, err = organization.PendingInvitesQuery(a, "usr_123", now, &invite)
	if err != nil {
		return err
	}
	show("3. pending invites - note the verified_at IS NOT NULL guard", built)

	var phoneData phone.Data
	built, err = phone.Of(a, "usr_123", &phoneData)
	if err != nil {
		return err
	}
	show("4. accessor form: just the phone, one small table", built)

	return demonstrateWiringGuards()
}

// demonstrateWiringGuards shows misconfigurations that fail at start-up rather
// than in production.
func demonstrateWiringGuards() error {
	fmt.Println("\n=== wiring guards: these all fail at New, not at runtime ===")
	base := auth.WithBaseURL("https://app.example.com")
	cases := []struct {
		name string
		opts []auth.Option
	}{
		{"no sign-in method at all", []auth.Option{base, auth.WithPlugins(email.New(email.Login(), email.WithMailer(mailStub{})))}},
		{"password with only a contact-only email: nobody can type a sign-in identifier", []auth.Option{base, auth.WithPlugins(
			email.New(email.Contact(), email.WithMailer(mailStub{})), password.New(password.WithoutRecovery()))}},
		{"username only: nothing can recover an account", []auth.Option{base, auth.WithPlugins(username.New(username.Login()), password.New())}},
		{"organization without the email plugin", []auth.Option{base, auth.WithPlugins(
			username.New(username.Login()), password.New(password.WithoutRecovery()), organization.New())}},
		{"two plugins claiming the same table alias", []auth.Option{base, auth.WithPlugins(
			username.New(username.Login()), password.New(password.WithoutRecovery()), clashingPlugin{})}},
	}
	for _, c := range cases {
		if _, err := auth.New(c.opts...); err != nil {
			fmt.Printf("  refused: %s\n      %v\n", c.name, err)
			continue
		}
		return fmt.Errorf("guard did not fire for %q", c.name)
	}
	return nil
}

// clashingPlugin deliberately reuses the password plugin's alias to prove the
// collision is caught at wire time.
type clashingPlugin struct{}

func (clashingPlugin) Name() string { return "clashing" }
func (clashingPlugin) Tables() []sqlb.Table {
	return []sqlb.Table{{Name: "other_table", Alias: password.TableAliasPassword}}
}

// smsStub and mailStub satisfy the delivery interfaces without sending
// anything, so the example can wire valid plugins. They are not production
// stand-ins.
type smsStub struct{}

func (smsStub) Send(context.Context, string, string) error { return nil }

type mailStub struct{}

func (mailStub) Send(context.Context, email.Mail) error { return nil }

// show prints a query with its bind values and scan-target count.
func show(title string, q sqlb.Query) {
	fmt.Printf("\n=== %s ===\n%s\n", title, wrap(q.SQL))
	fmt.Printf("  args:    %v\n", q.Args)
	fmt.Printf("  targets: %d scan destinations, in SELECT order\n", len(q.Targets))
}

// wrap breaks a statement at SQL keywords so long joins stay readable in a
// terminal. Cosmetic only; the generated SQL is a single line.
func wrap(sql string) string {
	for _, kw := range []string{" FROM ", " INNER JOIN ", " LEFT JOIN ", " WHERE ", " ORDER BY ", " LIMIT ", " OFFSET "} {
		sql = strings.ReplaceAll(sql, kw, "\n  "+strings.TrimSpace(kw)+" ")
	}
	return sql
}

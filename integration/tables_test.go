package integration

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// The real names TestTables_RenameTableEndToEnd gives three tables. They start
// with "app_", one of testTablePrefixes, so the harness resets them.
const (
	renamedUsers     = "app_members"
	renamedPasswords = "app_passwords"
	renamedLedger    = "app_schema_log"
	// renamePrefix is the prefix every other table takes in that test.
	renamePrefix = "app_"
)

// listTables returns every table of the current database or schema.
func listTables(t *testing.T, e *env) []string {
	t.Helper()
	var q string
	switch e.engine {
	case auth.EnginePostgres:
		q = postgresTablesQuery
	case auth.EngineMySQL:
		q = mysqlTablesQuery
	default:
		q = "SELECT name FROM sqlite_master WHERE type = 'table'"
	}
	rows, err := e.db.QueryContext(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// TestTables_RenameTableEndToEnd: an app renames three tables and prefixes the
// rest, migrates, signs up, signs in, runs a plugin query and the session
// join, reads with raw SQL through a.TableName, and every maintenance surface
// (schema check, orphans, sweep, the CLI) sees the real names. No label
// reaches the database.
func TestTables_RenameTableEndToEnd(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("orders:read"))
		a, err := auth.New(
			auth.WithDB(e.db, e.d), auth.WithBaseURL(testBaseURL), auth.WithClock(e.clock.Now), auth.WithDBRateStore(),
			auth.WithTablePrefix(renamePrefix),
			auth.RenameTable(auth.TableUser, renamedUsers),
			auth.RenameTable(password.TablePassword, renamedPasswords),
			auth.RenameTable(auth.TableMigrations, renamedLedger),
			auth.WithPlugins(em, pw, ak),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		ctx := context.Background()
		if _, err := a.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		// Every table has its real name and no table has a label.
		live := listTables(t, e)
		for _, want := range []string{renamedUsers, renamedPasswords, renamedLedger, renamePrefix + auth.TableNameIdentity,
			renamePrefix + auth.TableNameSession, renamePrefix + auth.TableNameVerification, renamePrefix + auth.TableNameCode,
			renamePrefix + auth.TableNameRateLimit, renamePrefix + apikey.TableNameKey} {
			if !slices.Contains(live, want) {
				t.Errorf("table %s missing; have %v", want, live)
			}
		}
		for _, label := range []string{auth.TableNameUser, auth.TableNameIdentity, auth.TableNameMigrations, password.TableNamePassword, apikey.TableNameKey} {
			if slices.Contains(live, label) {
				t.Errorf("label %s reached the database", label)
			}
		}
		if got := a.TableName(auth.TableUser); got != renamedUsers {
			t.Fatalf("TableName(user) = %q", got)
		}

		// Sign up, verify, sign in: the identity index, the password table and
		// the session table all work under their real names.
		up := signUpVerified(t, e, a, pw, em)
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if in.User.ID != up.User.ID {
			t.Fatalf("signed in as %s, signed up as %s", in.User.ID, up.User.ID)
		}
		// The session lookup joins the session and user tables.
		sctx := request(a, in.Token)
		if err := a.Resolve(sctx); err != nil {
			t.Fatal(err)
		}
		if u, ok := auth.CurrentUser(sctx); !ok || u.ID != up.User.ID {
			t.Fatalf("current user = %+v %v", u, ok)
		}
		// A plugin query on a prefixed plugin table, with the user join the
		// list makes.
		made := must[apikey.CreateResult](t)(ak.Create(sctx, apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:read"}}))
		if keys := must[[]apikey.Key](t)(ak.List(sctx)); len(keys) != 1 || keys[0].ID != made.Key.ID {
			t.Fatalf("keys = %+v", keys)
		}
		// Raw SQL the way an app writes it, through TableName.
		var n int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + a.TableName(auth.TableUser)).Scan(&n); err != nil || n != 1 {
			t.Fatalf("count members = %d %v", n, err)
		}
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + a.TableName(password.TablePassword)).Scan(&n); err != nil || n != 1 {
			t.Fatalf("count passwords = %d %v", n, err)
		}
		// A hand-built join through a.Select renders the real names too.
		var count int64
		q := a.Select().Columns(sqlb.Bind(sqlb.Count(), &count)).From(auth.TableUser).
			Join(sqlb.Join{Type: sqlb.JoinInner, Table: password.TablePassword, On: []sqlb.Predicate{sqlb.EqExpr(password.UserID, auth.UserID)}})
		if err := a.One(ctx, q); err != nil || count != 1 {
			t.Fatalf("join = %d %v", count, err)
		}

		// Maintenance surfaces.
		if r := must[auth.SchemaReport](t)(a.CheckSchema(ctx)); !r.OK() {
			t.Fatalf("schema: %s", r.Error())
		}
		if orphans := must[[]auth.Orphan](t)(a.Orphans(ctx)); len(orphans) != 0 {
			t.Fatalf("orphans = %+v", orphans)
		}
		if _, err := a.Sweep(ctx, time.Hour); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		run := func(args ...string) string {
			var out, errb bytes.Buffer
			if code := authcli.Main(ctx, a, args, &out, &errb); code != authcli.ExitOK {
				t.Fatalf("%v: exit %d\n%s%s", args, code, out.String(), errb.String())
			}
			return out.String() + errb.String()
		}
		if out := run("migrate", "status"); strings.Contains(out, "pending") && !strings.Contains(out, "0 pending") {
			t.Fatalf("status: %s", out)
		}
		script := run("migrate", "sql")
		for _, want := range []string{"CREATE TABLE IF NOT EXISTS " + renamedUsers + " (", "CREATE TABLE IF NOT EXISTS " + renamedPasswords + " (",
			"CREATE TABLE IF NOT EXISTS " + renamePrefix + apikey.TableNameKey + " ("} {
			if !strings.Contains(script, want) {
				t.Errorf("migrate sql lacks %q", want)
			}
		}
		if strings.Contains(script, " "+auth.TableNameUser+" ") || strings.Contains(script, " "+password.TableNamePassword+" ") {
			t.Fatalf("migrate sql names a label:\n%s", script)
		}
		if out := run("migrate", "orphans"); !strings.Contains(out, "0 orphan") {
			t.Fatalf("orphans: %s", out)
		}
		// The ledger lives under its real name, with every migration.
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + renamedLedger).Scan(&n); err != nil || n == 0 {
			t.Fatalf("ledger rows = %d %v", n, err)
		}

		// Renaming is decided before the first deploy: a second configuration
		// that names the user table differently finds its tables missing, and
		// the error names what it looked for.
		other, err := auth.New(auth.WithDB(e.db, e.d), auth.WithBaseURL(testBaseURL), auth.WithTablePrefix(renamePrefix),
			auth.RenameTable(auth.TableUser, "app_people"), auth.RenameTable(auth.TableMigrations, renamedLedger),
			auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		r := must[auth.SchemaReport](t)(other.CheckSchema(ctx))
		if r.OK() || !slices.Contains(r.MissingTables, "app_people") || !slices.Contains(r.MissingTables, renamePrefix+password.TableNamePassword) {
			t.Fatalf("a different rename must report missing tables: %+v", r)
		}
		if err := other.RequireSchema(ctx); !errors.Is(err, auth.ErrSchemaBehind) || !strings.Contains(err.Error(), "app_people") {
			t.Fatalf("RequireSchema = %v", err)
		}
	})
}

// TestTables_RenameTableRefusesAnUnregisteredPluginTable: New refuses a rename
// of a plugin's table when the plugin is not wired, so a rename cannot sit in
// the configuration doing nothing.
func TestTables_RenameTableRefusesAnUnregisteredPluginTable(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.RenameTable(apikey.TableKey, "app_keys"),
			auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		if !errors.Is(err, auth.ErrUnknownTable) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestTables_PrefixedRunUsesRealNames pins the harness switch itself: under
// EnvTablePrefix every table the harness creates carries the prefix, and
// without it none does, so the prefixed run cannot pass vacuously.
func TestTables_PrefixedRunUsesRealNames(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
		if got := a.TableName(auth.TableUser); got != tbl(auth.TableNameUser) {
			t.Fatalf("TableName = %q, want %q", got, tbl(auth.TableNameUser))
		}
		var n int
		err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameUser)).Scan(&n)
		if err != nil || n != 0 {
			t.Fatalf("count = %d %v", n, err)
		}
		if p := tablePrefix(); p != "" {
			if err := e.db.QueryRow("SELECT COUNT(*) FROM " + auth.TableNameUser).Scan(&n); err == nil || errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("the label table must not exist in a prefixed run: %v", err)
			}
		}
	})
}

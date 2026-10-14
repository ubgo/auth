package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
)

func TestCLI_StatusDryRunMigrate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)),
			auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		if err != nil {
			t.Fatal(err)
		}
		run := func(args ...string) (int, string) {
			var out, errb bytes.Buffer
			code := authcli.Main(context.Background(), a, args, &out, &errb)
			return code, out.String() + errb.String()
		}
		code, out := run("migrate", "--dry-run")
		if code != authcli.ExitOK || !strings.Contains(out, "pending  core") || strings.Contains(out, "applied") {
			t.Fatalf("dry run: %d\n%s", code, out)
		}
		if n := countTable(t, e, auth.TableNameUser); n != -1 {
			t.Fatalf("the dry run created auth_user")
		}
		code, out = run("migrate")
		if code != authcli.ExitOK || !strings.Contains(out, "applied core/0001_core_tables") {
			t.Fatalf("migrate: %d\n%s", code, out)
		}
		code, out = run("migrate", "status")
		if code != authcli.ExitOK || !strings.Contains(out, "0 pending, 0 changed") {
			t.Fatalf("status: %d\n%s", code, out)
		}
		if _, err := e.db.Exec("UPDATE " + tbl(auth.TableNameMigrations) + " SET checksum = 'x' WHERE owner = 'password'"); err != nil {
			t.Fatal(err)
		}
		if code, out = run("migrate", "status"); code != authcli.ExitFailed || !strings.Contains(out, "CHANGED  password") {
			t.Fatalf("status after tampering: %d\n%s", code, out)
		}
	})
}

// countTable returns the row count, or -1 when the table does not exist.
func countTable(t *testing.T, e *env, table string) int {
	table = tbl(table)
	t.Helper()
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		return -1
	}
	return n
}

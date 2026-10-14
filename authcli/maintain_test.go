package authcli_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/sqlb"
)

// jobPlugin is a Maintainer that records the options it was given.
type jobPlugin struct {
	gotDry bool
	err    error
}

func (*jobPlugin) Name() string { return "job" }

func (p *jobPlugin) Maintain(_ context.Context, o auth.MaintainOptions) (map[string]int64, error) {
	p.gotDry = o.DryRun
	return map[string]int64{"b": 2, "a": 1}, p.err
}

func maintainAuth(t *testing.T, j *jobPlugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}, j))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestMain_MaintainPrintsSortedCountersAndPassesDryRun: the counters print
// prefixed by the plugin and sorted, and --dry-run reaches the plugin.
func TestMain_MaintainPrintsSortedCountersAndPassesDryRun(t *testing.T) {
	j := &jobPlugin{}
	a := maintainAuth(t, j)
	code, out, errOut := run(t, a, "maintain")
	if code != authcli.ExitOK || out != "job.a\t1\njob.b\t2\n" || errOut != "" || j.gotDry {
		t.Fatalf("maintain: %d out=%q err=%q dry=%v", code, out, errOut, j.gotDry)
	}
	if code, _, _ := run(t, a, "maintain", "--dry-run"); code != authcli.ExitOK || !j.gotDry {
		t.Fatalf("--dry-run: %d dry=%v", code, j.gotDry)
	}
}

// TestMain_MaintainFailureIsExitFailedAfterTheCounters: what the plugin had
// done is still printed, and the exit code says it failed.
func TestMain_MaintainFailureIsExitFailedAfterTheCounters(t *testing.T) {
	j := &jobPlugin{err: errors.New("mailer down")}
	code, out, errOut := run(t, maintainAuth(t, j), "maintain")
	if code != authcli.ExitFailed || out != "job.a\t1\njob.b\t2\n" || !strings.Contains(errOut, "mailer down") || !strings.Contains(errOut, "job") {
		t.Fatalf("failing maintain: %d out=%q err=%q", code, out, errOut)
	}
}

// TestMain_MaintainUsage: -h succeeds, a stray argument or flag is a usage
// error, and the usage text names the command.
func TestMain_MaintainUsage(t *testing.T) {
	a := maintainAuth(t, &jobPlugin{})
	if code, _, errOut := run(t, a, "maintain", "-h"); code != authcli.ExitOK || !strings.Contains(errOut, "usage:") {
		t.Errorf("-h: %d %q", code, errOut)
	}
	for _, args := range [][]string{{"maintain", "extra"}, {"maintain", "--no-such-flag"}} {
		if code, _, errOut := run(t, a, args...); code != authcli.ExitUsage || !strings.Contains(errOut, "usage:") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if code, _, errOut := run(t, a); code != authcli.ExitUsage || !strings.Contains(errOut, "auth maintain") {
		t.Errorf("usage text lacks the maintain command: %d %q", code, errOut)
	}
}

// TestMain_MaintainWithNoMaintainerPrintsNothing: an app without a job has
// nothing to report and succeeds.
func TestMain_MaintainWithNoMaintainerPrintsNothing(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run(t, a, "maintain"); code != authcli.ExitOK || out != "" {
		t.Fatalf("no maintainer: %d %q", code, out)
	}
}

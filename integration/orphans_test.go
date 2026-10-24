package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/username"
)

// TestOrphans_ReportsWhatARemovedPluginLeft: an app runs with the oauth
// plugin, then removes it. Its table and its ledger rows stay, and Orphans
// names them; the email plugin's columns are still owned and not reported.
func TestOrphans_ReportsWhatARemovedPluginLeft(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oauth.New(oauth.WithProviders(oauth.Google("id", "secret"))))
		later, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)),
			auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		if err != nil {
			t.Fatal(err)
		}
		got, err := later.Orphans(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := []auth.Orphan{{Kind: auth.OrphanOwner, Name: oauth.PluginName}, {Kind: auth.OrphanTable, Name: tbl(oauth.TableNameAccount)}}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("orphans = %+v, want %+v", got, want)
		}
		var out, errb bytes.Buffer
		if code := authcli.Main(ctx, later, []string{"migrate", "orphans"}, &out, &errb); code != authcli.ExitOK || !strings.Contains(out.String(), "table\t"+tbl(oauth.TableNameAccount)) {
			t.Fatalf("cli orphans: %d %q %q", code, out.String(), errb.String())
		}
		// Removing the email plugin too orphans its columns on auth_user.
		bare, err := auth.New(e.withDB(), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)),
			auth.WithPlugins(username.New(username.Login()), e.passwordPlugin(password.WithoutRecovery())))
		if err != nil {
			t.Fatal(err)
		}
		got, err = bare.Orphans(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cols := 0
		for _, o := range got {
			if o.Kind == auth.OrphanColumn {
				cols++
			}
		}
		if cols != 2 {
			t.Fatalf("orphans without the email plugin = %+v, want its 2 columns", got)
		}
	})
}

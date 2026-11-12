package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// `auth oauth-client` through authcli.Main, on a real database: the
// provider plugin adds the command with no wiring, create shows the secret
// once or writes it to a new 0600 file, names stay unambiguous, update
// changes only the flags given, and delete has a dry run.
func TestOAuthClientCLI(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		cli := func(args ...string) (int, string, string) {
			var out, errb bytes.Buffer
			code := authcli.MainWithStdin(context.Background(), o.a, append([]string{oauthprovider.CmdOAuthClient}, args...), strings.NewReader(""), &out, &errb)
			return code, out.String(), errb.String()
		}
		if code, _, errOut := cli(); code != authcli.ExitUsage || !strings.Contains(errOut, "auth oauth-client create") {
			t.Fatalf("no subcommand: %d %q", code, errOut)
		}
		var outRoot bytes.Buffer
		authcli.Main(context.Background(), o.a, nil, &outRoot, &outRoot)
		if !strings.Contains(outRoot.String(), "plugin commands:") || !strings.Contains(outRoot.String(), "auth oauth-client list") {
			t.Fatalf("auth usage lacks the plugin command:\n%s", outRoot.String())
		}

		// Create, secret printed once.
		code, out, errOut := cli("create", "--name", "Wiki", "--redirect-uri", opRedirect, "--post-logout-uri", "https://client.example/out", "--skip-consent", "--json")
		if code != authcli.ExitOK {
			t.Fatalf("create: %d %q", code, errOut)
		}
		var reg oauthprovider.Registration
		if err := json.Unmarshal([]byte(out), &reg); err != nil || reg.Secret == "" || !reg.SkipConsent || reg.Name != "Wiki" {
			t.Fatalf("create json = %s %v", out, err)
		}
		// The same name again is refused, so a name picks one client.
		if code, _, errOut := cli("create", "--name", "Wiki", "--redirect-uri", opRedirect); code != authcli.ExitFailed || !strings.Contains(errOut, "another client has this name") {
			t.Fatalf("duplicate name: %d %q", code, errOut)
		}
		// Missing redirect URI: a usage error, nothing created.
		if code, _, _ := cli("create", "--name", "X"); code != authcli.ExitUsage {
			t.Fatalf("no redirect: %d", code)
		}

		// --secret-file: the secret goes to a new 0600 file and not to stdout;
		// an existing file is never overwritten.
		path := filepath.Join(t.TempDir(), "secret")
		code, out, errOut = cli("create", "--name", "Mail", "--redirect-uri", opRedirect, "--secret-file", path)
		if code != authcli.ExitOK || strings.Contains(out, oauthprovider.PrefixClientSecret) || !strings.Contains(errOut, path) {
			t.Fatalf("secret-file create: %d %q %q", code, out, errOut)
		}
		data := must[[]byte](t)(os.ReadFile(path))
		fi := must[os.FileInfo](t)(os.Stat(path))
		if !strings.HasPrefix(string(data), oauthprovider.PrefixClientSecret) || fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file = %q mode %v", data, fi.Mode())
		}
		if code, _, _ := cli("create", "--name", "Other", "--redirect-uri", opRedirect, "--secret-file", path); code != authcli.ExitFailed {
			t.Fatalf("existing secret file overwritten: %d", code)
		}
		if n := len(must[[]oauthprovider.Client](t)(o.op.AllClients(context.Background()))); n != 2 {
			t.Fatalf("a refused create left a client behind: %d clients", n)
		}

		// List and show, by name and by id.
		code, out, _ = cli("list")
		if code != authcli.ExitOK || !strings.Contains(out, reg.ClientID) || !strings.Contains(out, "Mail") {
			t.Fatalf("list: %d %q", code, out)
		}
		if code, out, _ := cli("show", "Wiki"); code != authcli.ExitOK || !strings.Contains(out, reg.ClientID) || strings.Contains(out, reg.Secret) {
			t.Fatalf("show: %d %q", code, out)
		}
		if code, _, errOut := cli("show", "nope"); code != authcli.ExitFailed || !strings.Contains(errOut, "oauthprovider.not_found") {
			t.Fatalf("show unknown: %d %q", code, errOut)
		}

		// Update changes only the flags given; "" clears a list.
		code, _, errOut = cli("update", reg.ClientID, "--post-logout-uri", "https://client.example/bye", "--post-logout-uri", "https://client.example/out", "--disabled=true")
		if code != authcli.ExitOK {
			t.Fatalf("update: %d %q", code, errOut)
		}
		c := must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID))
		if len(c.PostLogoutRedirectURIs) != 2 || !c.Disabled || !c.SkipConsent || c.Name != "Wiki" || c.RedirectURIs[0] != opRedirect {
			t.Fatalf("after update = %+v", c)
		}
		if code, _, _ := cli("update", "Wiki", "--post-logout-uri", ""); code != authcli.ExitOK {
			t.Fatal("clear failed")
		}
		if c := must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID)); len(c.PostLogoutRedirectURIs) != 0 {
			t.Fatalf("cleared = %v", c.PostLogoutRedirectURIs)
		}
		if code, _, _ := cli("show", "Wiki", "--name", "x"); code != authcli.ExitUsage {
			t.Fatalf("show with an update flag: %d", code)
		}

		// Delete: the dry run changes nothing.
		if code, out, _ := cli("delete", "Wiki", "--dry-run"); code != authcli.ExitOK || !strings.Contains(out, "would delete") {
			t.Fatalf("dry run: %d %q", code, out)
		}
		must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID))
		if code, _, _ := cli("delete", "Wiki"); code != authcli.ExitOK {
			t.Fatal("delete failed")
		}
		if _, err := o.op.Client(context.Background(), reg.ClientID); err == nil {
			t.Fatal("deleted client still there")
		}

		// Two clients created from Go with one name: the name is ambiguous.
		o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "Twin"}})
		o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "Twin"}})
		if code, _, errOut := cli("show", "Twin"); code != authcli.ExitFailed || !strings.Contains(errOut, "use the client id") {
			t.Fatalf("ambiguous name: %d %q", code, errOut)
		}
	})
}

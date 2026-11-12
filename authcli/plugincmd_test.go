package authcli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/sqlb"
)

// cmdPlugin is a plugin that adds commands.
type cmdPlugin struct {
	name string
	cmds []authcli.Command
}

func (p cmdPlugin) Name() string                { return p.name }
func (p cmdPlugin) Commands() []authcli.Command { return p.cmds }

func newCLIAuth(t *testing.T, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(append([]auth.Plugin{signIn{}}, plugins...)...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A plugin's command runs with the arguments after its word and the
// streams Main was given, its usage joins the usage text, and its exit code
// is Main's.
func TestMain_PluginCommand(t *testing.T) {
	var gotArgs []string
	echo := authcli.Command{Name: "echo-things", Usage: "auth echo-things [words]   print the words\n", Run: func(_ context.Context, _ *auth.Auth, args []string, std authcli.IO) int {
		gotArgs = args
		in := new(bytes.Buffer)
		_, _ = in.ReadFrom(std.Stdin)
		std.Stdout.Write([]byte(strings.Join(args, ",") + "|" + in.String()))
		return authcli.ExitFailed
	}}
	a := newCLIAuth(t, cmdPlugin{name: "p", cmds: []authcli.Command{echo}})
	var out, errb bytes.Buffer
	code := authcli.MainWithStdin(context.Background(), a, []string{"echo-things", "a", "--b"}, strings.NewReader("in"), &out, &errb)
	if code != authcli.ExitFailed || out.String() != "a,--b|in" || strings.Join(gotArgs, " ") != "a --b" {
		t.Fatalf("plugin command: %d %q %q", code, out.String(), errb.String())
	}
	if code, _, errOut := run(t, a); code != authcli.ExitUsage || !strings.Contains(errOut, "plugin commands:\n  auth echo-things [words]") {
		t.Fatalf("usage lacks the plugin's line: %q", errOut)
	}
	if code, _, _ := run(t, a, "no-such-word"); code != authcli.ExitUsage {
		t.Fatalf("unknown word: %d", code)
	}
}

// A plugin command never shadows a built-in one or another plugin's: Main
// refuses rather than pick one. A command without a Run is refused too.
func TestMain_PluginCommandClash(t *testing.T) {
	noop := func(context.Context, *auth.Auth, []string, authcli.IO) int { return authcli.ExitOK }
	for name, plugins := range map[string][]auth.Plugin{
		"built-in":    {cmdPlugin{name: "p", cmds: []authcli.Command{{Name: authcli.CmdSweep, Run: noop}, {Name: "x", Run: noop}}}},
		"two plugins": {cmdPlugin{name: "p", cmds: []authcli.Command{{Name: "x", Run: noop}}}, cmdPlugin{name: "q", cmds: []authcli.Command{{Name: "x", Run: noop}}}},
		"no run":      {cmdPlugin{name: "p", cmds: []authcli.Command{{Name: "x"}}}},
	} {
		a := newCLIAuth(t, plugins...)
		if code, _, errOut := run(t, a, "x"); code != authcli.ExitFailed || (name != "no run" && !strings.Contains(errOut, authcli.ErrCommandClash.Error())) {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}

// A plugin command's flag set answers -h with ExitOK and a bad flag with
// ExitUsage, each printing the usage to stderr.
func TestFlagSet(t *testing.T) {
	var errb bytes.Buffer
	fs := authcli.NewFlagSet("x", "the usage\n", &errb)
	fs.Bool("y", false, "")
	if code, stop := authcli.ParseFlags(fs, []string{"-h"}); code != authcli.ExitOK || !stop || !strings.Contains(errb.String(), "the usage") {
		t.Fatalf("-h: %d %v %q", code, stop, errb.String())
	}
	if code, stop := authcli.ParseFlags(fs, []string{"--nope"}); code != authcli.ExitUsage || !stop {
		t.Fatalf("bad flag: %d %v", code, stop)
	}
	if _, stop := authcli.ParseFlags(fs, []string{"-y"}); stop {
		t.Fatal("a good flag stopped the command")
	}
}

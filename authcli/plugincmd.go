package authcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ubgo/auth"
)

// Plugin commands: a plugin adds its own words to `auth` without this
// package importing it. The core module must not depend on optional
// modules (an OAuth provider, organizations), yet their operators need a
// command line as much as the core's; a plugin that implements
// CommandProvider is found among the Auth's plugins and routed to like a
// built-in command.

// Command is one word a plugin adds to the command line: `auth <Name> ...`.
// Run receives the arguments after Name and returns an exit code (ExitOK,
// ExitFailed or ExitUsage, the library-wide convention).
//
//ds:def id=authcli-command-avck6vee owner=@khanakia stability=stable
type Command struct {
	// Name is the word Main routes on; it never shadows a built-in command
	// (Main refuses to run with a clash rather than pick one).
	Name string
	// Usage is the command's lines in the usage text, each starting with
	// "auth <Name>", as the built-in lines do.
	Usage string
	// Run runs the command.
	Run func(ctx context.Context, a *auth.Auth, args []string, io IO) int
}

// IO is a command's standard streams. Stdin is read only by a command that
// says so in its usage (a secret piped in), never by default.
type IO struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// CommandProvider is a plugin that adds commands. It is found through the
// Auth's plugin list, so registering the plugin is all an app does.
//
//ds:def id=authcli-commandprovider-9487n422 owner=@khanakia stability=stable
type CommandProvider interface {
	auth.Plugin
	Commands() []Command
}

// ErrCommandClash is two commands with one name: a plugin's and a built-in
// one, or two plugins'. Main reports it and runs nothing, since running
// either would surprise the operator who typed the word.
var ErrCommandClash = errors.New("authcli: two commands share a name")

// builtins are the words Main itself routes on.
var builtins = []string{CmdMigrate, CmdGenerate, CmdSweep, CmdMaintain, CmdAdmin, CmdInfo, CmdSecret, CmdClient}

// pluginCommands lists the registered plugins' commands, refusing a clash.
func pluginCommands(a *auth.Auth) ([]Command, error) {
	var out []Command
	for _, p := range a.Plugins() {
		cp, ok := p.(CommandProvider)
		if !ok {
			continue
		}
		for _, c := range cp.Commands() {
			if c.Name == "" || c.Run == nil {
				return nil, fmt.Errorf("authcli: plugin %s: a command needs a name and a Run", p.Name())
			}
			if slices.Contains(builtins, c.Name) || slices.ContainsFunc(out, func(o Command) bool { return o.Name == c.Name }) {
				return nil, fmt.Errorf("%w: %q (plugin %s)", ErrCommandClash, c.Name, p.Name())
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// fullUsage is the usage text with the plugins' lines added after the
// built-in ones.
func fullUsage(a *auth.Auth) string {
	cmds, err := pluginCommands(a)
	if err != nil || len(cmds) == 0 {
		return usage
	}
	var b strings.Builder
	b.WriteString("plugin commands:\n")
	for _, c := range cmds {
		for _, line := range strings.Split(strings.TrimRight(c.Usage, "\n"), "\n") {
			b.WriteString("  " + line + "\n")
		}
	}
	return usage + "\n" + b.String()
}

// runPlugin runs the plugin command named args[0]; found is false when no
// plugin has it.
func runPlugin(ctx context.Context, a *auth.Auth, args []string, std IO) (code int, found bool) {
	cmds, err := pluginCommands(a)
	if err != nil {
		fmt.Fprintln(std.Stderr, err)
		return ExitFailed, true
	}
	for _, c := range cmds {
		if c.Name == args[0] {
			return c.Run(ctx, a, args[1:], std), true
		}
	}
	return 0, false
}

// NewFlagSet is a flag set for a plugin command: errors and -h go to
// stderr, followed by usage, as the built-in commands do. ParseFlags
// parses with it.
func NewFlagSet(name, usage string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	return fs
}

// ParseFlags parses args into fs. stop is true when parsing ended the
// command, and code is then what the command returns: ExitOK for -h,
// ExitUsage for a bad flag.
func ParseFlags(fs *flag.FlagSet, args []string) (code int, stop bool) { return parse(fs, args) }

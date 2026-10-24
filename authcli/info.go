package authcli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"text/tabwriter"
	"time"

	"github.com/ubgo/auth"
)

// ModulePath is the module whose version Info reports, read from the
// binary's build information. An app that vendors or replaces the module
// sees "(devel)" or the replacement's version, which is the truth about what
// it runs.
const ModulePath = "github.com/ubgo/auth"

// unknownVersion is what Info reports when the binary carries no build
// information for the module: a test binary, or a build from a work tree.
const unknownVersion = "unknown"

// Info is what "auth info" prints: the wiring of this instance, for a support
// request or a deployment check. It holds no secret and no user data; the
// trusted origins and the base URL are the deployment's public addresses.
//
//ds:def id=cli-info-4jrw9p2d owner=@khanakia stability=stable
type Info struct {
	Version        string            `json:"version"`
	Engine         string            `json:"engine"`
	BaseURL        string            `json:"baseUrl"`
	TrustedOrigins []string          `json:"trustedOrigins"`
	FreshWindow    Duration          `json:"freshWindow"`
	Session        SessionInfo       `json:"session"`
	Plugins        []string          `json:"plugins"`
	Identifiers    []string          `json:"identifiers"`
	Operations     []OperationInfo   `json:"operations"`
	Disabled       []auth.EndpointID `json:"disabled"`
	Migrations     []MigrationRef    `json:"migrations"`
}

// Duration is a time.Duration that encodes as its String form ("720h0m0s")
// in JSON and decodes from it. Info uses it because a bare time.Duration
// encodes as nanoseconds, which no person reading a support request can
// interpret, and because the round trip must hold: what --json prints
// decodes back into Info.
type Duration time.Duration

// MarshalText encodes d as time.Duration's String form.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText decodes the String form; anything time.ParseDuration
// refuses is an error, never a zero.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// String is time.Duration's String, so a table prints "720h0m0s".
func (d Duration) String() string { return time.Duration(d).String() }

// SessionInfo is auth.SessionConfig as Info reports it: the same four
// lifetimes, with JSON names and readable durations. auth.SessionConfig has
// no JSON tags because it is configuration, not a wire format; this is the
// wire format, so a rename in the core cannot silently change the output.
type SessionInfo struct {
	IdleTimeout          Duration `json:"idleTimeout"`
	MaxLifetime          Duration `json:"maxLifetime"`
	RefreshAfter         Duration `json:"refreshAfter"`
	TransientIdleTimeout Duration `json:"transientIdleTimeout"`
}

// sessionInfo converts the core's configuration into its reported form.
func sessionInfo(c auth.SessionConfig) SessionInfo {
	return SessionInfo{
		IdleTimeout: Duration(c.IdleTimeout), MaxLifetime: Duration(c.MaxLifetime),
		RefreshAfter: Duration(c.RefreshAfter), TransientIdleTimeout: Duration(c.TransientIdleTimeout),
	}
}

// MigrationRef names one migration in Info, without its statements.
type MigrationRef struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// OperationInfo is one route in Info.
type OperationInfo struct {
	ID      auth.EndpointID  `json:"id"`
	Kind    auth.OpKind      `json:"kind"`
	Require auth.Requirement `json:"require"`
	Route   string           `json:"route"`
}

// InfoOf collects Info for a. It touches no database: everything it reports
// was settled by auth.New. The error is the one Migrations returns for an
// engine the core has no DDL for.
func InfoOf(a *auth.Auth) (Info, error) {
	cfg := a.Config()
	out := Info{
		Version: moduleVersion(debug.ReadBuildInfo), Engine: a.Engine(), BaseURL: cfg.BaseURL,
		TrustedOrigins: cfg.TrustedOrigins, FreshWindow: Duration(cfg.FreshWindow), Session: sessionInfo(cfg.Session),
		Plugins: []string{}, Identifiers: []string{}, Operations: []OperationInfo{}, Disabled: a.DisabledOperations(),
		Migrations: []MigrationRef{},
	}
	migs, err := a.Migrations()
	if err != nil {
		return Info{}, err
	}
	for _, p := range a.Plugins() {
		out.Plugins = append(out.Plugins, p.Name())
	}
	for _, k := range cfg.Identifiers {
		out.Identifiers = append(out.Identifiers, string(k.Name))
	}
	for _, op := range a.Operations() {
		i := op.Info()
		out.Operations = append(out.Operations, OperationInfo{ID: i.ID, Kind: i.Kind, Require: i.Require, Route: op.Route()})
	}
	for _, m := range migs {
		out.Migrations = append(out.Migrations, MigrationRef{Owner: m.Owner, Name: m.Name})
	}
	if out.TrustedOrigins == nil {
		out.TrustedOrigins = []string{}
	}
	return out, nil
}

// moduleVersion finds ModulePath in the build information read by read, the
// main module when the binary is the library's own, or unknownVersion.
func moduleVersion(read func() (*debug.BuildInfo, bool)) string {
	bi, ok := read()
	if !ok {
		return unknownVersion
	}
	if bi.Main.Path == ModulePath && bi.Main.Version != "" {
		return bi.Main.Version
	}
	for _, d := range bi.Deps {
		if d.Path == ModulePath {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return unknownVersion
}

// info prints InfoOf as a table, or as JSON with --json.
func info(a *auth.Auth, args []string, stdout, stderr io.Writer) int {
	fs := newFlags(CmdInfo, stderr)
	asJSON := fs.Bool("json", false, "print JSON instead of a table")
	if code, stop := parse(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n%s", fs.Arg(0), usage)
		return ExitUsage
	}
	in, err := InfoOf(a)
	if err != nil {
		fmt.Fprintln(stderr, "auth info:", err)
		return ExitFailed
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(in)
	} else {
		err = printInfo(in, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "auth info:", err)
		return ExitFailed
	}
	return ExitOK
}

func printInfo(in Info, w io.Writer) error {
	tw := tabwriter.NewWriter(w, tableMinWidth, tableTabWidth, tablePadding, ' ', 0)
	fmt.Fprintf(tw, "version\t%s\nengine\t%s\nbase url\t%s\ntrusted origins\t%d\nfresh window\t%s\n",
		in.Version, in.Engine, in.BaseURL, len(in.TrustedOrigins), in.FreshWindow)
	fmt.Fprintf(tw, "session\tidle %s, max %s, refresh after %s\n", in.Session.IdleTimeout, in.Session.MaxLifetime, in.Session.RefreshAfter)
	fmt.Fprintf(tw, "plugins\t%d\nidentifiers\t%d\nmigrations\t%d\ndisabled operations\t%d\n", len(in.Plugins), len(in.Identifiers), len(in.Migrations), len(in.Disabled))
	for _, p := range in.Plugins {
		fmt.Fprintf(tw, "plugin\t%s\n", p)
	}
	for _, id := range in.Disabled {
		fmt.Fprintf(tw, "disabled\t%s\n", id)
	}
	for _, m := range in.Migrations {
		fmt.Fprintf(tw, "migration\t%s/%s\n", m.Owner, m.Name)
	}
	for _, op := range in.Operations {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", op.Kind, op.Route, op.Require, op.ID)
	}
	return tw.Flush()
}

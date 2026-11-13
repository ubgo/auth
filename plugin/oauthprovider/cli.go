package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
)

// The operator's command line for clients: `auth oauth-client
// create|list|show|update|delete|revoke-user`, added to authcli through
// authcli.CommandProvider, so an app that registers this plugin and wires
// authcli has it with no code. It manages every stored client, whoever owns
// it, so it belongs to the operator's shell, never to a route.

// CmdOAuthClient is the command word; the SubClient* constants are its
// subcommands.
const (
	CmdOAuthClient  = "oauth-client"
	SubClientCreate = "create"
	SubClientList   = "list"
	SubClientShow   = "show"
	SubClientUpdate = "update"
	SubClientDelete = "delete"
)

// Flags of the oauth-client subcommands.
const (
	flagName          = "name"
	flagRedirectURI   = "redirect-uri"
	flagPostLogoutURI = "post-logout-uri"
	flagScope         = "scope"
	flagGrant         = "grant"
	flagPublic        = "public"
	flagSkipConsent   = "skip-consent"
	flagEndSession    = "end-session"
	flagDisabled      = "disabled"
	flagSecretFile    = "secret-file"
	flagJSON          = "json"
	flagDryRun        = "dry-run"
)

// secretFileMode is the mode of a --secret-file: the owner alone reads it.
const secretFileMode = 0o600

// clientUsage is the usage text of the oauth-client command.
const clientUsage = `auth oauth-client create --name N --redirect-uri URL [--redirect-uri URL ...]
                          [--post-logout-uri URL ...] [--scope "openid email"] [--grant G ...]
                          [--public] [--skip-consent] [--end-session] [--secret-file PATH] [--json]
                          register a client; the secret is printed once, or written to PATH (mode 0600)
                          instead; a name another client has is refused, so a name always picks one client
auth oauth-client list [--json]             every stored client, oldest first
auth oauth-client show <id|name> [--json]   one client
auth oauth-client update <id|name> [--name N] [--redirect-uri URL ...] [--post-logout-uri URL ...]
                          [--scope S] [--skip-consent=BOOL] [--end-session=BOOL] [--disabled=BOOL] [--json]
                          change only the flags given; a list flag given as "" clears the list;
                          the authentication method never changes
auth oauth-client delete <id|name> [--dry-run]   delete a client with its codes, tokens and consents
` + revokeUserUsage

// ErrAmbiguousClient is a name that more than one client has: the operator
// names the client by id instead.
var ErrAmbiguousClient = errors.New("oauthprovider: more than one client has this name; use the client id")

// ErrClientNameTaken is a create for a name another client already has.
var ErrClientNameTaken = errors.New("oauthprovider: another client has this name")

// Commands implements authcli.CommandProvider.
func (p *Plugin) Commands() []authcli.Command {
	return []authcli.Command{{Name: CmdOAuthClient, Usage: clientUsage, Run: p.runClientCommand}}
}

// listFlag is a repeatable string flag. given records that it appeared, so
// update can tell "not given" from "given empty" (clear).
type listFlag struct {
	vals  []string
	given bool
}

func (l *listFlag) String() string { return strings.Join(l.vals, " ") }

func (l *listFlag) Set(v string) error {
	l.given = true
	if v != "" {
		l.vals = append(l.vals, v)
	}
	return nil
}

// runClientCommand routes `auth oauth-client <sub>`.
func (p *Plugin) runClientCommand(ctx context.Context, _ *auth.Auth, args []string, std authcli.IO) int {
	if len(args) == 0 {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	sub, rest := args[0], args[1:]
	fs := authcli.NewFlagSet(CmdOAuthClient+" "+sub, clientUsage, std.Stderr)
	asJSON := fs.Bool(flagJSON, false, "print JSON")
	var err error
	switch sub {
	case SubClientCreate:
		return p.cliCreate(ctx, fs, rest, asJSON, std)
	case SubClientList:
		if code, stop := authcli.ParseFlags(fs, rest); stop {
			return code
		}
		var all []Client
		if all, err = p.AllClients(ctx); err == nil {
			err = printClients(std.Stdout, all, *asJSON)
		}
	case SubClientShow, SubClientUpdate, SubClientDelete:
		return p.cliOne(ctx, sub, fs, rest, asJSON, std)
	case SubClientRevokeUser:
		return p.cliRevokeUser(ctx, fs, rest, asJSON, std)
	default:
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	return cliResult(std.Stderr, sub, err)
}

// cliResult turns an error into the exit code and its line on stderr. A
// library error prints its message and code ("Client not found.
// (oauthprovider.not_found)"), since its Error() is the bare code a
// program matches, not a sentence an operator reads.
func cliResult(stderr io.Writer, sub string, err error) int {
	if err == nil {
		return authcli.ExitOK
	}
	msg := err.Error()
	var ae *auth.Error
	if errors.As(err, &ae) && ae.Error() == msg {
		msg = fmt.Sprintf("%s (%s)", ae.Message, ae.Code)
	}
	fmt.Fprintf(stderr, "auth %s %s: %s\n", CmdOAuthClient, sub, msg)
	return authcli.ExitFailed
}

// cliCreate registers a client. The secret goes to stdout once, or to
// --secret-file (created, never overwritten, mode 0600) and then never to
// stdout, so it stays out of terminal scrollback and CI logs.
func (p *Plugin) cliCreate(ctx context.Context, fs *flag.FlagSet, args []string, asJSON *bool, std authcli.IO) int {
	name := fs.String(flagName, "", "the client's name, shown on the consent page")
	var redirects, postLogout, grants listFlag
	fs.Var(&redirects, flagRedirectURI, "a redirect URI (repeat for more)")
	fs.Var(&postLogout, flagPostLogoutURI, "a post-logout redirect URI (repeat for more)")
	fs.Var(&grants, flagGrant, "a grant type (repeat for more; default authorization_code and refresh_token)")
	scope := fs.String(flagScope, "", "space-separated scopes the client may ask for")
	public := fs.Bool(flagPublic, false, "a public client (no secret, PKCE required)")
	skip := fs.Bool(flagSkipConsent, false, "a first-party client: never ask the user")
	endSession := fs.Bool(flagEndSession, false, "let the client sign its users out (needs auth.WithSecret)")
	secretFile := fs.String(flagSecretFile, "", "write the secret to this new file instead of printing it")
	if code, stop := authcli.ParseFlags(fs, args); stop {
		return code
	}
	if strings.TrimSpace(*name) == "" || len(redirects.vals) == 0 || fs.NArg() > 0 {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	if *public && *secretFile != "" {
		fmt.Fprintf(std.Stderr, "auth %s %s: --%s: a public client has no secret\n", CmdOAuthClient, SubClientCreate, flagSecretFile)
		return authcli.ExitUsage
	}
	if _, err := p.findClient(ctx, *name); err == nil {
		return cliResult(std.Stderr, SubClientCreate, fmt.Errorf("%w: %s", ErrClientNameTaken, *name))
	} else if !errors.Is(err, ErrClientNotFound) {
		return cliResult(std.Stderr, SubClientCreate, err)
	}
	var out *os.File
	if *secretFile != "" {
		// Created before the client exists, so a path that cannot be written
		// fails before a secret nobody can read is minted.
		f, err := os.OpenFile(*secretFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, secretFileMode)
		if err != nil {
			return cliResult(std.Stderr, SubClientCreate, err)
		}
		out = f
	}
	spec := ClientSpec{
		ClientMetadata:   ClientMetadata{Name: strings.TrimSpace(*name), RedirectURIs: redirects.vals, PostLogoutRedirectURIs: postLogout.vals, GrantTypes: grants.vals, Scope: *scope},
		SkipConsent:      *skip,
		EnableEndSession: *endSession,
	}
	if *public {
		spec.AuthMethod = AuthMethodNone
	}
	reg, err := p.CreateClient(ctx, spec)
	if err != nil {
		if out != nil {
			out.Close()
			os.Remove(*secretFile)
		}
		return cliResult(std.Stderr, SubClientCreate, err)
	}
	if out != nil {
		_, werr := io.WriteString(out, reg.Secret+"\n")
		if cerr := out.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return cliResult(std.Stderr, SubClientCreate, fmt.Errorf("client %s created, but its secret was not written: %w (rotate it)", reg.ClientID, werr))
		}
		reg.Secret = ""
		fmt.Fprintf(std.Stderr, "secret written to %s\n", *secretFile)
	}
	if *asJSON {
		return cliResult(std.Stderr, SubClientCreate, printJSON(std.Stdout, reg))
	}
	err = printClient(std.Stdout, reg.Client)
	if err == nil && reg.Secret != "" {
		_, err = fmt.Fprintf(std.Stdout, "secret\t%s\n(shown once: store it now)\n", reg.Secret)
	}
	return cliResult(std.Stderr, SubClientCreate, err)
}

// cliOne runs show, update and delete, which name one client.
func (p *Plugin) cliOne(ctx context.Context, sub string, fs *flag.FlagSet, args []string, asJSON *bool, std authcli.IO) int {
	name := fs.String(flagName, "", "a new name")
	var redirects, postLogout listFlag
	fs.Var(&redirects, flagRedirectURI, "the redirect URIs (repeat; replaces the list)")
	fs.Var(&postLogout, flagPostLogoutURI, "the post-logout redirect URIs (repeat; replaces the list)")
	scope := fs.String(flagScope, "", "the scopes the client may ask for")
	skip := fs.Bool(flagSkipConsent, false, "first-party: never ask the user")
	endSession := fs.Bool(flagEndSession, false, "may sign its users out")
	disabled := fs.Bool(flagDisabled, false, "disable or re-enable the client")
	dry := fs.Bool(flagDryRun, false, "show what delete would remove and change nothing")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	ref := args[0]
	if code, stop := authcli.ParseFlags(fs, args[1:]); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if sub != SubClientUpdate && len(given) > 0 && !(len(given) == 1 && (given[flagJSON] || (sub == SubClientDelete && given[flagDryRun]))) {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	c, err := p.findClient(ctx, ref)
	if err != nil {
		return cliResult(std.Stderr, sub, err)
	}
	switch sub {
	case SubClientDelete:
		if *dry {
			_, err = fmt.Fprintf(std.Stdout, "would delete client %s (%s) with its codes, tokens and consents\n", c.ClientID, c.Name)
			return cliResult(std.Stderr, sub, err)
		}
		if err = p.DeleteClient(ctx, c.ClientID); err == nil {
			_, err = fmt.Fprintf(std.Stdout, "deleted client %s (%s)\n", c.ClientID, c.Name)
		}
		return cliResult(std.Stderr, sub, err)
	case SubClientUpdate:
		var patch ClientPatch
		if given[flagName] {
			patch.Name = name
		}
		if redirects.given {
			patch.RedirectURIs = &redirects.vals
		}
		if postLogout.given {
			patch.PostLogoutRedirectURIs = &postLogout.vals
		}
		if given[flagScope] {
			patch.Scope = scope
		}
		if given[flagSkipConsent] {
			patch.SkipConsent = skip
		}
		if given[flagEndSession] {
			patch.EnableEndSession = endSession
		}
		if patch != (ClientPatch{}) {
			if c, err = p.PatchClient(ctx, c.ClientID, patch); err != nil {
				return cliResult(std.Stderr, sub, err)
			}
		}
		if given[flagDisabled] {
			if err = p.SetClientDisabled(ctx, c.ClientID, *disabled); err != nil {
				return cliResult(std.Stderr, sub, err)
			}
			if c, err = p.Client(ctx, c.ClientID); err != nil {
				return cliResult(std.Stderr, sub, err)
			}
		}
	}
	if *asJSON {
		return cliResult(std.Stderr, sub, printJSON(std.Stdout, c))
	}
	return cliResult(std.Stderr, sub, printClient(std.Stdout, c))
}

// findClient finds a stored client by id, then by name; a name more than
// one client has is ErrAmbiguousClient.
func (p *Plugin) findClient(ctx context.Context, ref string) (Client, error) {
	if c, err := p.Client(ctx, ref); err == nil || !errors.Is(err, ErrClientNotFound) {
		return c, err
	}
	all, err := p.AllClients(ctx)
	if err != nil {
		return Client{}, err
	}
	var found []Client
	for _, c := range all {
		if c.Name == strings.TrimSpace(ref) {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 0:
		return Client{}, ErrClientNotFound
	case 1:
		return found[0], nil
	}
	return Client{}, ErrAmbiguousClient
}

// printJSON prints v indented, for scripts.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printClients prints a table (or a JSON array) of clients.
func printClients(w io.Writer, all []Client, asJSON bool) error {
	if asJSON {
		return printJSON(w, all)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT ID\tNAME\tREDIRECT URIS\tSTATUS")
	for _, c := range all {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ClientID, c.Name, strings.Join(c.RedirectURIs, " "), clientStatus(c))
	}
	return tw.Flush()
}

// printClient prints one client's fields, one per line.
func printClient(w io.Writer, c Client) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range [][2]string{
		{"client_id", c.ClientID},
		{"name", c.Name},
		{"auth_method", c.AuthMethod},
		{"redirect_uris", strings.Join(c.RedirectURIs, " ")},
		{"post_logout_redirect_uris", strings.Join(c.PostLogoutRedirectURIs, " ")},
		{"grant_types", strings.Join(c.GrantTypes, " ")},
		{"scope", c.Scope},
		{"skip_consent", fmt.Sprint(c.SkipConsent)},
		{"end_session", fmt.Sprint(c.EndSession)},
		{"status", clientStatus(c)},
		{"created_at", c.CreatedAt.UTC().Format("2006-01-02 15:04:05Z")},
	} {
		fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
	}
	return tw.Flush()
}

// The words printClient and printClients show for a client's state.
const (
	statusActive   = "active"
	statusDisabled = "disabled"
)

// clientStatus is the client's state word.
func clientStatus(c Client) string {
	if c.Disabled {
		return statusDisabled
	}
	return statusActive
}

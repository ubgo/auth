package authcli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ubgo/auth"
)

// The admin command and its subcommands: `auth admin grant` makes an existing
// user an admin, `auth admin create` creates one. They exist because the first
// admin cannot be made over HTTP (no admin exists to grant), and every app
// otherwise writes the same one-off job.
const (
	//ds:def id=cmdadmin-5rk2wq8n owner=@khanakia stability=stable
	CmdAdmin = "admin"
	//ds:def id=adminsubgrant-7mt4xk2p owner=@khanakia stability=stable
	AdminGrant = "grant"
	//ds:def id=adminsubcreate-9vq3nw6r owner=@khanakia stability=stable
	AdminCreate = "create"
)

// Flags of the admin subcommands. The password is never a flag: argv is
// visible to every process on the machine and lands in shell history, so it
// arrives on stdin only (FlagPasswordStdin), as `docker login
// --password-stdin` does.
const (
	flagEmail         = "email"
	flagName          = "name"
	flagJSON          = "json"
	flagDryRun        = "dry-run"
	FlagPasswordStdin = "password-stdin"
)

// AdminGranter is what `auth admin` needs from the admin plugin: the method
// `*admin.Plugin` has. Found through auth.PluginOf, so this package imports no
// plugin and an app registers nothing extra.
type AdminGranter interface {
	auth.Plugin
	Grant(ctx context.Context, userID string) error
}

// AddressSetter is what `auth admin` needs from the identifier plugin that
// owns addresses: its kind, to find a user by address, and SetFor, to give a
// created user a verified one. `*email.Plugin` has both. The kind is read
// from the plugin rather than named here, so this package never spells the
// email plugin's constant.
type AddressSetter interface {
	auth.Plugin
	Identifiers() []auth.IdentifierKind
	SetFor(ctx context.Context, userID, address string, verified bool) error
}

// PasswordSetter is what `auth admin create --password-stdin` needs from a
// password plugin: the method `*password.Plugin` has, found through
// auth.PluginOf, so the core module never imports the password module.
type PasswordSetter interface {
	auth.Plugin
	SetPassword(ctx context.Context, userID string, password auth.Token) error
}

// Errors of the admin command. Each is a configuration or input problem the
// operator can act on; database errors pass through as they are.
var (
	// ErrNoAdminPlugin: the Auth has no plugin with a Grant method.
	ErrNoAdminPlugin = errors.New("authcli: the admin plugin is not registered (auth.WithPlugins(admin.New()))")
	// ErrNoAddressPlugin: no plugin can find or set an address.
	ErrNoAddressPlugin = errors.New("authcli: no identifier plugin can set an address (auth.WithPlugins(email.New(...)))")
	// ErrNoPasswordPlugin: --password-stdin with no plugin that sets passwords.
	ErrNoPasswordPlugin = errors.New("authcli: no plugin can set a password (auth.WithPlugins(password.New()))")
	// ErrNoPassword: --password-stdin given and stdin was empty.
	ErrNoPassword = errors.New("authcli: --password-stdin: nothing was read from stdin")
)

// AdminResult is what `auth admin --json` prints: the user acted on and what
// was done. Under --dry-run nothing was done and DryRun says so, so a script
// never mistakes a rehearsal for the real thing.
//
//ds:def id=cli-adminresult-4wn8pq2k owner=@khanakia stability=stable
type AdminResult struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	// Created is true when `create` made the user; `grant` leaves it false.
	Created bool `json:"created"`
	// Granted is true when the user is now an admin by this command.
	Granted bool `json:"granted"`
	// PasswordSet is true when a password was read from stdin and set.
	PasswordSet bool `json:"passwordSet"`
	DryRun      bool `json:"dryRun"`
}

// adminFlags are the parsed flags both subcommands share.
type adminFlags struct {
	email, name           string
	asJSON, dryRun, stdin bool
}

// admin routes `auth admin <grant|create>`. stdin is read only under
// --password-stdin.
func admin(ctx context.Context, a *auth.Auth, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != AdminGrant && args[0] != AdminCreate) {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	fs := newFlags(CmdAdmin, stderr)
	var f adminFlags
	fs.StringVar(&f.email, flagEmail, "", "the user's address")
	fs.BoolVar(&f.asJSON, flagJSON, false, "print JSON instead of a sentence")
	fs.BoolVar(&f.dryRun, flagDryRun, false, "say what would be done and change nothing")
	if sub == AdminCreate {
		fs.StringVar(&f.name, flagName, "", "the user's display name")
		fs.BoolVar(&f.stdin, FlagPasswordStdin, false, "read the password from stdin")
	}
	if code, stop := parse(fs, rest); stop {
		return code
	}
	if fs.NArg() > 0 || strings.TrimSpace(f.email) == "" {
		fmt.Fprintf(stderr, "auth admin %s needs --email\n%s", sub, usage)
		return ExitUsage
	}
	var (
		res AdminResult
		err error
	)
	switch sub {
	case AdminGrant:
		res, err = adminGrant(ctx, a, f)
	default:
		res, err = adminCreate(ctx, a, f, stdin)
	}
	if err != nil {
		fmt.Fprintln(stderr, "auth admin "+sub+":", err)
		if errors.Is(err, ErrNoPassword) {
			return ExitUsage
		}
		return ExitFailed
	}
	if err := printAdmin(res, f.asJSON, stdout); err != nil {
		fmt.Fprintln(stderr, "auth admin "+sub+":", err)
		return ExitFailed
	}
	return ExitOK
}

// adminPlugins finds the plugins the command works through. The admin and
// address plugins are always needed; the password plugin only when a password
// is to be set, so an app without passwords (magic links, OAuth) still has the
// command.
func adminPlugins(a *auth.Auth, needPassword bool) (AdminGranter, AddressSetter, PasswordSetter, error) {
	granter, err := auth.PluginOf[AdminGranter](a)
	if err != nil {
		return nil, nil, nil, ErrNoAdminPlugin
	}
	addresses, err := auth.PluginOf[AddressSetter](a)
	if err != nil || len(addresses.Identifiers()) == 0 {
		return nil, nil, nil, ErrNoAddressPlugin
	}
	var passwords PasswordSetter
	if needPassword {
		if passwords, err = auth.PluginOf[PasswordSetter](a); err != nil {
			return nil, nil, nil, ErrNoPasswordPlugin
		}
	}
	return granter, addresses, passwords, nil
}

// adminGrant makes the owner of a verified address an admin. Verified only:
// admin rights for whoever typed an address at sign-up would be a takeover.
func adminGrant(ctx context.Context, a *auth.Auth, f adminFlags) (AdminResult, error) {
	granter, addresses, _, err := adminPlugins(a, false)
	if err != nil {
		return AdminResult{}, err
	}
	kind := addresses.Identifiers()[0].Name
	idn, err := a.FindIdentity(ctx, kind, f.email, true)
	if err != nil {
		return AdminResult{}, fmt.Errorf("find a verified %s %q: %w", kind, f.email, err)
	}
	res := AdminResult{UserID: idn.UserID, Email: idn.Value, DryRun: f.dryRun}
	if f.dryRun {
		return res, nil
	}
	if err := granter.Grant(ctx, idn.UserID); err != nil {
		return AdminResult{}, err
	}
	res.Granted = true
	return res, nil
}

// adminCreate creates a user with a verified address, a password when one
// arrives on stdin, and admin rights, in one transaction: a refused password
// or a taken address leaves no half-made user. The address is verified
// because the operator vouches for it; nobody else could, and an unverified
// admin could not sign in under RequireVerified.
func adminCreate(ctx context.Context, a *auth.Auth, f adminFlags, stdin io.Reader) (AdminResult, error) {
	// The password is read first: an empty pipe is a usage error, told
	// before any configuration or database problem.
	var password auth.Token
	if f.stdin {
		var err error
		if password, err = readPassword(stdin); err != nil {
			return AdminResult{}, err
		}
	}
	granter, addresses, passwords, err := adminPlugins(a, f.stdin)
	if err != nil {
		return AdminResult{}, err
	}
	kind := addresses.Identifiers()[0].Name
	value, err := a.Normalize(kind, f.email)
	if err != nil {
		return AdminResult{}, err
	}
	res := AdminResult{Email: value, DryRun: f.dryRun, PasswordSet: f.stdin}
	if f.dryRun {
		// The one check a rehearsal can make without writing: the address
		// is not another account's.
		if _, err := a.FindIdentity(ctx, kind, value, true); err == nil {
			return AdminResult{}, auth.ErrIdentityTaken
		} else if !errors.Is(err, auth.ErrIdentityNotFound) {
			return AdminResult{}, err
		}
		return res, nil
	}
	err = a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		u, err := a.CreateUser(ctx, auth.NewUser{Name: f.name})
		if err != nil {
			return err
		}
		res.UserID, res.Created = u.ID, true
		if err := addresses.SetFor(ctx, u.ID, f.email, true); err != nil {
			return err
		}
		if f.stdin {
			if err := passwords.SetPassword(ctx, u.ID, password); err != nil {
				return err
			}
		}
		if err := granter.Grant(ctx, u.ID); err != nil {
			return err
		}
		res.Granted = true
		return nil
	})
	if err != nil {
		return AdminResult{}, err
	}
	return res, nil
}

// readPassword reads the whole of stdin and drops one trailing line break,
// which is what `echo` and a heredoc add; anything else, spaces included, is
// the password. Empty is ErrNoPassword: a pipe that produced nothing is a
// script bug, not a request for an empty password.
func readPassword(stdin io.Reader) (auth.Token, error) {
	if stdin == nil {
		return "", ErrNoPassword
	}
	b, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read the password from stdin: %w", err)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" {
		return "", ErrNoPassword
	}
	return auth.Token(s), nil
}

// printAdmin prints the result as one sentence, or as JSON under --json.
func printAdmin(res AdminResult, asJSON bool, w io.Writer) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	var s string
	switch {
	case res.DryRun && res.Created, res.DryRun && res.UserID == "":
		s = fmt.Sprintf("would create %s as an admin", res.Email)
	case res.DryRun:
		s = fmt.Sprintf("would grant admin to %s (%s)", res.Email, res.UserID)
	case res.Created:
		s = fmt.Sprintf("created %s (%s) as an admin", res.Email, res.UserID)
	default:
		s = fmt.Sprintf("%s (%s) is an admin", res.Email, res.UserID)
	}
	if res.PasswordSet && !res.DryRun {
		s += " with the password from stdin"
	}
	_, err := fmt.Fprintln(w, s)
	return err
}

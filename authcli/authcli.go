// Package authcli is the command line an app gives its operators for the
// auth schema: apply migrations, print them as SQL, or show what is pending.
//
// It is a package, not a binary, because only the app knows its plugin list,
// and the plugin list decides the migrations. The app wires it into its own
// main or its own CLI framework:
//
//	if len(os.Args) > 1 && os.Args[1] == "auth" {
//		os.Exit(authcli.Main(ctx, a, os.Args[2:], os.Stdout, os.Stderr))
//	}
package authcli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/ubgo/auth"
)

// Exit codes: the library-wide convention for command lines. ExitFailed means
// the command ran and failed (the reason is on stderr); ExitUsage means it
// never ran because the arguments were wrong, so a script can tell a typo
// from a broken database.
const (
	//ds:def id=exitok-gnrts3ej owner=@khanakia stability=stable
	ExitOK = 0
	//ds:def id=exitfailed-ssu2cn9e owner=@khanakia stability=stable
	ExitFailed = 1
	//ds:def id=exitusage-d43sp75x owner=@khanakia stability=stable
	ExitUsage = 2
)

// Commands: the words Main routes on, after the "auth" word the app routed on.
// CmdSQL, CmdStatus and CmdOrphans are subcommands of CmdMigrate.
const (
	//ds:def id=cmdmigrate-mr367qab owner=@khanakia stability=stable
	CmdMigrate = "migrate"
	//ds:def id=cmdsql-y9ntekef owner=@khanakia stability=stable
	CmdSQL = "sql"
	//ds:def id=cmdstatus-cebt94q5 owner=@khanakia stability=stable
	CmdStatus = "status"
	//ds:def id=cmdorphans-ue59r4y3 owner=@khanakia stability=stable
	CmdOrphans = "orphans"
	// CmdCheck compares the live schema with the code: pending and changed
	// migrations, missing tables and columns. ExitFailed when anything is
	// behind, so a deploy script can gate on it.
	//ds:def id=cmdcheck-7hq3xw2n owner=@khanakia stability=stable
	CmdCheck = "check"
	//ds:def id=cmdsweep-nsszxzc2 owner=@khanakia stability=stable
	CmdSweep = "sweep"
	// CmdMaintain runs the plugins' scheduled jobs (auth.Maintain), such as
	// plugin/stale's mails to dormant accounts. Unlike sweep it can send mail and
	// delete accounts, so it is a command of its own and `--dry-run` shows what
	// it would do first.
	//ds:def id=cmdmaintain-4wn8qk3v owner=@khanakia stability=stable
	CmdMaintain = "maintain"
	//ds:def id=cmdinfo-7wkd3xqn owner=@khanakia stability=stable
	CmdInfo = "info"
	// CmdSecret prints a fresh random value for auth.EnvSecret. It touches
	// no database.
	//ds:def id=cmdsecret-3wq8nk5v owner=@khanakia stability=stable
	CmdSecret = "secret"
	// CmdGenerate is `migrate sql` under a second name (`generate`):
	// every migration as SQL, for a migration tool the app already runs.
	//ds:def id=cmdgenerate-8nd2xq4w owner=@khanakia stability=stable
	CmdGenerate = "generate"
)

// SecretBytes is how many random bytes `auth secret` draws: auth.MinSecretSize,
// printed base64-encoded, so the value is longer than the minimum and holds
// the full 256 bits.
//
//ds:def id=secretbytes-5kq2mw8n owner=@khanakia stability=stable
const SecretBytes = auth.MinSecretSize

//ds:def id=usage-9kra29g4
const usage = `usage: auth sweep [--retention 168h] delete expired sessions, tokens and plugin rows;
                                     with WithDeliveryOutbox, send the outbox's due messages
       auth maintain [--dry-run]   run the plugins' scheduled jobs (mail to dormant accounts,
                                     deletion of the ones that never answered);
                                     --dry-run counts them and changes nothing
       auth migrate [--dry-run]    apply pending migrations
       auth migrate sql              print every migration as SQL, change nothing
       auth migrate status           list migrations and whether each is applied
       auth migrate orphans          list tables, columns and owners no plugin claims now
       auth migrate check            fail unless the database holds every table, column and migration the code needs
       auth generate                 the same as auth migrate sql
       auth info [--json]            print the wiring: version, engine, plugins, routes, lifetimes
       auth secret [--value]         print AUTH_SECRET=<a fresh random secret> (--value: the value alone)
       auth client ts --out dir      write the typed TypeScript client of this app's routes into dir
       auth admin grant --email x    make the owner of a verified address an admin
       auth admin create --email x [--name y] [--password-stdin]
                                     create a user with a verified address and admin rights
                                     (--json prints the result as JSON, --dry-run changes nothing)

examples:
  myapp auth migrate status
  myapp auth migrate --dry-run
  myapp auth migrate check && myapp serve
  myapp auth migrate sql > schema.sql
  myapp auth info --json
  myapp auth secret --value | gopass insert -f myapp/auth-secret
  myapp auth client ts --out web/src/auth
  myapp auth admin grant --email alice@example.com
  echo "$ADMIN_PASSWORD" | myapp auth admin create --email root@example.com --name Root --password-stdin
  myapp auth admin create --email root@example.com --dry-run --json
`

// Main runs one command and returns its exit code. args excludes the
// program name and the "auth" word the app routed on. Output meant for a pipe
// (the SQL, the status table) goes to stdout; usage and errors go to stderr.
// Every command but "migrate" without a subcommand, "sweep", "maintain" and
// "admin" is read-only. A password for `admin create --password-stdin` is read from the
// process's standard input; MainWithStdin takes another reader.
//
//ds:def id=main-tduqyp9t
func Main(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) int {
	return MainWithStdin(ctx, a, args, os.Stdin, stdout, stderr)
}

// MainWithStdin is Main with an explicit standard input, for an app that
// embeds the command line behind its own and for tests. Only `admin create
// --password-stdin` reads it.
//
//ds:def id=mainwithstdin-6kp3rq2w owner=@khanakia stability=stable
func MainWithStdin(ctx context.Context, a *auth.Auth, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case CmdSweep:
			return sweep(ctx, a, args[1:], stdout, stderr)
		case CmdMaintain:
			return maintain(ctx, a, args[1:], stdout, stderr)
		case CmdAdmin:
			return admin(ctx, a, args[1:], stdin, stdout, stderr)
		case CmdInfo:
			return info(a, args[1:], stdout, stderr)
		case CmdSecret:
			return secret(args[1:], rand.Reader, stdout, stderr)
		case CmdClient:
			return client(a, args[1:], stdout, stderr)
		case CmdGenerate:
			args = append([]string{CmdMigrate, CmdSQL}, args[1:]...)
		}
	}
	if len(args) == 0 || args[0] != CmdMigrate {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	fs := newFlags(CmdMigrate, stderr)
	dry := fs.Bool("dry-run", false, "list what would be applied and change nothing")
	rest := args[1:]
	sub := ""
	if len(rest) > 0 && (rest[0] == CmdSQL || rest[0] == CmdStatus || rest[0] == CmdOrphans || rest[0] == CmdCheck) {
		sub, rest = rest[0], rest[1:]
	}
	if code, stop := parse(fs, rest); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n%s", fs.Arg(0), usage)
		return ExitUsage
	}
	var err error
	switch {
	case sub == CmdSQL:
		err = printSQL(a, stdout)
	case sub == CmdStatus:
		err = status(ctx, a, stdout, false)
	case sub == CmdOrphans:
		err = orphans(ctx, a, stdout)
	case sub == CmdCheck:
		err = check(ctx, a, stdout)
	case *dry:
		err = status(ctx, a, stdout, true)
	default:
		err = migrate(ctx, a, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "auth migrate:", err)
		return ExitFailed
	}
	return ExitOK
}

// newFlags returns a flag set that answers -h and a bad flag with the whole
// usage text, because every command shares one.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	return fs
}

// parse parses args into fs. stop is true when parsing ended the command, and
// code is then what Main returns: ExitOK for -h, which asked for the usage and
// got it, and ExitUsage for a bad flag.
func parse(fs *flag.FlagSet, args []string) (code int, stop bool) {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return ExitOK, false
	case errors.Is(err, flag.ErrHelp):
		return ExitOK, true
	default:
		return ExitUsage, true
	}
}

// secret prints a new value for auth.EnvSecret, read from random (crypto/rand
// in Main, a fixed reader in tests).
func secret(args []string, random io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags(CmdSecret, stderr)
	valueOnly := fs.Bool("value", false, "print the value alone, without the variable name")
	if code, stop := parse(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n%s", fs.Arg(0), usage)
		return ExitUsage
	}
	b := make([]byte, SecretBytes)
	if _, err := io.ReadFull(random, b); err != nil {
		fmt.Fprintln(stderr, "auth secret:", err)
		return ExitFailed
	}
	v := base64.StdEncoding.EncodeToString(b)
	if !*valueOnly {
		v = auth.EnvSecret + "=" + v
	}
	fmt.Fprintln(stdout, v)
	return ExitOK
}

func printSQL(a *auth.Auth, w io.Writer) error {
	script, err := a.MigrationSQL()
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, script)
	return err
}

// Migration states, as status prints them in its first column.
const (
	stateApplied = "applied"
	statePending = "pending"
	// stateChanged is upper case so a changed migration stands out in a long
	// list: it blocks Migrate until an operator looks at it.
	stateChanged = "CHANGED"
)

// Column layout of the status table: no minimum width, and two spaces between
// columns, which keeps the output aligned and still greppable.
const (
	tableMinWidth = 0
	tableTabWidth = 2
	tablePadding  = 2
)

// status prints the ledger comparison; pendingOnly is the dry run. A changed
// migration is an error in both, because Migrate would refuse to run.
func status(ctx context.Context, a *auth.Auth, w io.Writer, pendingOnly bool) error {
	states, err := a.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, tableMinWidth, tableTabWidth, tablePadding, ' ', 0)
	changed, pending := 0, 0
	for _, s := range states {
		label := stateApplied
		switch {
		case s.Changed:
			label, changed = stateChanged, changed+1
		case !s.Applied:
			label, pending = statePending, pending+1
		case pendingOnly:
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", label, s.Owner, s.Name)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "%d pending, %d changed, %d total\n", pending, changed, len(states))
	if changed > 0 {
		return fmt.Errorf("%w: %d migration(s)", auth.ErrChecksumMismatch, changed)
	}
	return nil
}

func migrate(ctx context.Context, a *auth.Auth, w io.Writer) error {
	done, err := a.Migrate(ctx)
	for _, d := range done {
		fmt.Fprintln(w, "applied", d)
	}
	if err != nil {
		return err
	}
	if len(done) == 0 {
		fmt.Fprintln(w, "nothing to apply")
	}
	return nil
}

// orphans prints what no registered plugin owns. It deletes nothing; the
// operator decides.
func orphans(ctx context.Context, a *auth.Auth, w io.Writer) error {
	list, err := a.Orphans(ctx)
	if err != nil {
		return err
	}
	for _, o := range list {
		fmt.Fprintf(w, "%s\t%s\n", o.Kind, o.Name)
	}
	fmt.Fprintf(w, "%d orphan(s)\n", len(list))
	return nil
}

// check prints what the database lacks and fails when it lacks anything.
// "schema ok" on success, so a deploy log shows the check ran.
func check(ctx context.Context, a *auth.Auth, w io.Writer) error {
	r, err := a.CheckSchema(ctx)
	if err != nil {
		return err
	}
	for _, m := range r.PendingMigrations {
		fmt.Fprintf(w, "pending\t%s\n", m)
	}
	for _, m := range r.ChangedMigrations {
		fmt.Fprintf(w, "%s\t%s\n", stateChanged, m)
	}
	for _, t := range r.MissingTables {
		fmt.Fprintf(w, "missing table\t%s\n", t)
	}
	for _, c := range r.MissingColumns {
		fmt.Fprintf(w, "missing column\t%s\n", c)
	}
	if !r.OK() {
		return fmt.Errorf("%w: %d pending, %d changed, %d missing table(s), %d missing column(s)", auth.ErrSchemaBehind,
			len(r.PendingMigrations), len(r.ChangedMigrations), len(r.MissingTables), len(r.MissingColumns))
	}
	fmt.Fprintln(w, "schema ok")
	return nil
}

// sweep runs a.Sweep and prints what it deleted, sorted by name, then, with
// the delivery outbox on, a.SendOutbox and what it sent.
func sweep(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) int {
	fs := newFlags(CmdSweep, stderr)
	retention := fs.Duration("retention", auth.DefaultSweepRetention, "keep spent tokens this long")
	if code, stop := parse(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 || *retention < 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	res, err := a.Sweep(ctx, *retention)
	names := make([]string, 0, len(res))
	for n := range res {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		fmt.Fprintf(stdout, "%s\t%d\n", n, res[n])
	}
	if err != nil {
		fmt.Fprintln(stderr, "auth sweep:", err)
		return ExitFailed
	}
	if !a.DeliveryOutbox() {
		return ExitOK
	}
	// Sweep never sends; with the outbox on, the same scheduled run retries
	// the messages a crash or a failed send left behind.
	sent, err := a.SendOutbox(ctx)
	fmt.Fprintf(stdout, "%s\t%d\n%s\t%d\n", outboxSentKey, sent.Sent, outboxFailedKey, sent.Failed)
	if err != nil {
		fmt.Fprintln(stderr, "auth sweep:", err)
		return ExitFailed
	}
	return ExitOK
}

// maintain runs a.Maintain and prints each counter, sorted by name; a plugin
// that fails stops the run after the counters it had.
func maintain(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) int {
	fs := newFlags(CmdMaintain, stderr)
	dry := fs.Bool("dry-run", false, "count what would happen and change nothing")
	if code, stop := parse(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	res, err := a.Maintain(ctx, auth.MaintainOptions{DryRun: *dry})
	names := make([]string, 0, len(res))
	for n := range res {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		fmt.Fprintf(stdout, "%s\t%d\n", n, res[n])
	}
	if err != nil {
		fmt.Fprintln(stderr, "auth maintain:", err)
		return ExitFailed
	}
	return ExitOK
}

// The lines "auth sweep" adds under WithDeliveryOutbox, after the deleted
// counts: how many outbox messages it sent and how many sends failed.
const (
	outboxSentKey   = "outbox.sent"
	outboxFailedKey = "outbox.failed"
)

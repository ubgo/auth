// Command stale-accounts mails the owners of dormant accounts and deletes the
// accounts that never answer, with plugin/stale. An account nobody has signed
// in to for 180 days gets one warning mail; if its owner still has not signed
// in 30 days later, a final mail is queued and the account is deleted in the
// same transaction. Any sign-in in between clears the warning.
//
//	AUTH_SECRET=$(openssl rand -hex 32) go run ./stale-accounts                     # serve
//	AUTH_SECRET=$(openssl rand -hex 32) go run ./stale-accounts auth maintain --dry-run   # count, change nothing
//	AUTH_SECRET=$(openssl rand -hex 32) go run ./stale-accounts auth maintain       # warn and delete
//
// Nothing runs by itself: the library has no timer, so the app runs "auth
// maintain" from its own scheduler (cron, a Kubernetes CronJob, a systemd
// timer), or calls auth.Maintain from a job of its own. Mail is printed to the
// log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/stale"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "stale-accounts.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// authCommand is the first argument that hands the rest of the command
	// line to authcli, as in the cli example: "auth maintain", "auth migrate".
	authCommand = "auth"
	// day is the unit the periods below are counted in.
	day = 24 * time.Hour
	// inactiveAfter is how long an account may go without a sign-in before its
	// owner is warned. The plugin's default is a year (stale.DefaultInactiveAfter)
	// and it accepts no less than a week (stale.MinInactiveAfter).
	inactiveAfter = 180 * day
	// deletionGrace is the time between the warning and the deletion: long
	// enough for the owner to read the mail and sign in. At least
	// stale.MinDeletionGrace.
	deletionGrace = 30 * day
)

var (
	// port is 8081, or $PORT when it is set, so two examples can run side by
	// side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas: WAL so readers do not block the writer, and a busy timeout
// instead of an immediate "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	base := []auth.Option{auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithPlugins(plugins(email.MailerFunc(logMail))...)}
	a, err := auth.New(append(base, options([]byte(os.Getenv(auth.EnvSecret)))...)...)
	if err != nil {
		log.Fatal(err) // a missing AUTH_SECRET fails here: the outbox seals mail with a key derived from it
	}
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	if code, handled := command(ctx, a, os.Args[1:], os.Stdout, os.Stderr); handled {
		_ = a.Close() // os.Exit skips the deferred calls; Close waits for mail in flight
		os.Exit(code)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// command runs "auth ..." through authcli and reports handled=true with its
// exit code; any other command line is the server's, and handled is false.
// "auth maintain" runs auth.Maintain, which runs plugin/stale and prints its
// counters (stale.warned, stale.deleted, …); "--dry-run" counts and changes
// nothing.
//
//ds:def id=staleaccounts-example-command-2kx7qn4w
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}

// options are the settings the stale plugin needs beside the database:
// deletion (stale.DeleteAfterWarning) requires the delivery outbox, so the
// final mail is stored in the transaction that deletes the account and sent
// (and retried) afterwards; without it a crash could delete an account whose
// owner was never told, and auth.New refuses the plugin. The outbox seals
// each stored message with a key derived from secret, which must be at least
// auth.MinSecretSize bytes.
//
//ds:def id=staleaccounts-example-options-6wn2qk8x
func options(secret []byte) []auth.Option {
	return []auth.Option{auth.WithSecret(secret), auth.WithDeliveryOutbox()}
}

// plugins is the app's plugin list. The warning goes to the user's best
// recovery channel, so the email plugin is built with Recover; an account
// with no verified address is counted as stale.no_channel and never deleted.
// An app adding the plugin to an existing user table also passes
// stale.Since(installTime): accounts older than the plugin have no recorded
// sign-in, and without it the first run would call every one of them inactive.
//
//ds:def id=staleaccounts-example-plugins-3qk8wn5v
func plugins(m email.Mailer) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		stale.New(stale.InactiveAfter(inactiveAfter), stale.DeleteAfterWarning(deletionGrace)),
	}
}

// newHandler mounts the library's routes.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

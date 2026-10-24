// Command cli is the quick start app with the operator's command line built
// in: the same binary serves the app and runs "auth migrate" and "auth sweep".
//
//	go run ./cli auth migrate --dry-run   # what would be applied
//	go run ./cli auth migrate             # apply it
//	go run ./cli auth migrate status      # every migration and its state
//	go run ./cli auth migrate sql         # the schema as SQL, for review
//	go run ./cli auth sweep               # delete expired sessions and tokens
//	go run ./cli auth info                # the settled wiring, for a support request
//	go run ./cli                          # serve; refuses while migrations are pending
//
// The command line is a package, not a binary of its own, because only the
// app knows its plugin list, and the plugin list decides the migrations.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "cli.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// authCommand is the first argument that hands the rest of the command
	// line to authcli. Any word works; the app picks one that cannot clash
	// with its own commands.
	authCommand = "auth"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file. It
// escapes only the path, never building a url.URL with a scheme, because Go
// writes a relative path such as "auth.db" as "file://auth.db", which SQLite
// reads as a host.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

//ds:def id=main-p5jr79xp
func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, os.LookupEnv)
	if err != nil {
		log.Fatal(err) // a malformed AUTH_* variable or a broken plugin combination fails here, not in production
	}
	defer a.Close()

	ctx := context.Background()
	if code, handled := command(ctx, a, os.Args[1:], os.Stdout, os.Stderr); handled {
		_ = a.Close() // os.Exit skips the deferred calls
		os.Exit(code)
	}

	if err := requireMigrated(ctx, a); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// command runs "auth ..." through authcli and reports handled=true with its
// exit code; any other command line is the server's, and handled is false.
//
//ds:def id=command-5hg2hb73
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}

// errPending is returned by requireMigrated when the schema is behind.
var errPending = fmt.Errorf("auth migrations are pending; run %q first", authCommand+" "+authcli.CmdMigrate)

// requireMigrated refuses to serve while any migration is pending or changed.
// The server does not migrate by itself here: with several instances, the
// operator (or the deploy job) runs "auth migrate" once, and a server that
// starts against an old schema fails loudly instead of at the first query.
//
//ds:def id=requiremigrated-nmbrfr8y
func requireMigrated(ctx context.Context, a *auth.Auth) error {
	states, err := a.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	for _, s := range states {
		if !s.Applied || s.Changed {
			return errPending
		}
	}
	return nil
}

// newAuth wires the library: email addresses to sign in with and recover
// through, and passwords. lookup is where the AUTH_* variables come from
// (os.LookupEnv in main, a map in the tests), so nothing reads the process
// environment behind the caller's back. extra is for options the test adds,
// such as a clock.
func newAuth(db *sql.DB, m email.Mailer, lookup func(string) (string, bool), extra ...auth.Option) (*auth.Auth, error) {
	env, err := envOptions(lookup)
	if err != nil {
		return nil, err
	}
	opts := []auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	}
	return auth.New(append(append(opts, env...), extra...)...)
}

// envOptions reads the AUTH_* variables (AUTH_BASE_URL, AUTH_SESSION_IDLE, …)
// through lookup and logs which ones are set, so a deploy's configuration is
// in its first log lines. Its options come after the defaults in newAuth, so
// a set variable wins and an unset one leaves the default; a malformed value
// is an error naming the variable, which stops the deploy instead of running
// with the default.
//
//ds:def id=cli-envoptions-9423x8e8
func envOptions(lookup func(string) (string, bool)) ([]auth.Option, error) {
	opts, err := auth.EnvOptions(lookup)
	if err != nil {
		return nil, err
	}
	for _, name := range auth.EnvVars {
		state := "default"
		if _, ok := lookup(name); ok {
			state = "set"
		}
		log.Printf("config %s: %s", name, state) // never the value: AUTH_SECRET is one of them
	}
	return opts, nil
}

// newHandler mounts the library's routes and one page of the app's own that
// only a signed-in user may see.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID    string `json:"id"`
	Hello string `json:"hello"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Hello: u.Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

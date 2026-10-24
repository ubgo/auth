// Command plugin-sweeper is an app with a plugin whose rows expire: the
// tickets plugin in ./tickets mints short-lived links to a path of the app,
// hands each one over as a response header (an effect), and deletes the
// expired ones when the app sweeps (a Sweeper).
//
//	go run ./plugin-sweeper              # serve on http://localhost:8081
//	go run ./plugin-sweeper auth sweep   # delete what has expired, then exit
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/examples/plugin-sweeper/tickets"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "plugin-sweeper.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// filesPrefix is the app's own pages a ticket can open.
	filesPrefix = "/files/"
	// cliWord is the first argument that hands the rest to authcli.
	cliWord = "auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, time.Now)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// "myapp auth sweep" runs Auth.Sweep with this app's plugin list, which
	// is what makes the tickets plugin's Sweep part of it.
	if len(os.Args) > 1 && os.Args[1] == cliWord {
		os.Exit(authcli.Main(context.Background(), a, os.Args[2:], os.Stdout, os.Stderr))
	}
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the library with the tickets plugin last. clock is
// time.Now in main; the test passes one it can move forward, to expire a
// ticket without waiting.
func newAuth(db *sql.DB, m email.Mailer, clock func() time.Time) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithClock(clock),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			tickets.New(),
		),
	)
}

// newHandler mounts the library's routes, which now include
// POST /auth/tickets/mint and GET /auth/tickets/redeem, and the pages a
// ticket opens.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+filesPrefix+"{name}", file)
	return mux
}

// file stands in for whatever a ticket opens: a download, a report, a
// shared page.
func file(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("contents of " + r.PathValue("name") + "\n")) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

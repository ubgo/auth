// Command ts-client-bearer is the server behind two Node programs that use
// the typed TypeScript client where no browser keeps the cookie: web/cli.ts,
// a command-line program that keeps its bearer token in a file so it stays
// signed in between runs, and web/server.ts, a Node HTTP server that renders
// for a browser by forwarding that browser's Cookie header to this API.
//
//	PORT=8111 go run ./ts-client-bearer
//	AUTH_URL=http://localhost:8111 node ts-client-bearer/web/cli.ts sign-up ada@example.com "correct horse battery staple" Ada
//
// The database is ts-client-bearer.db (SQLite) in the current directory.
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
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created where you run the program.
	dbFile = "ts-client-bearer.db"
	// authPrefix is where the JSON routes are mounted; the client's baseURL ends with it.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is where the server listens: 8081, or $PORT.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's origin: the only one allowed to send
	// cookie-authenticated POSTs. Bearer requests carry no cookie, so the
	// CLI needs no Origin.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys, which the library's cascades depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so
// a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email and password sign-in; the two programs need nothing
// more. Bearer mode is not a server option: a client asks for it per
// request with the Auth-Token-Mode header, which the TypeScript client sends
// when built with tokenMode "bearer".
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// newHandler mounts the library's routes.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

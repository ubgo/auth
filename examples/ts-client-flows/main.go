// Command ts-client-flows is the server behind web/flows.ts, which runs the
// flows beyond a plain sign-in with the typed TypeScript client from Node:
// email verification, password reset, a magic link, sign out everywhere, a
// mailed second-factor code and an organization. Mail goes to an in-memory
// inbox served at /dev/mail (devmail.go), so the script reads each link or
// code the way a person would read their mailbox.
//
//	PORT=8110 go run ./ts-client-flows
//	AUTH_URL=http://localhost:8110 node ts-client-flows/web/flows.ts
//
// The database is ts-client-flows.db (SQLite) in the current directory.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created where you run the program.
	dbFile = "ts-client-flows.db"
	// authPrefix is where the JSON routes are mounted; the client's baseURL ends with it.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// envAppURL names the variable holding the web app's origin, which mail
	// links point at. The script never opens those pages; it reads the token
	// out of the link, as the page would.
	envAppURL = "APP_URL"
)

var (
	// port is where the server listens: 8081, or $PORT.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the web app's origin: links in mail point at its pages.
	baseURL = cmp.Or(os.Getenv(envAppURL), "http://localhost:"+port)
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

	key := make([]byte, auth.SealKeySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	box := &devMailbox{}
	a, err := newAuth(db, box, key)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on http://%s (mail links point at %s)", addr, baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, box), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires every flow the script runs. The second factor is the mailed
// code (DeliveredCodes) and not an authenticator app, so the script needs no
// TOTP code and no wait for the next 30-second step. The plugin still asks
// for a sealing key; with WithoutTOTP no factor stores a secret under it, so
// main's random key per start loses nothing at a restart. An app with TOTP
// keeps a fixed key (see the two-factor example).
func newAuth(db *sql.DB, m email.Mailer, key []byte) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			magiclink.New(),
			twofactor.New(twofactor.WithEncryptionKey(key), twofactor.DeliveredCodes(), twofactor.WithoutTOTP()),
			organization.New(),
		),
	)
}

// newHandler mounts the library's routes and the example-only inbox.
func newHandler(a *auth.Auth, box *devMailbox) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(devMailPath, box)
	return mux
}

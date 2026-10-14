// Command kms-sealer keeps the secrets the library stores at rest (here, the
// TOTP secrets and recovery codes of two-factor sign-in) encrypted by a key
// service, so no encryption key for them ever sits in the app's memory.
//
//	go run ./kms-sealer
//
// The key service is a fake in this process (kms.go) with the shape of Vault
// transit or a cloud KMS: the app hands it a plaintext and a context, and
// stores the text it gets back. Mail is printed to the log.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "kms-sealer.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// appName is what authenticator apps show above the code.
	appName = "Acme"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr listens on this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL: the one origin allowed to send
	// cookie-authenticated POSTs.
	baseURL = "http://" + addr
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	// The fake service's keys live only in this process, so factors
	// enrolled in one run do not open in the next; a real service keeps them.
	kms, err := newFakeKMS()
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, kms)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s; secrets at rest sealed by the key service", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email, password and two-factor sign-in, and makes the key
// service the sealer of every plugin that keeps secrets at rest. twofactor
// gets no key of its own, so it seals through s; so would the oauth plugin's
// stored provider tokens.
//
//ds:def id=kmssealer-newauth-6pw3xr9k
func newAuth(db *sql.DB, s auth.Sealer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSealer(s),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			twofactor.New(twofactor.Issuer(appName)),
		),
	)
}

// newHandler mounts the library's routes and /me, which only a signed-in
// user may see.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID string `json:"id"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID}) // a client that hung up cannot be told
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}

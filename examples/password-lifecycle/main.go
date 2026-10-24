// Command password-lifecycle runs a password through the policies a
// compliance regime asks for, on top of the usual sign-up and sign-in: a reset
// by mailed code instead of a link, a history that refuses recent passwords,
// passwords that expire, and a guard against password spraying spread over
// many accounts.
//
//	AUTH_SECRET=$(openssl rand -base64 32) go run ./password-lifecycle
//
// Mail is printed to the log instead of sent.
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "password-lifecycle.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

// The lifecycle policies. Each is a product decision; these are the values a
// typical security questionnaire asks for.
//
//ds:def id=lifecyclepolicy-pwl7cy01 owner=@khanakia stability=stable
const (
	// historySize is how many passwords a user cannot go back to, counting
	// the one in use.
	historySize = 3
	// maxPasswordAge is how long a password signs in before it must be
	// changed. NIST SP 800-63B advises against expiry; set it only when a
	// policy requires it.
	maxPasswordAge = 90 * 24 * time.Hour
	// sprayFailures is how many failed sign-ins with one password, across
	// every account and IP, refuse that password for the guard's window.
	sprayFailures = 5
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
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// The spraying guard counts each failed password under a keyed hash, so
	// the secret is required; auth.New refuses a missing or short one.
	a, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), logMailer{}, time.Now)
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

// newAuth wires email and password with the four lifecycle policies. The
// clock is a parameter so the test can age a password past maxPasswordAge;
// main passes time.Now.
//
//ds:def id=newauth-pwl7cy02 owner=@khanakia stability=stable
func newAuth(db *sql.DB, secret []byte, m email.Mailer, now func() time.Time) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithClock(now),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(
				password.ResetByCode(),
				password.History(historySize),
				password.ExpireAfter(maxPasswordAge),
				password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: sprayFailures}),
			),
		),
	)
}

// newHandler mounts the library's routes and the app's /me page.
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

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link or code, so you can use it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

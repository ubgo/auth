// Command phone-account adds a phone number to an email-and-password
// account: the signed-in user adds a number, receives a code by SMS, verifies
// it, and can ask for a new code or remove the number. The number does not
// sign in here; it is a verified contact the app can text.
//
//	go run ./phone-account
//
// Mail and texts are printed to the log instead of sent; plug your providers
// into logMailer's and logSMS's places.
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
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "phone-account.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// codeTTL is how long a verify code works. The default text states it.
	codeTTL = 5 * time.Minute
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

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, logSMS{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email and password for sign-in, and the phone plugin with no
// sign-in option: a number is added and verified by a signed-in user, and
// that is all. The test builds the app with the same function.
//
//ds:def id=newauth-6gtjg8r8
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			phone.New(phone.WithSMS(sms), phone.WithCodeTTL(codeTTL)),
		),
	)
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))
	return mux
}

// appUser is the app's composite user: auth_user's columns are flat, and the
// number, which lives in auth_identity, is a nested struct loaded by a join in
// the same statement (ADR-0001). Only a verified number is primary, so the
// join finds nothing until the code is checked.
//
//ds:def id=appuser-29xtgc36
type appUser struct {
	auth.User
	Phone phone.Data
}

// Bindings lists every column the composite user reads.
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), phone.UserBindings(&u.Phone))
}

// Joins brings the user's primary phone identity into the query.
func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{phone.UserJoin()} }

// meResponse is what /me answers.
type meResponse struct {
	ID            string `json:"id"`
	Phone         string `json:"phone"`
	PhoneVerified bool   `json:"phoneVerified"`
}

// meHandler loads the signed-in user with their number in one query.
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u appUser
		if err := a.LoadUser(r.Context(), authhttp.MustUser(r).ID, &u); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Phone: u.Phone.Number, PhoneVerified: u.Phone.Verified()}) // a client that hung up cannot be told
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// logSMS prints texts instead of sending them. Replace it with your SMS
// provider's API client.
type logSMS struct{}

// Send logs the text, including the code, so you can type it in by hand.
func (logSMS) Send(_ context.Context, to, text string) error {
	log.Printf("sms to=%s %q", to, text)
	return nil
}

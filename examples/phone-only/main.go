// Command phone-only is a consumer app with no email and no password: people
// sign up and sign in with a phone number and a code sent by SMS.
//
//	go run ./phone-only
//
// Texts are printed to the log instead of sent; plug your SMS provider into
// logSMS's place.
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
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "phone-only.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs.
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

// allowedPrefixes are the country codes the app texts. Every SMS costs money,
// and refusing countries you do not serve is the cheapest defence against
// SMS pumping (attackers triggering texts to premium numbers they own).
var allowedPrefixes = []string{"+1", "+44"}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logSMS{})
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

// newAuth wires the library with the phone plugin alone. SignInWithCode is
// what makes it a sign-in method: without it, auth.New refuses the list
// because nobody could get in. The test builds the app with the same function.
//
//ds:def id=newauth-znczjfa3
func newAuth(db *sql.DB, sms phone.SMSSender) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			phone.New(phone.Login(), phone.Recover(), phone.SignInWithCode(), phone.WithSMS(sms), phone.AllowPrefixes(allowedPrefixes...)),
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
// phone number, which lives in auth_identity, is a nested struct loaded by a
// join in the same statement (ADR-0001).
//
//ds:def id=appuser-dtrcdfrt
type appUser struct {
	auth.User
	Phone phone.Data
}

// Bindings lists every column the composite user reads.
//
//ds:def id=appuser-bindings-r6fpbeqm
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), phone.UserBindings(&u.Phone))
}

// Joins brings the user's primary phone identity into the query.
//
//ds:def id=appuser-joins-zpjfxhmt
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

// logSMS prints texts instead of sending them. Replace it with your SMS
// provider's API client.
type logSMS struct{}

// Send logs the text, including the code, so you can type it in by hand.
func (logSMS) Send(_ context.Context, to, text string) error {
	log.Printf("sms to=%s %q", to, text)
	return nil
}

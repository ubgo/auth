// Command password-policies is the quick start with rules on new passwords:
// a longer minimum, three character classes, a company rule of its own, and
// a check against known breaches through the Have I Been Pwned range API.
// The same rules apply at sign-up, reset and change.
//
//	go run ./password-policies
//
// Mail is printed to the log instead of sent. The breach check calls the
// public range API: only the first five hex characters of the password's
// SHA-1 leave the machine.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	"github.com/ubgo/auth/plugin/password/hibp"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "password-policies.db"
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
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// Password rules. NIST advises length over composition rules; the class rule
// is here because some products must have one.
const (
	// minLength is the shortest password accepted, in characters.
	minLength = 12
	// classes is how many of the four character classes (lowercase,
	// uppercase, digits, everything else) a password must draw from.
	classes = 3
	// forbidden is a word no password may contain, as a company rule.
	forbidden = "acme"
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

// ErrCompanyName is the company rule's own error: a stable code and a message
// the client shows as is. A policy that returns a plain error would answer
// password.weak instead.
//
//ds:def id=errcompanyname-e4xkw4bu owner=@khanakia stability=stable
var ErrCompanyName = auth.NewError("acme.password_company_name", http.StatusBadRequest, "The password must not contain the company name.")

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, hibp.New())
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

// newAuth wires email and password with the rules. The breach checker is a
// parameter so the test can stand in a fake range API; main passes the real
// one. Length is always checked first, then each policy in order, then the
// breach check.
//
//ds:def id=newauth-w7tbnaeb owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, breaches password.BreachChecker) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(
				password.MinLength(minLength),
				password.RequireClasses(classes),
				password.Policy(noCompanyName),
				password.CheckBreached(breaches),
			),
		),
	)
}

// noCompanyName is the company rule: a Policy gets the new password in clear
// and returns nil to accept it. Returning an *auth.Error keeps its code; any
// other error becomes password.weak.
//
//ds:def id=nocompanyname-uxgxwbsh owner=@khanakia stability=stable
func noCompanyName(pw string) error {
	if strings.Contains(strings.ToLower(pw), forbidden) {
		return ErrCompanyName
	}
	return nil
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))
	return mux
}

// meResponse is what /me answers: a settings page shows "set a password" or
// "change password" from HasPassword.
type meResponse struct {
	ID          string `json:"id"`
	HasPassword bool   `json:"hasPassword"`
}

// meHandler asks the password plugin whether the signed-in user has one.
//
//ds:def id=mehandler-a3yb2ukz owner=@khanakia stability=stable
func meHandler(a *auth.Auth) http.Handler {
	pw := passwordPlugin(a)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		has, err := pw.HasPassword(r.Context(), u.ID)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, HasPassword: has}) // a client that hung up cannot be told
	})
}

// passwordPlugin finds the password plugin among those auth.New was given, so
// the handler needs no second reference to it.
func passwordPlugin(a *auth.Auth) *password.Plugin {
	for _, p := range a.Plugins() {
		if pw, ok := p.(*password.Plugin); ok {
			return pw
		}
	}
	panic(errors.New("password-policies: the password plugin is not wired"))
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

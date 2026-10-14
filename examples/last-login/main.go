// Command last-login shows how a user last signed in: a password or a
// magic link, and when. The sign-in page of a real app puts that method in
// front; here /me just says it.
//
//	go run ./last-login
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
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "last-login.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
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

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys, which the library's cascades depend on.
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

	a, ll, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, ll), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email, passwords, magic links and the last-login record. The
// plugin is returned too, because /me reads through it. The test builds the
// app with the same function.
//
//ds:def id=newauth-8r5kw2nx
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *lastlogin.Plugin, error) {
	ll := lastlogin.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			magiclink.New(),
			ll,
		),
	)
	return a, ll, err
}

// newHandler mounts the library's routes and /me.
func newHandler(a *auth.Auth, ll *lastlogin.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me(ll)))))
	return mux
}

// meResponse is what /me answers: who, and how they last signed in.
//
//ds:def id=meresponse-6k3tv9qp
type meResponse struct {
	ID         string     `json:"id"`
	LastMethod string     `json:"lastMethod"`
	LastAt     *time.Time `json:"lastAt"`
}

// me reads the record through the plugin; RequireUser has already refused
// anyone signed out.
//
//ds:def id=me-4w7nx2kt
func me(ll *lastlogin.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		last, err := ll.Of(r.Context(), u.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, LastMethod: last.LastLoginMethod, LastAt: last.LastLoginAt}) // a client that hung up cannot be told
	}
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

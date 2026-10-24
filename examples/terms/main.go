// Command terms records which version of the terms each user accepted: the
// sign-up form sends the version it showed, users who signed up before a new
// version accept it later, and a page of the app refuses anyone who has not
// accepted the version in force.
//
//	go run ./terms
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
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "terms.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// currentTerms is the version of the terms in force. Bumping it makes
	// every user accept again before they reach the dashboard; the value is
	// a label the app chooses, compared exactly.
	currentTerms = "2026-09"
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

	a, tm, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, tm), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the library with the terms plugin and returns the plugin, for
// the routes that ask it which version is current and who accepted it.
//
//ds:def id=newauth-trjn44bk owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *terms.Plugin, error) {
	tm := terms.New(terms.Current(currentTerms))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), tm),
	)
	return a, tm, err
}

// newHandler mounts the library's routes, a public route that tells the
// sign-up form which version to show, and a dashboard that only a signed-in
// user who accepted the current terms may see.
//
//ds:def id=newhandler-9anxf4ng owner=@khanakia stability=stable
func newHandler(a *auth.Auth, tm *terms.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /terms", termsHandler(tm))
	mux.Handle("GET /dashboard", authhttp.Middleware(a)(authhttp.RequireUser(tm.RequireCurrent()(http.HandlerFunc(dashboard)))))
	return mux
}

// termsResponse is what GET /terms answers: the version the form must send
// back in the Terms-Version header.
type termsResponse struct {
	Version string `json:"version"`
	Header  string `json:"header"`
}

// termsHandler tells a sign-up form which version is in force and which
// header carries the user's acceptance.
func termsHandler(tm *terms.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, termsResponse{Version: tm.Version(), Header: terms.TermsHeader})
	})
}

// dashboardResponse is what GET /dashboard answers.
type dashboardResponse struct {
	Hello string `json:"hello"`
}

// dashboard runs only for a user who accepted the current terms: RequireUser
// and RequireCurrent have refused everyone else.
//
//ds:def id=dashboard-46336d85 owner=@khanakia stability=stable
func dashboard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dashboardResponse{Hello: authhttp.MustUser(r).Name})
}

// writeJSON answers v with 200.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

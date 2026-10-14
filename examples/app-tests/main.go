// Command app-tests is a small app whose tests are written with the
// github.com/ubgo/auth/authtest harness: email and password sign-in, phone
// codes, a protected page, and a settings action that needs a fresh sign-in.
//
//	go run ./app-tests
//	go test ./app-tests
//
// The program itself is ordinary; main_test.go is the point of the recipe.
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
	// dbFile is the SQLite database, created where the program runs.
	dbFile = "app-tests.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds a slow client's headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL: the trusted origin, and where links
	// in mail point.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys for the library's cascades.
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
	a, err := auth.New(append(options(db, sqlb.SQLiteDialect{}), auth.WithPlugins(plugins(logMailer{}, logSMS{})...))...)
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

// plugins is the app's plugin list, with the senders as parameters: main
// passes loggers, the test passes the harness's recorders. Keeping the list
// in one function is what lets the test wire exactly what production runs.
//
//ds:def id=apptests-plugins-5kq8wn3r
func plugins(m email.Mailer, s phone.SMSSender) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		phone.New(phone.Contact(), phone.WithSMS(s)),
	}
}

// options is every auth option but the plugins: the database and the public
// URL. The test replaces both through the harness, so this function is what
// main alone uses; it is here so the two lists stay side by side.
func options(db *sql.DB, d sqlb.Dialect) []auth.Option {
	return []auth.Option{auth.WithDB(db, d), auth.WithBaseURL(baseURL)}
}

// newHandler mounts the library's routes and the app's own pages.
//
//ds:def id=apptests-newhandler-8tm2xq6v
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me is a page only a signed-in user reaches.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name}) // a client that hung up cannot be told
}

// logMailer and logSMS print messages instead of sending them.
type (
	logMailer struct{}
	logSMS    struct{}
)

// Send logs the mail.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// Send logs the text.
func (logSMS) Send(_ context.Context, to, text string) error {
	log.Printf("sms to=%s %s", to, text)
	return nil
}

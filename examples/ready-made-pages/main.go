// Command ready-made-pages is email and password sign-in without writing a
// single form: authui serves sign-in, sign-up, forgot and reset password,
// email verification and account settings as server-rendered pages, and the
// app adds only its own dashboard.
//
//	go run ./ready-made-pages
//
// Open http://localhost:8081/ in a browser. Mail is printed to the log
// instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "ready-made-pages.db"
	// authPrefix is where the library's JSON routes are mounted, for any
	// script or single-page code that wants them next to the pages.
	authPrefix = "/auth"
	// appName is shown in every page title ("Sign in · Acme").
	appName = "Acme"
	// dashboardPath is the app's own page, where a sign-in lands.
	dashboardPath = "/dashboard"
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
	// post the forms, and links in mail point at it.
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

// newAuth wires the library: email addresses to sign in with and recover
// through, and passwords. The pages follow the plugin list: add magiclink,
// twofactor or terms here and their pages and form fields appear.
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

// newHandler mounts the pages at the root, where the plugins' default mail
// links (/verify-email, /reset-password) already point, the JSON routes under
// authPrefix, and the app's dashboard.
//
//ds:def id=newhandler-59d7ee62
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET "+dashboardPath, authhttp.Middleware(a)(http.HandlerFunc(dashboard)))
	mux.Handle("GET /{$}", http.RedirectHandler(dashboardPath, http.StatusSeeOther))
	mux.Handle("/", authui.Handler(a, authui.AppName(appName), authui.AfterSignIn(dashboardPath)))
	return mux
}

// dashboardPage is the app's own page: it greets the user and links to the
// ready-made settings page, with a sign-out form that posts to the pages.
var dashboardPage = template.Must(template.New("dashboard").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard · {{.App}}</title>
<h1>Hello, {{.Name}}</h1>
<p><a href="` + authui.PathSettings + `">Account settings</a></p>
<form method="post" action="` + authui.PathLogout + `"><button>Sign out</button></form>
`))

// dashboardData is what dashboardPage renders.
type dashboardData struct {
	App  string
	Name string
}

// dashboard shows the page to a signed-in user and sends anyone else to the
// ready-made sign-in page.
//
//ds:def id=dashboard-5jvjn3k4
func dashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := authhttp.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, authui.PathLogin, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardPage.Execute(w, dashboardData{App: appName, Name: u.Name}); err != nil {
		log.Printf("dashboard: %v", err)
	}
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
